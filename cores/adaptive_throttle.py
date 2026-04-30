"""
adaptive_throttle.py — Runtime Adaptive Concurrency Controller
==============================================================

Why you need this even with a perfect auto-tuner
─────────────────────────────────────────────────
The auto-tuner finds a safe rate at scan *start*.  A 6-hour overnight scan
will encounter:
  • Router NAT tables that fill up and flush
  • Network congestion from other users or background traffic
  • ISP throttling that kicks in after sustained usage
  • Your Wi-Fi / radio link quality changing as interference shifts

An auto-tuned rate that is perfect at 10pm may be too high at 2am and too
low by 5am.  Adaptive throttling monitors health in real time and adjusts
concurrency automatically throughout the scan.

The algorithm is AIMD (Additive Increase, Multiplicative Decrease):
  • When health is good:  concurrency += STEP  (slow increase)
  • When health degrades: concurrency *= BACKOFF  (fast decrease)
  • Recovery is always gradual; congestion escape is always fast.

Integration with scanner.py
────────────────────────────
The scanner creates its semaphore once at the top of run_scanner_pipeline().
To use adaptive throttling, make a small change:

    # In scanner.py, replace the one-time semaphore with DynamicSemaphore:
    from adaptive_throttle import DynamicSemaphore, AdaptiveThrottler

    throttler = AdaptiveThrottler(initial=config.MAX_CONCURRENT_SCANS, gateway=gateway_ip)
    semaphore = throttler.semaphore   # DynamicSemaphore, drop-in for asyncio.Semaphore

    throttler_task = asyncio.create_task(throttler.run())

    # ... existing scanner code unchanged ...

    throttler_task.cancel()

The DynamicSemaphore is a drop-in asyncio.Semaphore replacement.
"""

import asyncio
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# DynamicSemaphore — asyncio.Semaphore whose limit can change at runtime
# ──────────────────────────────────────────────────────────────────────────────

class DynamicSemaphore:
    """
    A semaphore whose concurrency limit can be raised or lowered at runtime.

    Behaves identically to asyncio.Semaphore for users (async with sem:).
    When the limit is lowered, in-flight tasks continue but no new ones
    start until the in-flight count drops below the new limit.
    When the limit is raised, waiting tasks are released immediately.
    """
    def __init__(self, initial: int) -> None:
        self._limit: int = max(1, initial)
        self._active: int = 0
        self._waiters: list[asyncio.Future] = []
        self._lock = asyncio.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def active(self) -> int:
        return self._active

    def set_limit(self, new_limit: int) -> None:
        """Change the concurrency limit."""
        self._limit = max(1, new_limit)
        self._wake_waiters()

    def _wake_waiters(self) -> None:
        # Reserve slots before waking waiters to avoid thundering-herd wakeups.
        while self._waiters and self._active < self._limit:
            waiter = self._waiters.pop(0)
            if not waiter.done():
                self._active += 1
                waiter.set_result(None)

    async def acquire(self) -> None:
        loop = asyncio.get_running_loop()
        async with self._lock:
            if self._active < self._limit:
                self._active += 1
                return
            fut = loop.create_future()
            self._waiters.append(fut)

        try:
            await fut
            return
        except asyncio.CancelledError:
            # If cancelled, remove queued waiter or release pre-reserved slot.
            async with self._lock:
                if fut in self._waiters:
                    self._waiters.remove(fut)
                else:
                    self._active = max(0, self._active - 1)
                    self._wake_waiters()
            raise

    def release(self) -> None:
        self._active = max(0, self._active - 1)
        self._wake_waiters()

    async def __aenter__(self) -> "DynamicSemaphore":
        await self.acquire()
        return self

    async def __aexit__(self, *_) -> None:
        self.release()


# ──────────────────────────────────────────────────────────────────────────────
# Health sampler — tracks timeout rate and gateway RTT in a sliding window
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class _Sample:
    ts: float
    ok: bool          # True = successful connection
    timeout: bool     # True = timed out
    latency_ms: float


class HealthWindow:
    """Sliding window of recent connection outcomes."""

    def __init__(self, window_seconds: float = 30.0) -> None:
        self._window = window_seconds
        self._samples: list[_Sample] = []

    def record(self, ok: bool, timeout: bool, latency_ms: float) -> None:
        self._samples.append(_Sample(time.monotonic(), ok, timeout, latency_ms))
        cutoff = time.monotonic() - self._window
        self._samples = [s for s in self._samples if s.ts >= cutoff]

    def timeout_rate(self) -> float:
        if not self._samples:
            return 0.0
        return sum(1 for s in self._samples if s.timeout) / len(self._samples)

    def median_latency_ms(self) -> float:
        lat = [s.latency_ms for s in self._samples if not s.timeout]
        if not lat:
            return 0.0
        return sorted(lat)[len(lat) // 2]

    def sample_count(self) -> int:
        return len(self._samples)


# ──────────────────────────────────────────────────────────────────────────────
# Adaptive Throttler
# ──────────────────────────────────────────────────────────────────────────────

class AdaptiveThrottler:
    """
    Monitors network health in real time and adjusts DynamicSemaphore concurrency.

    Usage
    ─────
        throttler = AdaptiveThrottler(initial=200, gateway="192.168.1.1")
        task = asyncio.create_task(throttler.run())

        # Pass throttler.semaphore to your scanner in place of asyncio.Semaphore.
        # Call throttler.record_outcome() from each connection attempt.

        task.cancel()

    The scanner needs two small changes:
      1. Use throttler.semaphore instead of asyncio.Semaphore(N).
      2. Call throttler.record_outcome(ok, timed_out, latency_ms) after each probe.
    """

    # Tuning constants
    POLL_INTERVAL   = 10.0   # seconds between health checks
    STEP_UP         = 5      # concurrency to add when healthy
    BACKOFF_FACTOR  = 0.70   # multiply current limit when congested
    MIN_LIMIT       = 3      # never drop below this
    MIN_SAMPLES     = 20     # need at least this many samples before acting

    # Thresholds
    TIMEOUT_WARN    = 0.12   # 12% timeouts = degraded
    TIMEOUT_CRIT    = 0.25   # 25% timeouts = congested (hard backoff)
    GW_WARN_RATIO   = 1.8    # gateway RTT 1.8× baseline = warn
    GW_CRIT_RATIO   = 3.0    # gateway RTT 3.0× baseline = congested

    def __init__(
        self,
        initial: int,
        gateway: Optional[str] = None,
        max_limit: Optional[int] = None,
        verbose: bool = True,
    ) -> None:
        self.semaphore = DynamicSemaphore(initial)
        self._initial = initial
        self._max = max_limit or initial * 4
        self._gateway = gateway
        self._verbose = verbose
        self._window = HealthWindow(window_seconds=30.0)
        self._baseline_gw_rtt: Optional[float] = None
        self._last_action: str = "init"

    def record_outcome(self, ok: bool, timed_out: bool, latency_ms: float) -> None:
        """Call this from every connection attempt in the scanner."""
        self._window.record(ok, timed_out, latency_ms)

    async def _measure_gw_rtt(self) -> Optional[float]:
        if not self._gateway:
            return None
        try:
            if sys.platform == "win32":
                cmd = ["ping", "-n", "3", self._gateway]
            else:
                cmd = ["ping", "-c", "3", "-W", "2", self._gateway]
            result = await asyncio.to_thread(
                subprocess.run, cmd, capture_output=True, text=True, timeout=15
            )
            m = re.search(r"[\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms", result.stdout)
            if m:
                return float(m.group(1))
            m = re.search(r"Average\s*=\s*([\d.]+)\s*ms", result.stdout, re.IGNORECASE)
            if m:
                return float(m.group(1))
        except Exception:
            pass
        return None

    def _log(self, msg: str) -> None:
        if self._verbose:
            print(f"\r[Throttle] {msg}" + " " * 20)

    async def run(self) -> None:
        """
        Background task.  Run with asyncio.create_task() alongside your scanner.
        Cancel when scanning finishes.
        """
        # Establish gateway baseline
        if self._gateway:
            self._baseline_gw_rtt = await self._measure_gw_rtt()
            if self._baseline_gw_rtt:
                self._log(f"Gateway baseline RTT: {self._baseline_gw_rtt:.1f}ms")

        while True:
            await asyncio.sleep(self.POLL_INTERVAL)

            current = self.semaphore.limit
            n = self._window.sample_count()

            if n < self.MIN_SAMPLES:
                continue  # Not enough data yet

            to_rate = self._window.timeout_rate()
            gw_rtt = await self._measure_gw_rtt()

            # Compute congestion signals.
            # Timeout rate is informational only; wild scans naturally time out
            # on dead/filtered IPs, so it must not affect throttling decisions.
            congested = False
            degraded = False

            if gw_rtt is not None and self._baseline_gw_rtt:
                ratio = gw_rtt / self._baseline_gw_rtt
                if ratio >= self.GW_CRIT_RATIO:
                    congested = True
                    reason = f"gw_rtt={ratio:.1f}× baseline (crit≥{self.GW_CRIT_RATIO}×)"
                elif ratio >= self.GW_WARN_RATIO:
                    degraded = True
                    reason = f"gw_rtt={ratio:.1f}× baseline (warn≥{self.GW_WARN_RATIO}×)"
                else:
                    reason = f"healthy (to={to_rate*100:.0f}%)"
            else:
                # If gateway RTT cannot be measured, default to healthy so we
                # do not accidentally throttle a scan based on unavailable data.
                reason = f"healthy (to={to_rate*100:.0f}%)"

            if congested:
                new_limit = max(self.MIN_LIMIT, int(current * self.BACKOFF_FACTOR))
                self.semaphore.set_limit(new_limit)
                self._last_action = "backoff"
                self._log(
                    f"CONGESTED ({reason}) — limit {current} → {new_limit}"
                )
            elif degraded:
                # Soft degradation: hold current limit, don't increase
                self._last_action = "hold"
                self._log(
                    f"DEGRADED ({reason}) — holding at {current}"
                )
            else:
                # Healthy: increase slowly
                new_limit = min(self._max, current + self.STEP_UP)
                if new_limit != current:
                    self.semaphore.set_limit(new_limit)
                    self._last_action = "increase"
                    self._log(
                        f"healthy (to={to_rate*100:.0f}%) — limit {current} → {new_limit}"
                    )


def print_preflight_status(
    stage: str,
    completed: int,
    total: int,
    current_rate: int,
    action: str = "",
    found: int = 0,
) -> None:
    """Single-line progress indicator for preflight batches."""
    percent = (completed / total) * 100 if total > 0 else 0
    bar_len = 20
    filled = int(bar_len * completed / total) if total > 0 else 0
    bar = "█" * filled + "-" * (bar_len - filled)
    prefix = f"{stage} " if stage else ""
    action_str = f" | {action}" if action else ""
    print(
        f"\r{prefix}[{bar}] {percent:.1f}% ({completed}/{total}) @ {int(current_rate)} pps{action_str} | open={found}".ljust(140),
        end="",
        flush=True,
    )


def print_wait_progress(stage: str, elapsed: int, total_wait: int, found: int) -> None:
    """
    Dedicated progress bar for the post-scan idle/drain phase.

    Distinct from the scan progress bar: shows how much of the wait window
    has elapsed (so the user can see the timer ticking down with its own
    visual fill, instead of just a number embedded in a status field).
    """
    elapsed = max(0, min(int(elapsed), int(total_wait)))
    total_wait = max(1, int(total_wait))
    pct = (elapsed / total_wait) * 100
    bar_len = 20
    filled = int(bar_len * elapsed / total_wait)
    bar = "█" * filled + "-" * (bar_len - filled)
    prefix = f"{stage} " if stage else ""
    remaining = total_wait - elapsed
    print(
        f"\r{prefix}[{bar}] {pct:.0f}% — waiting {remaining}s for delayed packets (found {found})".ljust(140),
        end="",
        flush=True,
    )
