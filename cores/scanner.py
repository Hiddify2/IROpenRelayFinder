import os
import sys
import time
import asyncio
import subprocess
import re
import ssl
import socket as _socket  # for TCP_NODELAY constant
import threading
import ipaddress
import math
import random
import shutil
import signal
from math import ceil
from functools import lru_cache

# ==========================================================================
# UVLOOP AUTO-INSTALL (must run before any event loop is created)
# ==========================================================================
# We attempt this at module import so users don't have to wire it up in
# their main() — the previous version required a manual call to
# install_fast_event_loop() that almost nobody noticed in their entry script.
#
# Safe no-op on Windows or if uvloop isn't installed.
# Idempotent: setting the policy after a loop has already started would be
# unsafe, so we detect that case and skip silently.

def _try_auto_install_uvloop() -> bool:
    if sys.platform == "win32":
        return False
    try:
        import uvloop  # type: ignore
    except ImportError:
        return False
    # If a loop is already running, switching policies is unsafe — bail.
    try:
        asyncio.get_running_loop()
        return False
    except RuntimeError:
        pass  # No loop running — safe to set policy
    try:
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
        return True
    except Exception:
        return False


_UVLOOP_INSTALLED = _try_auto_install_uvloop()


def install_fast_event_loop() -> bool:
    """
    Backward-compatible explicit installer. Idempotent.
    Returns True iff uvloop is now (or was already) the default policy.
    """
    global _UVLOOP_INSTALLED
    if _UVLOOP_INSTALLED:
        return True
    _UVLOOP_INSTALLED = _try_auto_install_uvloop()
    return _UVLOOP_INSTALLED


def _running_on_uvloop() -> bool:
    """
    Detect if the *currently running* loop is uvloop. Must be called from
    inside an async context to be reliable (uses get_running_loop()).
    """
    try:
        loop = asyncio.get_running_loop()
        return "uvloop" in type(loop).__module__.lower()
    except RuntimeError:
        # Outside coroutine — fall back to the install flag
        return _UVLOOP_INSTALLED


# --- State and Route Service imports ---
from utils.runtime_state import STATE
from utils.pause_controller import PauseController

from cores.adaptive_throttle import (
    AdaptiveThrottler,
    print_preflight_status,
    print_wait_progress,
)
from utils import config
from utils import paths
from utils import storage
from utils import data_store
from utils.helpers import cleanup_files, load_white_cache, get_base_domain, parse_ip_port, format_ip_port, add_ban_entry
from utils.asn_engine import get_asn_info

# Cache for preflight parameters to avoid cyclic blocking
_cached_masscan_args = None
_cached_nmap_args = None
_sudo_keepalive_started = False
_masscan_supports_pcap_buffers = None
_EXTRA_PROBE_DOMAINS = ("gemini.google.com", "notebooklm.google.com")

# Per-endpoint probe fan-out cap. CRITICAL for performance: without this,
# N endpoints × M probes coroutines all queue on a single socket_sem, and
# the resulting queue depth (e.g., 152×8=1216 against a sem of 76) means
# probes wait so long for their slot that the endpoint's hard_timeout fires
# before they get serviced.
#
# Sizing rule: we want CEIL(num_probes / probe_sem) × max_probe_time to be
# well under hard_timeout. With ~10 probe domains and 6s per-probe timeout:
#   probe_sem=2 → 5 waves × 6s = 30s  (BUSTS 28s hard_timeout — v3 lost ~50%
#                                       of endpoints this way)
#   probe_sem=4 → 3 waves × 6s = 18s  (safe margin, current setting)
# socket budget = endpoint_slots × probe_sem, so endpoint_slots adjusts
# automatically (76 // 4 = 19 endpoint slots).
_PER_IP_PROBE_CONCURRENCY = 4

_GEMINI_PROBE_HOST = "gemini.google.com"
_CRITICAL_PROBE_DOMAINS = ("workers.dev", "pages.dev")
_GOOGLE_FAMILY_SUFFIXES = (
    "google.com",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "gmail.com",
    "googlemail.com",
)

# Static parts of the HTTP probe — pre-encoded so each probe only pays for
# encoding the dynamic Host value.
_PROBE_HEAD = b"GET / HTTP/1.1\r\nHost: "
_PROBE_TAIL = (
    b"\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    b"\r\nAccept: text/html,application/xhtml+xml,application/json"
    b"\r\nAccept-Encoding: identity"
    b"\r\nConnection: close\r\n\r\n"
)

# Pre-compiled regex — avoids recompiling on every classify_response() call
_STATUS_RE = re.compile(rb"http/\d(?:\.\d)?\s+(\d{3})", re.IGNORECASE)


@lru_cache(maxsize=1024)
def _build_http_probe(domain: str, path: str = "/") -> bytes:
    """
    Build and cache HTTP probe payloads per host to reduce per-probe CPU/alloc
    overhead in large scans.
    """
    host = (domain or "").encode("ascii", "ignore")
    req_path = (path or "/").strip()
    if not req_path.startswith("/"):
        req_path = "/" + req_path
    req_line = b"GET " + req_path.encode("ascii", "ignore") + b" HTTP/1.1\r\nHost: "
    return req_line + host + _PROBE_TAIL


def _order_probe_domains(domains):
    """
    Stable ordering with critical domains first so high-value pairs are tested
    in the earliest wave without changing total probe count.
    """
    ordered = []
    seen = set()
    for dom in list(_CRITICAL_PROBE_DOMAINS) + list(domains or []):
        clean = (dom or "").strip().lower()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        ordered.append(clean)
    return ordered


def _probe_path_for_domain(domain: str) -> str:
    dom = (domain or "").strip().lower()
    if dom in _CRITICAL_PROBE_DOMAINS:
        # Cloudflare edge diagnostic endpoint; tends to be far more stable than
        # root-path behavior for workers/pages capability checks.
        return "/cdn-cgi/trace"
    return "/"


def _retry_attempts_for_domain(domain: str) -> int:
    base = max(1, int(getattr(config, "SCAN_RETRY_ATTEMPTS", 2)))
    dom = (domain or "").strip().lower()
    if dom in _CRITICAL_PROBE_DOMAINS:
        return min(5, base + 1)
    if dom == _GEMINI_PROBE_HOST:
        return max(1, base - 1)
    return base


_ANSI = {
    "reset": "\033[0m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "red": "\033[91m",
    "cyan": "\033[96m",
    "dim": "\033[2m",
}

# Cached once at first call — avoids repeated isatty()/os.getenv() on every print
_COLOR_SUPPORTED: bool | None = None


def _supports_color():
    global _COLOR_SUPPORTED
    if _COLOR_SUPPORTED is None:
        _COLOR_SUPPORTED = sys.stdout.isatty() and os.getenv("NO_COLOR") is None
    return _COLOR_SUPPORTED


def _c(name: str) -> str:
    if not _supports_color():
        return ""
    return _ANSI.get(name, "")


def _fmt_duration_hms(seconds: float) -> str:
    total = max(0, int(round(seconds)))
    hours = total // 3600
    mins = (total % 3600) // 60
    secs = total % 60
    if hours > 0:
        return f"{hours}h{mins:02d}m{secs:02d}s"
    if mins > 0:
        return f"{mins}m{secs:02d}s"
    return f"{secs}s"


def _fmt_duration_short(seconds: float) -> str:
    seconds = max(0.0, float(seconds))
    if seconds >= 60.0:
        return _fmt_duration_hms(seconds)
    return f"{seconds:.1f}s"


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if pct <= 0:
        return float(ordered[0])
    if pct >= 100:
        return float(ordered[-1])
    rank = int(math.ceil((pct / 100.0) * len(ordered))) - 1
    rank = max(0, min(rank, len(ordered) - 1))
    return float(ordered[rank])


def _find_default_gateway() -> str | None:
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["ipconfig"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            for line in out.splitlines():
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    if gw and re.match(r"^\d+\.\d+\.\d+\.\d+$", gw):
                        return gw
        else:
            out = subprocess.check_output(["ip", "route"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            for line in out.splitlines():
                if line.startswith("default") and "via" in line:
                    m = re.search(r"via (\d+\.\d+\.\d+\.\d+)", line)
                    if m:
                        return m.group(1)
            out = subprocess.check_output(["route", "-n", "get", "default"], text=True, stderr=subprocess.DEVNULL, timeout=5)
            m = re.search(r"gateway:\s+(\S+)", out)
            if m:
                return m.group(1)
    except Exception:
        pass
    return None


async def _cancel_and_await(tasks):
    pending = [t for t in tasks if t and not t.done()]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)


async def _close_writer(writer, timeout: float = 1.0):
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        return
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=timeout)
    except Exception:
        pass


def ensure_sudo_keepalive():
    """Spawns a background daemon to keep the sudo token warm during overnight Cyclic Scans."""
    global _sudo_keepalive_started
    if _sudo_keepalive_started:
        return
    if sys.platform == 'win32' or os.geteuid() == 0:
        return

    try:
        # Verify or prompt for password once
        subprocess.run(["sudo", "-v"], check=True)

        def sudo_daemon():
            while True:
                time.sleep(60)
                try:
                    subprocess.run(["sudo", "-n", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

        threading.Thread(target=sudo_daemon, daemon=True).start()
        _sudo_keepalive_started = True
        print("[+] Background Sudo token keepalive active for continuous scanning.")
    except Exception:
        print("[-] Warning: Sudo keepalive failed. Unattended scans might hang after 15 minutes.")


# ==========================================
# MASSCAN WRAPPERS
# ==========================================
def _parse_masscan_output(output_file):
    """Full-file parse — kept for the final reconciliation pass after the scan exits."""
    open_endpoints = set()
    for line in storage.read_text_lines(output_file, encoding="utf-8"):
        if line.startswith("open"):
            parts = line.split()
            if len(parts) >= 4:
                try:
                    port = int(parts[2])
                except (TypeError, ValueError):
                    continue
                open_endpoints.add((parts[3], port))
    return open_endpoints


def _parse_masscan_lines(lines):
    """Parse a batch of already-split text lines. Returns set of (ip, port)."""
    eps = set()
    for line in lines:
        line = line.strip()
        if not line.startswith("open"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            port = int(parts[2])
        except (TypeError, ValueError):
            continue
        eps.add((parts[3], port))
    return eps


def _extract_bare_ips(ips):
    bare_ips = set()
    for target in ips:
        # [FIX] Prevent parse_ip_port from mangling tuples
        if isinstance(target, tuple) and len(target) >= 1:
            bare_ips.add(str(target[0]))
        else:
            parsed = parse_ip_port(target)
            bare_ips.add(parsed[0] if parsed else str(target).strip())
    return list(bare_ips)


def _masscan_has_pcap_buffers() -> bool:
    global _masscan_supports_pcap_buffers
    if _masscan_supports_pcap_buffers is not None:
        return _masscan_supports_pcap_buffers

    try:
        probe = subprocess.run(
            ["masscan", "127.0.0.1", "-p1", "--echo", "--pcap-buffers", "64"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        err = (probe.stderr or "").lower()
        _masscan_supports_pcap_buffers = (probe.returncode == 0) and ("unknown config option" not in err)
    except Exception:
        _masscan_supports_pcap_buffers = False
    return _masscan_supports_pcap_buffers


def run_masscan_preflight(ips, use_cached=False):
    """
    Synchronous masscan preflight with incremental tail-read of the output
    file. Each poll only re-parses bytes written since the last poll; old
    behavior re-parsed the entire file every tick (O(N²) over scan lifetime).
    """
    global _cached_masscan_args
    if not ips:
        print("\n[*] No targets provided for Masscan pre-flight.")
        return []

    bare_ips = _extract_bare_ips(ips)
    print(f"\n[*] Preparing Masscan for {len(bare_ips)} unique IPs...")

    uid = os.getpid()
    total_ips = len(bare_ips)

    if use_cached and _cached_masscan_args:
        rate, retries, wait = _cached_masscan_args
        print(f"[*] Using cached Masscan settings: Rate={rate}, Retries={retries}, Wait={wait}s")
    else:
        rate_def = str(config.TUNED_MASSCAN_RATE) if config.TUNED_MASSCAN_RATE else "1000"
        rate = input(f"[?] Enter Masscan rate (packets/sec) [Default {rate_def}]: ").strip()
        if not rate.isdigit():
            rate = rate_def

        retries = input("[?] Enter packet retries [Default 2]: ").strip()
        if not retries.isdigit():
            retries = "2"

        wait = input("[?] Enter end-of-scan wait time [Default 10]: ").strip()
        if not wait.isdigit():
            wait = "10"

        _cached_masscan_args = (rate, retries, wait)

    port_arg = ",".join(str(p) for p in config.TARGET_PORTS)
    rate_int = int(rate)

    all_open_endpoints = set()
    rst_drop_rule_applied = False
    iptables_path = shutil.which("iptables") if (sys.platform != "win32" and sys.platform.startswith("linux")) else None

    if iptables_path:
        insert_cmd = [iptables_path, "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
        if os.geteuid() != 0:
            ensure_sudo_keepalive()
            insert_cmd.insert(0, "sudo")
        try:
            subprocess.run(insert_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            rst_drop_rule_applied = True
            print("[*] Temporary iptables RST drop rule enabled for Masscan preflight.")
        except Exception:
            print("[!] Warning: Failed to apply iptables RST drop rule. Continuing without it.")
    elif sys.platform != "win32" and sys.platform.startswith("linux"):
        print("[!] Warning: iptables not found. Continuing without RST suppression.")

    target_file = paths.data_path("tmp", f"masscan_targets_{uid}.txt")
    output_file = paths.data_path("tmp", f"masscan_results_{uid}.txt")
    storage.atomic_write_text(target_file, "".join(f"{ip}\n" for ip in bare_ips), encoding="utf-8")

    cmd = [
        "masscan", f"-p{port_arg}", "-iL", target_file,
        "--retries", retries, "--wait", wait,
        "--connection-timeout", "3", "--status",
        "--rate", str(rate_int), "-oL", output_file,
    ]
    if _masscan_has_pcap_buffers():
        cmd.extend(["--pcap-buffers", "64"])
    if sys.platform != 'win32' and os.geteuid() != 0:
        ensure_sudo_keepalive()
        cmd.insert(0, "sudo")

    print(f"\n[*] Launching Masscan: rate={rate_int} pps, retries={retries}, wait={wait}s")
    print(f"[*] Single sweep over {total_ips} IPs (no batching).\n")

    seen = set()
    completed_ref = [0]
    wait_started = threading.Event()
    wait_stop = threading.Event()
    results_stop = threading.Event()
    wait_started_at = [0.0]
    print_lock = threading.Lock()

    def _redraw():
        print_preflight_status(
            "",
            completed_ref[0],
            total_ips,
            rate_int,
            "scanning..." if not wait_started.is_set() else "draining...",
            found=len(seen),
        )

    def _live_results_poller():
        """Tail-read masscan output: only re-parse newly written bytes."""
        last_size = 0
        leftover = ""
        while not results_stop.is_set():
            try:
                cur_size = os.path.getsize(output_file)
            except OSError:
                cur_size = 0

            if cur_size > last_size:
                try:
                    with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        chunk = f.read(cur_size - last_size)
                except OSError:
                    chunk = ""
                last_size = cur_size

                data = leftover + chunk
                lines = data.split("\n")
                leftover = lines[-1]  # save partial trailing line for next poll
                eps = _parse_masscan_lines(lines[:-1])
                new_eps = eps - seen
                if new_eps:
                    seen.update(new_eps)
                    all_open_endpoints.update(new_eps)
                    with print_lock:
                        if wait_started.is_set():
                            elapsed = int(time.monotonic() - wait_started_at[0])
                            print_wait_progress("", elapsed, int(wait), len(seen))
                        else:
                            _redraw()
            results_stop.wait(timeout=0.5)

    def _wait_phase_runner():
        wait_s = max(1, int(wait))
        start = time.monotonic()
        wait_started_at[0] = start
        while not wait_stop.is_set():
            elapsed = int(time.monotonic() - start)
            if elapsed >= wait_s:
                break
            with print_lock:
                print_wait_progress("", elapsed, wait_s, len(seen))
            wait_stop.wait(timeout=0.25)
        with print_lock:
            print_wait_progress("", wait_s, wait_s, len(seen))

    process = None
    results_thread = None
    wait_thread = None
    try:
        with print_lock:
            print_preflight_status("", 0, total_ips, rate_int, "scanning...")

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )

        results_thread = threading.Thread(target=_live_results_poller, daemon=True)
        results_thread.start()

        for line in iter(process.stdout.readline, ''):
            pct_match = re.search(r"([0-9]+(?:\.[0-9]+)?)%\s*done", line, re.IGNORECASE)
            if not pct_match:
                continue
            try:
                pct = float(pct_match.group(1))
            except Exception:
                pct = 0.0
            pct = max(0.0, min(100.0, pct))
            completed_ref[0] = min(total_ips, int(round((pct / 100.0) * total_ips)))

            if pct >= 99.9 and not wait_started.is_set():
                wait_started.set()
                if wait_thread is None:
                    wait_thread = threading.Thread(target=_wait_phase_runner, daemon=True)
                    wait_thread.start()
            elif not wait_started.is_set():
                with print_lock:
                    _redraw()

        wait_stop.set()
        if wait_thread is not None:
            wait_thread.join(timeout=2.0)
        process.wait()

        if process.returncode != 0:
            print(f"\n[!] Masscan exited with code {process.returncode}.")

        results_stop.set()
        if results_thread is not None:
            results_thread.join(timeout=1.0)

        # Final reconciliation: catch lines written between last poll and exit.
        final_eps = _parse_masscan_output(output_file)
        new_final = final_eps - seen
        if new_final:
            seen.update(new_final)
            all_open_endpoints.update(new_final)
        print()

    except KeyboardInterrupt:
        print(f"\n[-] Masscan interrupted by user.")
        raise
    except Exception as e:
        print(f"\n[-] Masscan failed: {e}")
    finally:
        results_stop.set()
        wait_stop.set()
        cleanup_files(target_file, output_file)

        if rst_drop_rule_applied and iptables_path:
            delete_cmd = [iptables_path, "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
            if os.geteuid() != 0:
                ensure_sudo_keepalive()
                delete_cmd.insert(0, "sudo")
            try:
                subprocess.run(delete_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("\n[*] Removed temporary iptables RST drop rule.")
            except Exception:
                print("\n[!] Warning: Failed to remove temporary iptables RST drop rule.")

    print(f"[+] Masscan preflight complete. Trimmed down to {len(all_open_endpoints)} online endpoints.")
    return list(all_open_endpoints)


async def _terminate_subprocess(process, grace: float = 3.0):
    """
    Robust async subprocess termination. Tries TERM, then KILL.
    On POSIX uses process group to clean up forked children (sudo masscan).
    """
    if process is None:
        return
    if process.returncode is not None:
        return

    try:
        if sys.platform != "win32":
            try:
                pgid = os.getpgid(process.pid)
                os.killpg(pgid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.terminate()
                except Exception:
                    pass
        else:
            try:
                process.terminate()
            except Exception:
                pass

        try:
            await asyncio.wait_for(process.wait(), timeout=grace)
            return
        except asyncio.TimeoutError:
            pass

        # Hard kill
        if sys.platform != "win32":
            try:
                pgid = os.getpgid(process.pid)
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    process.kill()
                except Exception:
                    pass
        else:
            try:
                process.kill()
            except Exception:
                pass

        try:
            await process.wait()
        except Exception:
            pass
    except Exception:
        pass


async def execute_masscan_silent(ips, rate, retries, wait, duration=None):
    """
    Async masscan run. POSIX uses process groups so the sudo wrapper's
    child masscan is killed cleanly when we cancel.
    """
    uid = os.getpid()
    target_file = paths.data_path("tmp", f"masscan_targets_tune_{uid}.txt")
    output_file = paths.data_path("tmp", f"masscan_results_tune_{uid}.txt")
    bare_ips = _extract_bare_ips(ips)
    storage.atomic_write_text(target_file, "".join(f"{ip}\n" for ip in bare_ips), encoding="utf-8")

    port_arg = ",".join(str(p) for p in config.TARGET_PORTS)
    cmd = ["masscan", f"-p{port_arg}", "-iL", target_file, "-oL", output_file,
           "--rate", str(rate), "--retries", str(retries), "--wait", str(wait)]
    if sys.platform != 'win32' and os.geteuid() != 0:
        cmd.insert(0, "sudo")

    popen_kwargs = {}
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True

    process = None
    open_eps = set()
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            **popen_kwargs,
        )

        if duration is None:
            await process.wait()
        else:
            try:
                await asyncio.wait_for(process.wait(), timeout=max(0.01, float(duration)))
            except asyncio.TimeoutError:
                await _terminate_subprocess(process, grace=3.0)

        if process.returncode not in (None, 0):
            pass
        open_eps = _parse_masscan_output(output_file)
    except asyncio.CancelledError:
        await _terminate_subprocess(process, grace=2.0)
        raise
    except Exception:
        open_eps = _parse_masscan_output(output_file)
    finally:
        cleanup_files(target_file, output_file)

    return list(open_eps)


# ==========================================
# NMAP WRAPPERS
# ==========================================
def _parse_nmap_output(output_file):
    """Full-file parse — kept for final reconciliation."""
    open_eps = set()
    for line in storage.read_text_lines(output_file, encoding="utf-8"):
        line = line.strip()
        if not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host_ip = parts[1]
        for m in re.finditer(r'(\d+)/open/tcp', line):
            try:
                port_val = int(m.group(1))
            except (TypeError, ValueError):
                continue
            if port_val in config.TARGET_PORTS:
                open_eps.add((host_ip, port_val))
    return open_eps


def _parse_nmap_lines(lines):
    """Parse a batch of pre-split nmap gnmap text lines."""
    eps = set()
    for line in lines:
        line = line.strip()
        if not line.startswith("Host:"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        host_ip = parts[1]
        for m in re.finditer(r'(\d+)/open/tcp', line):
            try:
                port_val = int(m.group(1))
            except (TypeError, ValueError):
                continue
            if port_val in config.TARGET_PORTS:
                eps.add((host_ip, port_val))
    return eps


def run_nmap_preflight(ips, use_cached=False):
    """
    Synchronous nmap preflight. Same incremental-tail optimization as masscan.
    """
    global _cached_nmap_args
    if not ips:
        print("\n[*] No targets provided for Nmap pre-flight.")
        return []

    bare_ips = _extract_bare_ips(ips)
    print(f"\n[*] Preparing Nmap for {len(bare_ips)} unique IPs...")

    uid = os.getpid()
    total_ips = len(bare_ips)

    if use_cached and _cached_nmap_args:
        if len(_cached_nmap_args) >= 4:
            timing, retries, min_rate, max_rate = _cached_nmap_args[:4]
        else:
            timing, retries, min_rate, max_rate = "-T4", "2", "100", "500"
        print(f"[*] Using cached Nmap settings: {timing}, Retries={retries}")
    else:
        print("\n[?] Select Nmap timing template:\n    [1] T2 - Polite\n    [2] T3 - Normal\n    [3] T4 - Aggressive [Default]")
        timing_choice = input("    Choice [Default 3 / T4]: ").strip()
        timing_map = {"1": "-T2", "2": "-T3", "3": "-T4"}
        timing = timing_map.get(timing_choice, "-T4")

        retries = input("\n[?] Max retries per probe [Default 2]: ").strip()
        if not retries.isdigit():
            retries = "2"

        min_rate, max_rate = "", ""
        if timing != "-T2":
            min_def = str(config.TUNED_NMAP_MIN_RATE) if config.TUNED_NMAP_MIN_RATE else "100"
            max_def = str(config.TUNED_NMAP_MAX_RATE) if config.TUNED_NMAP_MAX_RATE else "500"
            min_rate = input(f"\n[?] Minimum packet rate [Default {min_def}]: ").strip()
            if not min_rate.isdigit():
                min_rate = min_def
            max_rate = input(f"\n[?] Maximum packet rate [Default {max_def}]: ").strip()
            if not max_rate.isdigit():
                max_rate = max_def

        _cached_nmap_args = (timing, retries, min_rate, max_rate)

    scan_type = "-sT"
    port_arg = ",".join(str(p) for p in config.TARGET_PORTS)
    nmap_max_rate = int(max_rate) if max_rate and str(max_rate).isdigit() else 500
    nmap_min_rate = int(min_rate) if min_rate and str(min_rate).isdigit() else max(1, min(100, nmap_max_rate))

    nmap_rst_drop_rule_applied = False
    nmap_iptables_path = None
    if scan_type == "-sS" and sys.platform != "win32" and sys.platform.startswith("linux"):
        nmap_iptables_path = shutil.which("iptables")
        if nmap_iptables_path:
            insert_cmd = [nmap_iptables_path, "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
            if os.geteuid() != 0:
                ensure_sudo_keepalive()
                insert_cmd.insert(0, "sudo")
            try:
                subprocess.run(insert_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                nmap_rst_drop_rule_applied = True
                print("[*] Temporary iptables RST drop rule enabled for Nmap SYN preflight.")
            except Exception:
                print("[!] Warning: Failed to apply iptables RST drop rule for Nmap SYN scan. Continuing without it.")
        else:
            print("[!] Warning: iptables not found. Continuing Nmap SYN scan without RST suppression.")

    all_open_endpoints = set()

    target_file = paths.data_path("tmp", f"nmap_targets_{uid}.txt")
    output_file = paths.data_path("tmp", f"nmap_results_{uid}.gnmap")
    storage.atomic_write_text(target_file, "".join(f"{ip}\n" for ip in bare_ips), encoding="utf-8")

    cmd = [
        "nmap", "-p", port_arg, scan_type, "-Pn", "-n",
        "-iL", target_file, "-oG", output_file, timing,
        "--max-retries", retries, "--host-timeout", "300s", "--stats-every", "1s",
    ]
    if timing != "-T2":
        cmd.extend(["--min-rate", str(nmap_min_rate), "--max-rate", str(nmap_max_rate)])

    print(f"\n[*] Launching Nmap: timing={timing}, retries={retries}, max-rate={nmap_max_rate} pps")
    print(f"[*] Single sweep over {total_ips} IPs (no batching).\n")

    nmap_seen = set()
    nmap_found_ref = [0]
    nmap_results_stop = threading.Event()
    nmap_print_lock = threading.Lock()

    def _nmap_live_poller():
        """Incremental tail-read of nmap gnmap output."""
        last_size = 0
        leftover = ""
        while not nmap_results_stop.is_set():
            try:
                cur_size = os.path.getsize(output_file)
            except OSError:
                cur_size = 0

            if cur_size > last_size:
                try:
                    with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                        f.seek(last_size)
                        chunk = f.read(cur_size - last_size)
                except OSError:
                    chunk = ""
                last_size = cur_size

                data = leftover + chunk
                lines = data.split("\n")
                leftover = lines[-1]
                eps = _parse_nmap_lines(lines[:-1])
                new_eps = eps - nmap_seen
                if new_eps:
                    nmap_seen.update(new_eps)
                    nmap_found_ref[0] = len(nmap_seen)
            nmap_results_stop.wait(timeout=1.0)

    process = None
    nmap_poll_thread = None
    try:
        print_preflight_status("", 0, total_ips, nmap_max_rate, "scanning...")

        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )

        nmap_poll_thread = threading.Thread(target=_nmap_live_poller, daemon=True)
        nmap_poll_thread.start()

        completed = 0
        for line in iter(process.stdout.readline, ''):
            if "hosts completed" in line:
                stats_match = re.search(r'(\d+) hosts completed', line)
                if stats_match:
                    completed = min(total_ips, int(stats_match.group(1)))
                    with nmap_print_lock:
                        print_preflight_status("", completed, total_ips, nmap_max_rate, "scanning...", found=nmap_found_ref[0])

        nmap_results_stop.set()
        if nmap_poll_thread is not None:
            nmap_poll_thread.join(timeout=2.0)

        process.wait()
        if process.returncode != 0:
            print(f"\n[!] Nmap exited with code {process.returncode}. Continuing with partial results.")

        all_open_endpoints.update(_parse_nmap_output(output_file))

    except KeyboardInterrupt:
        print(f"\n[-] Nmap interrupted by user.")
        raise
    except Exception as e:
        print(f"\n[-] Nmap error: {e}")
    finally:
        nmap_results_stop.set()
        cleanup_files(target_file, output_file)

        if nmap_rst_drop_rule_applied and nmap_iptables_path:
            delete_cmd = [nmap_iptables_path, "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"]
            if os.geteuid() != 0:
                ensure_sudo_keepalive()
                delete_cmd.insert(0, "sudo")
            try:
                subprocess.run(delete_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("[*] Removed temporary iptables RST drop rule for Nmap SYN preflight.")
            except Exception:
                print("[!] Warning: Failed to remove temporary iptables RST drop rule for Nmap SYN preflight.")

    print()
    print(f"[+] Nmap preflight complete. Found {len(all_open_endpoints)} open endpoints.")
    return list(all_open_endpoints)


async def execute_nmap_silent(ips, timing, retries, min_rate, max_rate, scan_type, host_timeout="300s", duration=None):
    uid = os.getpid()
    target_file = paths.data_path("tmp", f"nmap_targets_tune_{uid}.txt")
    output_file = paths.data_path("tmp", f"nmap_results_tune_{uid}.gnmap")
    bare_ips = _extract_bare_ips(ips)
    storage.atomic_write_text(target_file, "".join(f"{ip}\n" for ip in bare_ips), encoding="utf-8")

    port_arg = ",".join(str(p) for p in config.TARGET_PORTS)
    scan_type = "-sT"
    cmd = ["nmap", "-p", port_arg, scan_type, "-Pn", "-n", "-iL", target_file, "-oG", output_file,
           timing, "--max-retries", str(retries), "--host-timeout", str(host_timeout)]
    if timing != "-T2":
        cmd.extend(["--min-rate", str(min_rate), "--max-rate", str(max_rate)])

    popen_kwargs = {}
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True

    process = None
    open_eps = set()
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            **popen_kwargs,
        )

        if duration is None:
            await process.wait()
        else:
            try:
                await asyncio.wait_for(process.wait(), timeout=max(0.01, float(duration)))
            except asyncio.TimeoutError:
                await _terminate_subprocess(process, grace=3.0)

        open_eps = _parse_nmap_output(output_file)
    except asyncio.CancelledError:
        await _terminate_subprocess(process, grace=2.0)
        raise
    except Exception:
        open_eps = _parse_nmap_output(output_file)
    finally:
        cleanup_files(target_file, output_file)

    return list(open_eps)


# ==========================================
# ASYNCIO TCP SCANNER
# ==========================================
async def _check_tcp_endpoint(target, semaphore, timeout=3.0):
    async with semaphore:
        # [FIX] Prevent parse_ip_port from mangling tuples
        if isinstance(target, tuple) and len(target) >= 2:
            ip, port = str(target[0]), int(target[1])
        else:
            parsed = parse_ip_port(target)
            if not parsed:
                return None
            ip, port = parsed

        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            await _close_writer(writer)
            return (ip, port)
        except Exception:
            return None


def _normalize_endpoint(target):
    """
    Normalize a single target to (ip, port) or None if unrecoverable.

    Defends against the upstream "ip-with-embedded-port" tuple bug:
    callers sometimes pass tuples like ("188.121.123.148:443", 2053) where
    target[0] already contains a port. Without this fix, asyncio's
    open_connection treats target[0] as a hostname and getaddrinfo returns
    EAI_NONAME (= OS Error -2). 96 of these in the last debug log.
    """
    if isinstance(target, tuple) and len(target) >= 2:
        raw_ip = str(target[0]).strip()
        raw_port = target[1]

        # If target[0] contains a colon, it could be:
        #  (a) bare IPv6 ("::1", "fe80::1") — valid IP literal
        #  (b) bracketed IPv6 ("[::1]") — also fine
        #  (c) "ipv4:port" form — needs re-parsing, target[1] is bogus
        if ":" in raw_ip and not raw_ip.startswith("["):
            try:
                ipaddress.ip_address(raw_ip)
                # Bare IPv6: target[1] is the real port
                try:
                    return raw_ip, int(raw_port)
                except (TypeError, ValueError):
                    return None
            except (ValueError, TypeError):
                # Not a bare IP literal — must be "ipv4:port" string
                parsed = parse_ip_port(raw_ip)
                return parsed if parsed else None

        # Plain IPv4 or bracketed IPv6
        try:
            return raw_ip, int(raw_port)
        except (TypeError, ValueError):
            return None

    if isinstance(target, str):
        parsed = parse_ip_port(target)
        return parsed if parsed else None

    return None


def _iter_scan_targets(targets):
    """
    Yield normalized (ip, port) pairs without building a second full copy of
    the scan list in memory. Generator-friendly: the input may be a list,
    tuple, set, or arbitrary iterator/generator.
    """
    for target in targets:
        # Tuple form (or pre-paired): use defensive normalizer.
        if isinstance(target, tuple) and len(target) >= 2:
            normalized = _normalize_endpoint(target)
            if normalized:
                yield normalized
            continue

        if isinstance(target, str):
            raw = target.strip()
            if not raw:
                continue
            # Bare IPs / CIDRs fan out across the configured target ports.
            if ":" not in raw and not raw.startswith("["):
                ports = list(config.TARGET_PORTS)
                if len(ports) > 1:
                    random.shuffle(ports)
                for port in ports:
                    yield raw, int(port)
                continue

        parsed = parse_ip_port(target)
        if parsed:
            yield parsed


def _iter_scan_targets_round_robin(targets):
    """
    Yield normalized (ip, port) pairs in port-major order: every IP gets one
    endpoint yielded before any IP gets its second. This is what makes the
    soft dead-IP tracker fire mid-scan — by the time IP X's 2nd port enters
    the queue, X's 1st-port result is back, and after enough timeouts the
    remaining ports on X are short-circuited.

    Materializes a per-IP port list. RAM: ~24 bytes per (ip, port) pair —
    e.g. 4608 endpoints ≈ 110KB. Only used for list-like inputs; streaming
    inputs fall back to _iter_scan_targets to keep RAM bounded for huge
    CIDR fan-outs.
    """
    by_ip: dict[str, list[int]] = {}
    ip_order: list[str] = []
    for ip, port in _iter_scan_targets(targets):
        ports = by_ip.get(ip)
        if ports is None:
            by_ip[ip] = [port]
            ip_order.append(ip)
        else:
            ports.append(port)

    max_ports = max((len(v) for v in by_ip.values()), default=0)
    for i in range(max_ports):
        for ip in ip_order:
            ports = by_ip[ip]
            if i < len(ports):
                yield ip, ports[i]


def _count_scan_targets(targets):
    """
    Count the normalized endpoint fan-out without storing the expanded list.
    Only safe for re-iterable inputs (list/tuple/set). For generator inputs,
    use streaming mode instead and skip the count.
    """
    total = 0
    for target in targets:
        if isinstance(target, tuple) and len(target) >= 2:
            total += 1 if _normalize_endpoint(target) else 0
            continue

        if isinstance(target, str):
            raw = target.strip()
            if not raw:
                continue
            if ":" not in raw and not raw.startswith("["):
                total += len(config.TARGET_PORTS)
                continue

        total += 1 if parse_ip_port(target) else 0
    return total


def _count_unique_scan_ips(targets):
    """Same caveat as _count_scan_targets — re-iterable inputs only."""
    unique = set()
    for target in targets:
        if isinstance(target, tuple) and len(target) >= 1:
            normalized = _normalize_endpoint(target if len(target) >= 2 else (target[0], 0))
            ip = normalized[0] if normalized else str(target[0]).strip()
        else:
            parsed = parse_ip_port(target)
            ip = parsed[0].strip() if parsed else ""
        if ip:
            unique.add(ip)
    return len(unique)


async def run_tcp_scan(targets, concurrency, desc="Scanning", timeout=3.0):
    if not targets:
        return []

    if not isinstance(targets, list):
        targets = list(targets)

    total = _count_scan_targets(targets)
    if total <= 0:
        return []

    sem = asyncio.Semaphore(concurrency)
    found = []
    completed = 0
    task_buffer_limit = max(64, min(2048, max(1, concurrency) * 6))
    target_iter = iter(_iter_scan_targets(targets))
    tasks: set = set()

    def _spawn_one_task() -> bool:
        try:
            target = next(target_iter)
        except StopIteration:
            return False
        task = asyncio.create_task(_check_tcp_endpoint(target, sem, timeout=timeout))
        tasks.add(task)
        return True

    for _ in range(task_buffer_limit):
        if not _spawn_one_task():
            break

    try:
        while tasks:
            done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for future in done:
                res = await future
                if res:
                    found.append(res)
                completed += 1
                if completed % 10 == 0 or completed == total:
                    bar_len = 30
                    filled = int(bar_len * completed / total)
                    bar = '█' * filled + '-' * (bar_len - filled)
                    percent = (completed / total) * 100
                    sys.stdout.write(f"\r   [{bar}] {percent:.1f}% ({completed}/{total}) {desc:<15}")
                    sys.stdout.flush()

            while len(tasks) < task_buffer_limit:
                if not _spawn_one_task():
                    break
    finally:
        await _cancel_and_await(tasks)

    sys.stdout.write('\r' + ' ' * 80 + '\r')
    return found


# ==========================================
# RESPONSE CLASSIFIER
# ==========================================
_HARD_REJECT = [
    b"error 1034",
    b"error 1001",
    b"error 1002",
    b"error 1003",
    b"error 1016",
    b"error 1033",
    b"edge ip restricted",
    b"direct ip access not allowed",
    b"peyvandha.ir",
    b"internet.ir",
    b"10.10.3",
    b"cra.ir",
    b"app-unavailable-in-region",
    b"unavailable in your region",
    b"gemini.google.com/faq",
    b"does not have permission to get url",
    b"that's all we know",
    b"unknown domain",
    b"your client does not have permission",
    b"www.google.com/images/errors/robot.png",
    b"invalid host header",
    b"no such application",
    b"fastly error: unknown domain"
]

_SOFT_ACCEPT = [
    b"unable to load site",
    b"sorry, you have been blocked",
]

_EDGE_IP_RESTRICTED_MARKERS = (
    b"error 1034",
    b"edge ip restricted",
)
_NON_RETRYABLE_REJECT_TAGS = (
    "HARD_REJECT:EDGE_IP_RESTRICTED",
)
_NON_OVERRIDABLE_HARD_REJECT = (
    b"error 1034",
    b"error 1001",
    b"error 1002",
    b"error 1003",
    b"error 1016",
    b"error 1033",
    b"edge ip restricted",
    b"direct ip access not allowed",
    b"peyvandha.ir",
    b"internet.ir",
    b"10.10.3",
    b"cra.ir",
    b"app-unavailable-in-region",
    b"unavailable in your region",
    b"unknown domain",
    b"invalid host header",
    b"no such application",
    b"fastly error: unknown domain",
)
_TLS_HTTP_FALLBACK_ACCEPT_STATUS = {
    200, 201, 202, 203, 204, 205, 206,
    300, 301, 302, 303, 304, 307, 308,
    401, 403, 404, 405, 429,
}

_CDN_SIGS = [
    b"server: cloudflare",
    b"server: gws",
    b"server: sffe",
    b"server: varnish",
    b"server: bunny",
    b"x-fastly-request-id:",
    b"cf-ray:",
    b"cf-cache-status:",
    b"x-served-by:",
    b"x-cache:",
]

_HARD_REJECT_RE = re.compile(b"|".join(re.escape(p) for p in _HARD_REJECT))
_SOFT_ACCEPT_RE = re.compile(b"|".join(re.escape(p) for p in _SOFT_ACCEPT))
_CDN_SIGS_RE = re.compile(b"|".join(re.escape(p) for p in _CDN_SIGS))
_NON_OVERRIDABLE_RE = re.compile(b"|".join(re.escape(p) for p in _NON_OVERRIDABLE_HARD_REJECT))
_EDGE_IP_RESTRICTED_RE = re.compile(b"|".join(re.escape(p) for p in _EDGE_IP_RESTRICTED_MARKERS))


def _hard_reject_tag(resp: bytes) -> str | None:
    if not resp:
        return None
    resp_lower = resp.lower()
    if _EDGE_IP_RESTRICTED_RE.search(resp_lower):
        return "HARD_REJECT:EDGE_IP_RESTRICTED"
    return None


def _is_google_family_domain(domain: str) -> bool:
    clean = (domain or "").strip().lower().strip(".")
    if not clean:
        return False
    for suffix in _GOOGLE_FAMILY_SUFFIXES:
        if clean == suffix or clean.endswith("." + suffix):
            return True
    return False


def _extract_status_code(resp_lower: bytes) -> int | None:
    if not resp_lower:
        return None
    status_line = resp_lower.split(b'\r\n', 1)[0]
    if b'http/' not in status_line:
        return None
    m = _STATUS_RE.search(status_line)
    if not m:
        return None
    try:
        return int(m.group(1))
    except Exception:
        return None


def _has_non_overridable_hard_reject(resp_lower: bytes) -> bool:
    return bool(_NON_OVERRIDABLE_RE.search(resp_lower))


def _is_non_retryable_reject_reason(reason: str) -> bool:
    if not reason:
        return False
    return any(tag in reason for tag in _NON_RETRYABLE_REJECT_TAGS)


def _is_endpoint_dead_reason(reason: str) -> bool:
    """
    A reason indicating the IP itself is unreachable, NOT just one domain
    being blocked. When a single probe returns this, we abort all sibling
    probes for the same endpoint immediately — saves up to 7 wasted
    socket attempts per dead IP.

    NOTE: TimeoutError and ConnectionRefusedError are treated as hard IP-level
    signals because they usually mean the socket path itself is dead; if all
    sibling probes on an endpoint resolve this way, retries are unnecessary.
    """
    if not reason:
        return False
    rl = reason.lower()
    if "blackhole" in rl:
        return False
    if "connectionrefusederror" in rl:
        return True
    if "timed out" in rl or "timeouterror" in rl or "timeout" in rl:
        return True
    if rl.startswith("os error"):  # EHOSTUNREACH, ENETUNREACH, EAI_NONAME, etc.
        return True
    return False


def _is_transient_failure_reason(reason: str) -> bool:
    if not reason:
        return True
    if _is_non_retryable_reject_reason(reason):
        return False
    reason_lower = reason.lower()
    non_retryable_ssl_tokens = (
        "certificate_verify_failed",
        "wrong_version_number",
        "sslv3_alert_handshake_failure",
        "connectionreseterror",
    )
    if any(tok in reason_lower for tok in non_retryable_ssl_tokens):
        return False
    if reason_lower.startswith("rejected server response"):
        return False
    transient_tokens = (
        "timeout",
        "dead/empty",
        "ssl error",
        "connection error",
        "read error",
        "hard scan timeout",
    )
    return any(tok in reason_lower for tok in transient_tokens)


def _is_blackhole_failure_reason(reason: str) -> bool:
    return bool(reason and "blackhole" in reason.lower())


def _ban_endpoint_for_domain_variants(domain: str, endpoint: tuple, ban_sink=None) -> None:
    clean_domain = (domain or "").strip().lower().strip(".")
    if not clean_domain:
        return

    keys = [clean_domain]
    try:
        base = (get_base_domain(clean_domain) or clean_domain).strip().lower().strip(".")
    except Exception:
        base = clean_domain

    if base and base not in keys:
        keys.append(base)

    for key in keys:
        try:
            if ban_sink is not None:
                ban_sink.append((key, endpoint))
            else:
                add_ban_entry(key, endpoint, persist=True)
        except Exception:
            pass


@lru_cache(maxsize=4096)
def _domain_match_tokens(domain: str):
    """Return a small cached set of byte tokens that should match this domain."""
    clean = (domain or "").strip().lower().strip(".")
    if not clean:
        return tuple()

    tokens = [clean.encode("utf-8", "ignore")]

    try:
        base_domain = get_base_domain(clean)
    except Exception:
        base_domain = clean

    base_domain = (base_domain or clean).strip().lower().strip(".")
    if base_domain and base_domain != clean:
        tokens.append(base_domain.encode("utf-8", "ignore"))

    out = []
    seen = set()
    for tok in tokens:
        if tok and tok not in seen:
            seen.add(tok)
            out.append(tok)
    return tuple(out)


@lru_cache(maxsize=8192)
def _cached_base_domain(domain: str) -> str:
    clean = (domain or "").strip().lower().strip(".")
    if not clean:
        return ""
    try:
        return (get_base_domain(clean) or clean).strip().lower().strip(".")
    except Exception:
        return clean


def classify_response(resp: bytes, domain: str) -> str:
    if not resp:
        return 'dead'

    resp_lower = resp.lower()

    if _HARD_REJECT_RE.search(resp_lower):
        return 'reject'

    if _SOFT_ACCEPT_RE.search(resp_lower):
        return 'soft_accept'

    status_line = resp_lower.split(b'\r\n', 1)[0]
    if b'http/' not in status_line:
        return 'dead'

    m = _STATUS_RE.search(status_line)
    if not m:
        return 'dead'

    status_code = int(m.group(1))

    if status_code < 100 or status_code >= 600:
        return 'reject'

    header_end = resp_lower.find(b'\r\n\r\n')
    headers = resp_lower[:header_end] if header_end != -1 else resp_lower

    has_cdn_sig = bool(_CDN_SIGS_RE.search(headers))
    domain_tokens = _domain_match_tokens(domain)
    has_domain = any(tok in resp_lower for tok in domain_tokens)
    has_location_match = b"\r\nlocation:" in headers and has_domain

    if status_code in (400, 403, 409, 421, 451):
        if has_domain and not has_cdn_sig:
            return 'accept'
        return 'reject'

    if status_code >= 500:
        return 'reject'

    if 200 <= status_code < 400:
        if has_domain or has_location_match or has_cdn_sig:
            return 'accept'
        return 'reject'

    if 400 < status_code < 500:
        if has_domain:
            return 'accept'
        if has_cdn_sig:
            return 'accept'

    return 'reject'


async def probe_route_endpoint(
    ip: str,
    domain: str,
    port: int = 443,
    timeout: float = 4.0,
    http_verify: bool = True,
    tls_only: bool = False,
    return_reason: bool = False,
):
    """
    Lightweight route verifier shared by the router and health checks.

    Uses the same strict TLS + HTTP classification path as the scanner,
    but performs a single bounded probe without retry waves or jitter.
    """
    writer = None
    reason = None
    t0 = time.perf_counter()
    try:
        is_tls = config.is_tls_port(port)
        ctx = config.PROBE_SSL_CONTEXT if is_tls else None
        srv_host = domain if is_tls else None
        connect_timeout = max(0.2, min(float(timeout), 2.5))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=srv_host),
            timeout=connect_timeout,
        )

        if http_verify and is_tls:
            probe_path = _probe_path_for_domain(domain)
            probe = _build_http_probe(domain, probe_path)
            writer.write(probe)
            await writer.drain()

            resp_buf = bytearray()
            header_end = -1
            first_read_deadline = max(0.5, min(float(timeout), 4.0))
            next_read_deadline = max(0.25, min(float(timeout), 2.0))
            first_chunk = True
            while True:
                deadline = first_read_deadline if first_chunk else next_read_deadline
                chunk = await asyncio.wait_for(reader.read(4096), timeout=deadline)
                first_chunk = False
                if not chunk:
                    break
                resp_buf.extend(chunk)
                if header_end == -1:
                    idx = resp_buf.find(b"\r\n\r\n")
                    if idx != -1:
                        header_end = idx + 4
                if header_end != -1 and len(resp_buf) >= header_end + 4096:
                    break
                if len(resp_buf) >= 8192:
                    break

            if resp_buf:
                verdict = classify_response(bytes(resp_buf), domain)
                if verdict == 'reject':
                    reason = 'http-reject'
                    if return_reason:
                        return None, (time.perf_counter() - t0) * 1000.0, reason
                    return None

        result = ip if tls_only else (ip, port)
        if return_reason:
            return result, (time.perf_counter() - t0) * 1000.0, (reason or 'ok')
        return result
    except asyncio.TimeoutError:
        reason = 'timeout'
    except ssl.SSLError:
        reason = 'tls-error'
    except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, OSError):
        reason = 'connect-error'
    except Exception:
        reason = 'error'
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    if return_reason:
        return None, (time.perf_counter() - t0) * 1000.0, (reason or 'error')
    return None


# ==========================================
# TLS PROBE ENGINE (DIRECT)
# ==========================================

async def _probe_domain(ip: str, domain: str, port: int, timeout: float,
                        probe_path_override: str | None = None):
    """
    Direct TLS probe to (ip, port) with SNI=domain.
    Returns (verdict, latency_ms, reason).
    """
    start_time = time.perf_counter()
    writer = None

    try:
        # Burst smoothing: reduce simultaneous SYN bursts that trigger initial
        # edge blackholes / SYN flood protection.
        await asyncio.sleep(random.uniform(0.01, 0.15))
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                ip, port,
                ssl=config.PROBE_SSL_CONTEXT,
                server_hostname=domain,
            ),
            timeout=timeout,
        )

        try:
            raw_sock = writer.get_extra_info('socket')
            if raw_sock is not None:
                raw_sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
        except Exception:
            pass

        probe_path = probe_path_override or _probe_path_for_domain(domain)
        probe = _build_http_probe(domain, probe_path)
        writer.write(probe)
        await writer.drain()

        _HEADER_BODY_SLICE = 4096
        _HARD_CAP = 8192
        configured_read_timeout = float(getattr(config, 'PROBE_READ_TIMEOUT', 3.5))
        read_timeout = max(2.5, min(7.0, configured_read_timeout))

        _resp_buf = bytearray()

        async def _do_read() -> None:
            header_end = -1
            while True:
                try:
                    chunk = await reader.read(8192)
                except Exception:
                    break
                if not chunk:
                    break
                _resp_buf.extend(chunk)
                if header_end == -1:
                    idx = _resp_buf.find(b'\r\n\r\n')
                    if idx != -1:
                        header_end = idx + 4
                        if len(_resp_buf) >= header_end + _HEADER_BODY_SLICE:
                            break
                else:
                    if len(_resp_buf) >= header_end + _HEADER_BODY_SLICE:
                        break
                if len(_resp_buf) >= _HARD_CAP:
                    break

        try:
            await asyncio.wait_for(_do_read(), timeout=read_timeout)
        except asyncio.TimeoutError:
            pass
        resp = bytes(_resp_buf)

        resp_lower = resp.lower() if resp else b""
        verdict = classify_response(resp, domain)
        lat = (time.perf_counter() - start_time) * 1000 if verdict in ('accept', 'soft_accept') else 0.0

        # Default reason
        reason = "Accepted"

        # Extract headers/body info for richer diagnostics when not accepted
        header_end = resp.find(b'\r\n\r\n')
        headers = resp[:header_end] if header_end != -1 else resp
        status_code = _extract_status_code(resp_lower)

        def _extract_hdr(byte_hdr_name: bytes) -> str | None:
            try:
                m = re.search(rb'(?mi)^' + re.escape(byte_hdr_name) + rb'\s*:\s*(.+)$', headers)
                if m:
                    return m.group(1).strip().decode('utf-8', 'ignore')
            except Exception:
                pass
            return None

        server_hdr = _extract_hdr(b'server')
        cf_ray = _extract_hdr(b'cf-ray')

        body_snippet = None
        try:
            if header_end != -1 and len(resp) > header_end + 4:
                body = resp[header_end + 4: header_end + 4 + 50]
                if any(32 <= b <= 126 for b in body):
                    body_snippet = body.decode('utf-8', 'ignore')
        except Exception:
            body_snippet = None

        if verdict == 'reject':
            # Hard reject special-case tag
            tag = _hard_reject_tag(resp)
            if tag == "HARD_REJECT:EDGE_IP_RESTRICTED":
                reason = "[HARD_REJECT:EDGE_IP_RESTRICTED] Cloudflare Error 1034 / Edge IP Restricted"
            else:
                # TLS->HTTP fallback acceptance
                if (
                    status_code in _TLS_HTTP_FALLBACK_ACCEPT_STATUS
                    and not _has_non_overridable_hard_reject(resp_lower)
                ):
                    verdict = 'accept'
                    lat = (time.perf_counter() - start_time) * 1000
                    reason = "Accepted (TLS+HTTP fallback)"
                else:
                    parts = []
                    if status_code is not None:
                        parts.append(str(status_code))
                    if server_hdr:
                        parts.append(f"Server: {server_hdr}")
                    if cf_ray:
                        parts.append(f"CF-Ray: {cf_ray}")
                    if body_snippet:
                        parts.append(f"Body={repr(body_snippet)}")
                    if parts:
                        reason = "Rejected: " + " | ".join(parts)
                    else:
                        status_line = resp.split(b'\r\n')[0].decode('utf-8', 'ignore') if resp else "Empty Response"
                        reason = f"Rejected Server Response: {status_line}"
        elif verdict == 'dead':
            reason = "Dead/Empty HTTP Response"
        elif verdict == 'soft_accept':
            parts = []
            if status_code is not None:
                parts.append(str(status_code))
            if server_hdr:
                parts.append(f"Server: {server_hdr}")
            if cf_ray:
                parts.append(f"CF-Ray: {cf_ray}")
            if body_snippet:
                parts.append(f"Body={repr(body_snippet)}")
            if parts:
                reason = "SoftAccept: " + " | ".join(parts)
            else:
                reason = "Soft Accept / Cloudflare Block"

        return verdict, lat, reason

    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        return 'dead', 0.0, 'SSL Handshake Timeout (Blackholed)'
    except ssl.SSLError as e:
        # Try to extract OpenSSL/SSL alert or reason text from exception
        ssl_reason = None
        try:
            # common format: "[SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:... )"
            s = str(e)
            m = re.search(r"\[SSL: ([^\]]+)\]", s)
            if m:
                ssl_reason = m.group(1)
            else:
                ssl_reason = getattr(e, 'reason', None) or s
        except Exception:
            ssl_reason = str(e)
        return 'dead', 0.0, f'SSL Error ({ssl_reason})'
    except ConnectionRefusedError:
        return 'dead', 0.0, 'ConnectionRefusedError'
    except ConnectionResetError:
        return 'dead', 0.0, 'ConnectionResetError'
    except OSError as e:
        return 'dead', 0.0, f'OS Error ({e.errno or "?"})'
    except Exception as e:
        op = 'Read' if writer is not None else 'Connection'
        return 'dead', 0.0, f'{op} Error ({type(e).__name__})'
    finally:
        if writer is not None:
            await _close_writer(writer)


class _DeadIPTracker:
    """
    Per-IP TCP-connect outcome tracker shared across all endpoints in a scan.

    An IP is considered 'soft dead' once it has accumulated >= threshold
    consecutive TCP-connect timeouts AND zero TCP-connect successes. Once
    marked, future endpoints on that IP short-circuit at _check_ip_tls_logic
    without opening a socket — saving (6 - threshold) ports' worth of 6s
    timeout per dead IP.

    Threshold semantics (default 3 with 6 ports): an IP gets a fair shot at
    most of its ports before being culled. Combined with port-major
    round-robin iteration, an IP with one open port (e.g. 2096 only) is
    found unless 2096 happened to land in the last 3 of the per-IP port
    order — and we randomize port order in _iter_scan_targets for bare-IP
    inputs, so that's a coin flip per IP. Tuple inputs (already-specific
    endpoints from preflight) preserve their ordering.

    A host-unreachable OSError (EHOSTUNREACH/ENETUNREACH) is a stronger
    signal than a timeout — one is enough to mark dead immediately.
    """
    __slots__ = ("threshold", "_state")

    def __init__(self, threshold: int = 3):
        self.threshold = max(1, int(threshold))
        # ip -> [timeout_count, success_count]
        self._state: dict[str, list[int]] = {}

    def is_dead(self, ip: str) -> bool:
        s = self._state.get(ip)
        if not s:
            return False
        return s[1] == 0 and s[0] >= self.threshold

    def record_timeout(self, ip: str) -> None:
        s = self._state.get(ip)
        if s is None:
            self._state[ip] = [1, 0]
        else:
            s[0] += 1

    def record_success(self, ip: str) -> None:
        s = self._state.get(ip)
        if s is None:
            self._state[ip] = [0, 1]
        else:
            s[1] += 1

    def mark_dead_now(self, ip: str) -> None:
        s = self._state.get(ip)
        if s is None:
            self._state[ip] = [self.threshold, 0]
        elif s[1] == 0:
            s[0] = max(s[0], self.threshold)

    def dead_count(self) -> int:
        return sum(1 for s in self._state.values() if s[1] == 0 and s[0] >= self.threshold)


# Errno values that mean the IP itself is unroutable (not just one port closed).
_HOST_UNREACHABLE_ERRNOS = frozenset({
    101,  # ENETUNREACH (Linux)
    113,  # EHOSTUNREACH (Linux)
    51,   # ENETUNREACH (macOS / BSD)
    65,   # EHOSTUNREACH (macOS / BSD)
})


async def _check_ip_tls_logic(ip, port, domains, probe_domains, timeout,
                              probe_sem_size,
                              skip_tcp=False, deep_scan=False,
                              throttler=None, ban_sink=None,
                              dead_ip_tracker=None, pause_controller=None):
    """
    Orchestrate probes for one (ip, port) endpoint.

        Per-endpoint probe semaphore only. Global concurrency is enforced by
        the task-level semaphore in check_ip_tls_single.
    """
    passed_domains: list = []
    soft_domains: list = []
    latencies: list = []
    fail_reasons: dict = {}
    endpoint = (ip, port)

    def _record_outcome(ok: bool, timed_out: bool, latency_ms: float) -> None:
        if throttler is not None:
            try:
                throttler.record_outcome(ok, timed_out, latency_ms)
            except Exception:
                pass

    probe_sem = asyncio.Semaphore(max(1, probe_sem_size))

    def _all_domain_failures_are_ip_dead() -> bool:
        if passed_domains or soft_domains:
            return False
        if len(fail_reasons) < len(probe_domains):
            return False
        return all(_is_endpoint_dead_reason(r) for r in fail_reasons.values())

    async def _wait_if_paused():
        if pause_controller is not None:
            await pause_controller.wait_if_paused()

    # ── Soft dead-IP short-circuit ────────────────────────────────────────
    # Skip endpoints on IPs that have already failed TCP on enough ports.
    # The full-timeout slot-squat is the single biggest perf killer on
    # dead-IP-heavy scans (see scanner perf notes); short-circuiting here
    # frees the socket_sem slot in microseconds.
    if dead_ip_tracker is not None and dead_ip_tracker.is_dead(ip):
        return ip, port, [], 9999, [], {
            d: f"TCP Port {port} Skipped (IP marked dead after {dead_ip_tracker.threshold}+ TCP timeouts)"
            for d in domains
        }

    await _wait_if_paused()
    if not skip_tcp:
        # Tighter timeout for the FIRST TCP-connect attempt: live IPs respond
        # in <1s, so 2.5s catches them but kills dead IPs in 2.5s instead of
        # the full SCAN_TIMEOUT (typically 6s). The retry phase still uses
        # the full timeout for TLS-level retries.
        initial_tcp_timeout = min(float(timeout), 2.5)
        tcp_started = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=initial_tcp_timeout
            )
            await _close_writer(writer)
            _record_outcome(True, False, (time.monotonic() - tcp_started) * 1000)
            if dead_ip_tracker is not None:
                dead_ip_tracker.record_success(ip)
        except Exception as e:
            timed_out = isinstance(e, asyncio.TimeoutError)
            _record_outcome(False, timed_out, (time.monotonic() - tcp_started) * 1000)
            if dead_ip_tracker is not None:
                if timed_out:
                    dead_ip_tracker.record_timeout(ip)
                elif isinstance(e, OSError) and not isinstance(e, ConnectionRefusedError):
                    # ConnectionRefused = port closed but IP responsive (do not
                    # mark dead). Other OSErrors with host-unreachable errno
                    # mean the IP itself is unroutable — mark dead immediately.
                    if getattr(e, "errno", None) in _HOST_UNREACHABLE_ERRNOS:
                        dead_ip_tracker.mark_dead_now(ip)
            return ip, port, [], 9999, [], {
                d: f"TCP Port {port} Closed/Timeout ({type(e).__name__})" for d in domains
            }

    async def probe_once(domain: str, custom_timeout=None, alt_path=None):
        """One socket open, bounded by the per-endpoint probe semaphore."""
        async with probe_sem:
            await _wait_if_paused()
            v, l, r = await _probe_domain(
                ip, domain, port,
                custom_timeout if custom_timeout is not None else timeout,
                probe_path_override=alt_path,
            )
            _record_outcome(
                v == 'accept',
                v == 'dead' and 'timeout' in r.lower(),
                l,
            )
            return domain, v, l, r

    # ── Phase 1: initial wave of probes ───────────────────────────────────
    await _wait_if_paused()
    initial_results = await asyncio.gather(
        *(probe_once(d) for d in probe_domains),
        return_exceptions=True,
    )

    failed_domains = []
    for res in initial_results:
        if isinstance(res, Exception):
            continue
        domain, verdict, lat, reason = res
        if verdict == 'accept':
            passed_domains.append(domain)
            latencies.append(lat)
        elif verdict == 'soft_accept':
            soft_domains.append(domain)
            latencies.append(lat)
            fail_reasons[domain] = reason
        else:
            if _is_non_retryable_reject_reason(reason):
                fail_reasons[domain] = reason
                _ban_endpoint_for_domain_variants(domain, endpoint, ban_sink)
                continue
            if not _is_transient_failure_reason(reason):
                fail_reasons[domain] = reason
                continue
            failed_domains.append(domain)
            fail_reasons[domain] = reason

    if _all_domain_failures_are_ip_dead():
        return ip, port, [], 9999, [], fail_reasons

    # ── Phase 2: retry transient failures ─────────────────────────────────
    if failed_domains:
        def _retry_sleep_seconds(reason: str) -> float:
            return random.uniform(0.5, 1.5) if _is_blackhole_failure_reason(reason) else random.uniform(0.1, 0.5)

        async def retry_probe(domain: str):
            last_reason = fail_reasons[domain]
            attempts = _retry_attempts_for_domain(domain)

            for attempt in range(attempts):
                await _wait_if_paused()
                dom_clean = (domain or "").strip().lower()
                if dom_clean in _CRITICAL_PROBE_DOMAINS:
                    deep_timeout = timeout + 4.0 + (attempt * 2.5)
                else:
                    deep_timeout = timeout + 3.0 + (attempt * 2.0)

                alt_path = None
                if dom_clean in _CRITICAL_PROBE_DOMAINS and attempt >= 1:
                    alt_path = "/"

                try:
                    _, v, l, r = await probe_once(domain, deep_timeout, alt_path)
                    if v == 'accept':
                        return domain, 'accept', l, r
                    if v == 'soft_accept':
                        return domain, 'soft_accept', l, r
                    if _is_non_retryable_reject_reason(r):
                        return domain, 'reject', 0.0, r
                    last_reason = f"Retry {attempt+1} Failed: {r}"
                except Exception as e:
                    last_reason = f"Retry Error: {type(e).__name__}"
                    if attempt < attempts - 1:
                        if _is_transient_failure_reason(last_reason):
                            await asyncio.sleep(_retry_sleep_seconds(last_reason))
                        else:
                            return domain, 'reject', 0.0, last_reason
                    continue
                if attempt < attempts - 1:
                    if _is_transient_failure_reason(last_reason):
                        await asyncio.sleep(_retry_sleep_seconds(last_reason))
                    else:
                        return domain, 'reject', 0.0, last_reason
            return domain, 'reject', 0.0, last_reason

        retry_tasks = {asyncio.create_task(retry_probe(d)) for d in failed_domains}
        for completed in asyncio.as_completed(retry_tasks):
            try:
                res = await completed
            except Exception:
                continue
            domain, verdict, lat, reason = res
            if verdict == 'accept':
                passed_domains.append(domain)
                latencies.append(lat)
                fail_reasons.pop(domain, None)
            elif verdict == 'soft_accept':
                soft_domains.append(domain)
                latencies.append(lat)
                fail_reasons[domain] = reason
            else:
                fail_reasons[domain] = reason
                if _is_non_retryable_reject_reason(reason):
                    _ban_endpoint_for_domain_variants(domain, endpoint, ban_sink)
            if _all_domain_failures_are_ip_dead():
                for task in retry_tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*retry_tasks, return_exceptions=True)
                break

    if not passed_domains and not soft_domains:
        return ip, port, [], 9999, [], fail_reasons

    # Gemini-specific hygiene (unchanged)
    gemini_passed = _GEMINI_PROBE_HOST in passed_domains
    if not gemini_passed:
        gemini_reason = fail_reasons.get(_GEMINI_PROBE_HOST, "")
        if gemini_reason and not _is_transient_failure_reason(gemini_reason):
            try:
                if ban_sink is not None:
                    ban_sink.append((_GEMINI_PROBE_HOST, endpoint))
                else:
                    add_ban_entry(_GEMINI_PROBE_HOST, endpoint, persist=True)
            except Exception:
                pass

    avg_latency = int(sum(latencies) / len(latencies)) if latencies else 9999
    return ip, port, passed_domains, avg_latency, soft_domains, fail_reasons


async def check_ip_tls(
    endpoint,
    domains,
    semaphore,
    timeout=config.SCAN_TIMEOUT,
    skip_tcp=False,
    deep_scan=False,
    throttler=None,
):
    """
    Backward-compatible wrapper used by background workers.
    """
    if isinstance(endpoint, tuple) and len(endpoint) >= 2:
        normalized = _normalize_endpoint(endpoint)
        if not normalized:
            return None, 0, [], 9999, [], {}
        ip, port = normalized
    else:
        parsed = parse_ip_port(endpoint)
        if not parsed:
            return None, 0, [], 9999, [], {}
        ip, port = parsed

    probe_domains = _order_probe_domains(list(domains or []) + list(_EXTRA_PROBE_DOMAINS))
    return await check_ip_tls_single(
        ip,
        port,
        domains,
        probe_domains,
        semaphore,
        timeout=timeout,
        skip_tcp=skip_tcp,
        deep_scan=deep_scan,
        throttler=throttler,
    )


# ==========================================
# SINGLE-PAIR TASK WRAPPER
# ==========================================
async def check_ip_tls_single(
    ip, port, domains, probe_domains, socket_sem,
    timeout=config.SCAN_TIMEOUT, skip_tcp=False, deep_scan=False,
    throttler=None, ban_sink=None, probe_sem_size=None,
    dead_ip_tracker=None, pause_controller=None,
):
    """
    Process a single (ip, port) pair.

    Hard timeout is COMPUTED, not pulled from config.HARD_SCAN_TIMEOUT.
    The 45s value in config was too generous: under contention, dead
    endpoints squatted slots for the full 45s, and the result loop drained
    so slowly that 71% of probes hit the timeout in the v2 test (per the
    debug log). Now we compute a tight envelope based on the actual retry
    chain length and cap at 30s.
    """
    if probe_sem_size is None:
        probe_sem_size = _PER_IP_PROBE_CONCURRENCY

    # Hard timeout: allow enough time for all probe waves + retry waves.
    waves = max(1, math.ceil(len(probe_domains) / max(1, probe_sem_size)))
    per_retry_worker_budget = (timeout + 3.0) + 0.2 + (timeout + 5.0)
    hard_timeout = max(
        float(getattr(config, "HARD_SCAN_TIMEOUT", 45.0)),
        (timeout * waves) + (per_retry_worker_budget * waves) + 6.0,
    )

    async def _wait_if_paused():
        if pause_controller is not None:
            await pause_controller.wait_if_paused()

    # Cheap pre-check outside the socket_sem: if the IP is already known dead,
    # don't even wait for a slot — just return. Saves the slot for live work.
    if dead_ip_tracker is not None and dead_ip_tracker.is_dead(ip):
        return ip, port, [], 9999, [], {
            d: f"TCP Port {port} Skipped (IP marked dead after {dead_ip_tracker.threshold}+ TCP timeouts)"
            for d in probe_domains
        }

    try:
        await _wait_if_paused()
        async with socket_sem:
            await _wait_if_paused()
            return await asyncio.wait_for(
                _check_ip_tls_logic(
                    ip, port, domains, probe_domains, timeout,
                    probe_sem_size,
                    skip_tcp, deep_scan, throttler, ban_sink,
                    dead_ip_tracker=dead_ip_tracker,
                    pause_controller=pause_controller,
                ),
                timeout=hard_timeout,
            )
    except asyncio.TimeoutError:
        return ip, port, [], 9999, [], {
            d: f"Hard Scan Timeout (>{hard_timeout:.1f}s)" for d in probe_domains
        }
    except Exception as e:
        return ip, port, [], 9999, [], {
            d: f"Error ({type(e).__name__})" for d in probe_domains
        }


async def run_mass_scan(targets, domains, results_list, skip_tcp=False, deep_scan=False, pause_controller=None):
    """
    Top-level scan driver.

    Concurrency model (v4):
    -----------------------
    socket_budget   = absolute cap on simultaneous outbound TLS sockets
                      (= config.MAX_CONCURRENT_SCANS).
    probe_sem_size  = max simultaneous probes per single endpoint
                      (_PER_IP_PROBE_CONCURRENCY = 4).
    endpoint_slots  = max endpoint orchestrators alive concurrently
                      = max(1, socket_budget // probe_sem_size).

    The math: endpoint_slots × probe_sem_size = socket_budget. Every probe
    that wants a socket finds an immediately-free slot — no queue wait.

    With 10 probe domains and probe_sem=4, an endpoint completes its
    initial probe wave in ceil(10/4) = 3 waves × 6s = 18s, well under
    the 40s hard_timeout. v3 used probe_sem=2 → 5 waves × 6s = 30s,
    which busted the 28s hard_timeout for ~51% of endpoints, silently
    discarding their successful probe results.

    Streaming targets:
    ------------------
    If targets is a generator/iterator (not list/tuple/set), we don't
    materialize it — saves RAM on huge CIDR expansions. We lose pre-count
    and ETA in that mode but the scan still runs correctly.
    """
    if not targets:
        print("\n[*] No IPs provided for async scan.")
        return

    total_start = time.monotonic()

    if pause_controller is None:
        pause_controller = PauseController()
    pause_controller.bind_loop(asyncio.get_running_loop())

    net_status_text = ""
    net_status_until = 0.0
    net_status_sticky = False

    def _set_net_status(msg: str, *, sticky: bool, ttl: float = 0.0, dim: bool = False) -> None:
        nonlocal net_status_text, net_status_until, net_status_sticky
        rendered = f"{_c('dim')}{msg}{_c('reset')}" if dim else msg
        net_status_text = rendered
        net_status_sticky = bool(sticky)
        net_status_until = 0.0 if sticky else (time.monotonic() + max(0.0, float(ttl)))

    def _current_net_status() -> str:
        nonlocal net_status_text, net_status_until, net_status_sticky
        if not net_status_text:
            return ""
        if net_status_sticky:
            return net_status_text
        if time.monotonic() <= net_status_until:
            return net_status_text
        net_status_text = ""
        net_status_until = 0.0
        net_status_sticky = False
        return ""

    async def _ping_once(host: str, timeout_s: float) -> bool:
        if not host:
            return False
        timeout_s = max(0.5, float(timeout_s))
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout_s * 1000)), host]
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-W", str(int(timeout_s * 1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_s))), host]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except Exception:
            return False

        try:
            await asyncio.wait_for(proc.communicate(), timeout=timeout_s + 0.5)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return False
        return proc.returncode == 0

    async def _connectivity_monitor(stop_event: asyncio.Event) -> None:
        hosts = ["nobitex.ir", "digikala.com", "google.com"]
        ok_interval = 5.0
        fail_interval = 1.0
        timeout_s = 1.5
        while not stop_event.is_set():
            results = await asyncio.gather(
                *(_ping_once(host, timeout_s) for host in hosts),
                return_exceptions=True,
            )
            ok_map = {}
            for host, res in zip(hosts, results):
                ok_map[host] = bool(res is True)

            any_ok = any(ok_map.values())
            if not any_ok:
                if not pause_controller.is_paused_by("net"):
                    pause_controller.pause("net")
                    status = ", ".join(f"{h}=down" for h in hosts)
                    _set_net_status(
                        f"[NET] No ping replies. Auto-pausing scan. ({status})",
                        sticky=True,
                    )
                interval = fail_interval
            else:
                if pause_controller.is_paused_by("net"):
                    pause_controller.resume("net")
                    status = ", ".join(f"{h}={'ok' if ok_map[h] else 'down'}" for h in hosts)
                    _set_net_status(
                        f"[NET] Connectivity restored. Auto-resuming scan. ({status})",
                        sticky=False,
                        ttl=3.0,
                        dim=True,
                    )
                interval = ok_interval

            try:
                await asyncio.wait_for(stop_event.wait(), timeout=interval)
            except asyncio.TimeoutError:
                continue

    # ── Targets handling: support streaming for huge subnets ──────────────
    is_listlike = isinstance(targets, (list, tuple, set, frozenset))

    if is_listlike:
        # Re-iterable input: pre-count cheaply for ETA support.
        if not isinstance(targets, list):
            # Note: this DOES materialize set/tuple, but those are typically
            # already-finite collections. The dangerous case (1M+ generator
            # over CIDR fan-out) is handled by the streaming branch below.
            targets = list(targets)
        total_tasks = _count_scan_targets(targets)
        if total_tasks <= 0:
            print("\n[*] No valid endpoints provided for async scan.")
            return
        unique_ips = _count_unique_scan_ips(targets)
        # Port-major round-robin so the dead-IP tracker can short-circuit
        # subsequent ports of dead IPs once the first sweep has finished.
        target_iter = iter(_iter_scan_targets_round_robin(targets))
    else:
        # Generator/iterator: stream lazily, no pre-count, no ETA.
        # This is the RAM-safe path for huge subnet expansions.
        total_tasks = None
        unique_ips = None
        target_iter = iter(_iter_scan_targets(targets))


    # ── Concurrency math ──────────────────────────────────────────────────
    socket_budget = max(1, int(config.MAX_CONCURRENT_SCANS))
    n_probes_per_ep = max(1, len(domains) + len(_EXTRA_PROBE_DOMAINS))
    probe_sem_size = max(1, min(_PER_IP_PROBE_CONCURRENCY, socket_budget, n_probes_per_ep))
    endpoint_slots = max(1, socket_budget // probe_sem_size)

    gateway = _find_default_gateway()
    throttler = AdaptiveThrottler(
        initial=endpoint_slots,
        gateway=gateway,
        max_limit=endpoint_slots,
        verbose=False,
    )
    socket_sem = throttler.semaphore
    throttler_task = asyncio.create_task(throttler.run())
    routes_changed = False

    loop_kind = "uvloop" if _running_on_uvloop() else "asyncio (selector)"
    if total_tasks is not None:
        print(f"\n[*] Initializing Async Engine for {total_tasks} IP:Port pairs across {unique_ips} unique IPs...")
    else:
        print(f"\n[*] Initializing Async Engine in streaming mode (target count unknown — saves RAM on big subnets)...")
    print(
        f"[*] Concurrency: {endpoint_slots} endpoints × {probe_sem_size} probes/endpoint "
        f"= {socket_budget} max sockets ({n_probes_per_ep} probes/IP, loop: {loop_kind})"
    )

    cached_eps = load_white_cache()
    cached_ep_set = cached_eps
    worker_eps_collected: set = set()
    asn_cache: dict = {}
    exact_routes = STATE.exact_routes()
    wildcard_routes = STATE.wildcard_routes()
    banned_routes = STATE.banned_routes()

    probe_domains = _order_probe_domains(domains + list(_EXTRA_PROBE_DOMAINS))
    debug_domains = list(probe_domains)
    per_domain_stats = {
        d: {"pass": 0, "soft": 0, "fail": 0, "unknown": 0}
        for d in debug_domains
    }
    accepted_count = 0
    soft_only_count = 0
    dead_count = 0
    accepted_latencies: list[float] = []
    first_result_at = None
    first_success_at = None
    timeout_failures = 0
    retry_failures = 0
    non_retryable_rejects = 0
    failure_reason_counts: dict[str, int] = {}
    interrupted = False
    per_asn_stats: dict[str, dict[str, int]] = {}
    per_asn_failure_reasons: dict[str, dict[str, int]] = {}
    total_tested = len(probe_domains)

    def _get_asn_for_ip(ip: str) -> tuple[str | None, str | None]:
        if ip in asn_cache:
            return asn_cache[ip]
        asn, as_name, _ = get_asn_info(ip)
        asn_cache[ip] = (asn, as_name)
        return asn, as_name

    completed = 0
    scan_start = time.monotonic()
    _PROGRESS_MIN_INTERVAL = 0.2
    _last_progress_draw = 0.0
    _last_progress_width = 0

    def _render_progress(force: bool = False):
        nonlocal _last_progress_draw, _last_progress_width
        now = time.monotonic()
        if not force and (now - _last_progress_draw) < _PROGRESS_MIN_INTERVAL:
            return
        elapsed = max(0.01, now - scan_start)
        rate = completed / elapsed
        paused_tag = " PAUSED" if pause_controller is not None and pause_controller.is_paused() else ""
        net_tag = _current_net_status()

        if total_tasks is not None and total_tasks > 0:
            eta_secs = (total_tasks - completed) / rate if rate > 0 else 0
            if eta_secs < 3600:
                eta_str = f"{int(eta_secs // 60)}m{int(eta_secs % 60):02d}s"
            else:
                eta_str = f"{eta_secs / 3600:.1f}h"
            bar_len = 25
            filled = int(bar_len * completed / total_tasks)
            bar = '█' * filled + '-' * (bar_len - filled)
            percent = (completed / total_tasks) * 100
            line = (
                f"[{bar}] {percent:.1f}% ({completed}/{total_tasks}) "
                f"{rate:.1f}/s ETA:{eta_str}{paused_tag}"
            )
        else:
            # Streaming mode — no total, no ETA
            line = f"[stream] processed: {completed} | {rate:.1f}/s{paused_tag}"

        if net_tag:
            line = f"{line} | {net_tag}"

        pad = max(0, _last_progress_width - len(line))
        sys.stdout.write(f"\r{line}{' ' * pad}")
        sys.stdout.flush()
        _last_progress_draw = now
        _last_progress_width = len(line)

    # Keep a small backlog of tasks waiting on the endpoint semaphore.
    task_buffer_limit = max(64, min(2048, endpoint_slots * 6))
    _ban_sink: list = []
    # Soft dead-IP tracker. Threshold of 3 means an IP must time out on 3
    # different ports (with 0 successes) before its remaining ports are
    # culled. With the user-confirmed multi-port-firewall reality (e.g. some
    # IPs only have 2096 open while 443 is filtered), this leaves room to
    # find narrow open ports while still saving ~50% of dead-IP socket time.
    _dead_ip_tracker = _DeadIPTracker(threshold=3)

    async def _wait_if_paused():
        if pause_controller is not None:
            await pause_controller.wait_if_paused()

    pause_status_stop = None
    pause_status_task = None
    net_monitor_task = None
    if pause_controller is not None:
        pause_status_stop = asyncio.Event()

        net_monitor_task = asyncio.create_task(_connectivity_monitor(pause_status_stop))

        async def _pause_status_loop():
            while not pause_status_stop.is_set():
                if pause_controller.is_paused():
                    _render_progress(force=True)
                try:
                    await asyncio.wait_for(pause_status_stop.wait(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

        pause_status_task = asyncio.create_task(_pause_status_loop())

    try:
        result_q: asyncio.Queue = asyncio.Queue()
        in_flight: set = set()
        targets_exhausted = False

        def _on_done(fut):
            result_q.put_nowait(fut)

        def _spawn_one_task() -> bool:
            nonlocal targets_exhausted
            if targets_exhausted:
                return False
            try:
                ip, port = next(target_iter)
            except StopIteration:
                targets_exhausted = True
                return False
            task = asyncio.create_task(
                check_ip_tls_single(
                    ip, port, domains, probe_domains, socket_sem,
                    skip_tcp=skip_tcp, deep_scan=deep_scan, throttler=throttler,
                    ban_sink=_ban_sink, probe_sem_size=probe_sem_size,
                    dead_ip_tracker=_dead_ip_tracker,
                    pause_controller=pause_controller,
                )
            )
            task.add_done_callback(_on_done)
            in_flight.add(task)
            return True

        for _ in range(task_buffer_limit):
            await _wait_if_paused()
            if not _spawn_one_task():
                break

        if total_tasks is not None:
            print(f"\n[*] Processing {total_tasks} endpoints in a bounded async pipeline...")
        else:
            print(f"\n[*] Processing endpoints in streaming async pipeline...")
        _render_progress(force=True)

        try:
            while in_flight or not targets_exhausted:
                await _wait_if_paused()
                if not in_flight:
                    if not _spawn_one_task():
                        break
                    continue

                fut = await result_q.get()
                in_flight.discard(fut)
                completed += 1

                try:
                    res = fut.result()
                    if isinstance(res, Exception):
                        pass
                    else:
                        ip, port, passed, latency, soft_domains, fail_reasons = res
                        endpoint = (ip, port)

                        if first_result_at is None:
                            first_result_at = time.monotonic() - scan_start

                        if passed or soft_domains:
                            sys.stdout.write('\r' + ' ' * 110 + '\r')
                            gemini_passed = _GEMINI_PROBE_HOST in passed

                            results_list.append({
                                "ip":         ip,
                                "port":       port,
                                "score":      len(passed),
                                "domains":    passed,
                                "latency_ms": latency
                            })

                            if soft_domains:
                                worker_eps_collected.add(endpoint)
                                try:
                                    for s_dom in soft_domains:
                                        bd = _cached_base_domain(s_dom)
                                        _ban_sink.append((bd, endpoint))
                                except Exception:
                                    pass

                            status_tag = "[NEW]" if endpoint not in cached_ep_set else "[CACHED]"
                            asn, as_name = _get_asn_for_ip(ip)
                            asn_display = f"({asn} - {as_name[:20]}...)" if asn else "(Unknown ASN)"

                            if passed:
                                score_str = f"{len(passed)}/{total_tested}"
                                passed_domains_str = ", ".join(passed)
                                print(
                                    f"{_c('green')}[+]{_c('reset')}   {format_ip_port(ip, port):<21} {status_tag:<8} "
                                    f"-> Passed {score_str} [{passed_domains_str}] in {latency}ms {asn_display}"
                                )

                                # --- AUTO-ROUTING INTEGRATION ---
                                endpoint_str = format_ip_port(ip, port)
                                for d in passed:
                                    clean_domain = d.strip('.').lower()
                                    base_domain = _cached_base_domain(clean_domain)
                                    google_family = _is_google_family_domain(clean_domain)
                                    is_banned = False
                                    for ban_key in (clean_domain, base_domain):
                                        banned_set = banned_routes.get(ban_key)
                                        if banned_set and (endpoint in banned_set or endpoint_str in banned_set):
                                            is_banned = True
                                            break
                                    if not is_banned:
                                        if clean_domain not in exact_routes:
                                            exact_routes[clean_domain] = {}
                                        exact_routes[clean_domain][port] = ip
                                        if base_domain not in exact_routes:
                                            exact_routes[base_domain] = {}
                                        exact_routes[base_domain][port] = ip
                                        if (not google_family) or gemini_passed:
                                            w_key = f".{base_domain}"
                                            if w_key not in wildcard_routes:
                                                wildcard_routes[w_key] = {}
                                            wildcard_routes[w_key][port] = ip
                                        routes_changed = True
                            else:
                                print(
                                    f"{_c('yellow')}[~][SOFT]{_c('reset')} {format_ip_port(ip, port):<21} {status_tag:<8} "
                                    f"-> Blocked for: {', '.join(soft_domains)} | {latency}ms {asn_display}"
                                )

                        elif deep_scan and fail_reasons:
                            sys.stdout.write('\r' + ' ' * 110 + '\r')
                            elapsed = time.monotonic() - scan_start if 'scan_start' in locals() else 0.0
                            print(f"{_c('red')}[-]{_c('reset')} {format_ip_port(ip, port)} Debug Diagnostics [+{elapsed:.1f}s]:")
                            for dom, reason in fail_reasons.items():
                                line_elapsed = time.monotonic() - scan_start if 'scan_start' in locals() else 0.0
                                print(f"    -> [+{line_elapsed:.1f}s] {dom}: {reason}")

                        # ---- Debug statistics (always collected) ----
                        if passed:
                            accepted_count += 1
                            accepted_latencies.append(float(latency))
                            if first_success_at is None:
                                first_success_at = time.monotonic() - scan_start
                        elif soft_domains:
                            soft_only_count += 1
                        else:
                            dead_count += 1

                        if deep_scan:
                            asn, as_name = _get_asn_for_ip(ip)
                            asn_key = f"{asn} - {as_name}" if asn else "Unknown ASN"
                            asn_stats = per_asn_stats.setdefault(
                                asn_key, {"tested": 0, "accepted": 0, "soft": 0, "dead": 0}
                            )
                            asn_stats["tested"] += 1
                            if passed:
                                asn_stats["accepted"] += 1
                            elif soft_domains:
                                asn_stats["soft"] += 1
                            else:
                                asn_stats["dead"] += 1

                            if fail_reasons:
                                reason_map = per_asn_failure_reasons.setdefault(asn_key, {})
                                for reason in fail_reasons.values():
                                    reason_str = str(reason)
                                    reason_map[reason_str] = reason_map.get(reason_str, 0) + 1

                        if fail_reasons:
                            for dom, reason in fail_reasons.items():
                                if dom in per_domain_stats:
                                    per_domain_stats[dom]["fail"] += 1
                                reason_str = str(reason)
                                failure_reason_counts[reason_str] = failure_reason_counts.get(reason_str, 0) + 1
                                reason_lower = reason_str.lower()
                                if "timeout" in reason_lower:
                                    timeout_failures += 1
                                if reason_lower.startswith("retry") or " retry " in reason_lower:
                                    retry_failures += 1
                                if _is_non_retryable_reject_reason(reason_str):
                                    non_retryable_rejects += 1

                        known_domains = set()
                        if passed:
                            for dom in passed:
                                if dom in per_domain_stats:
                                    per_domain_stats[dom]["pass"] += 1
                                    known_domains.add(dom)
                        if soft_domains:
                            for dom in soft_domains:
                                if dom in per_domain_stats:
                                    per_domain_stats[dom]["soft"] += 1
                                    known_domains.add(dom)
                        if fail_reasons:
                            for dom in fail_reasons.keys():
                                if dom in per_domain_stats:
                                    known_domains.add(dom)

                        for dom in debug_domains:
                            if dom not in known_domains:
                                per_domain_stats[dom]["unknown"] += 1

                except Exception:
                    pass

                _render_progress(force=(total_tasks is not None and completed == total_tasks))
                await _wait_if_paused()
                _spawn_one_task()

        except KeyboardInterrupt:
            interrupted = True
            sys.stdout.write('\r' + ' ' * 110 + '\r')
            print("\n[-] Scan interrupted by user. Finalizing debug summary...")

        finally:
            await _cancel_and_await(list(in_flight))
        print()
        scan_end = time.monotonic()

    finally:
        throttler_task.cancel()
        try:
            await asyncio.gather(throttler_task, return_exceptions=True)
        except KeyboardInterrupt:
            # Allow continuation to debug report even if user presses Ctrl+C again
            pass
        if pause_status_stop is not None:
            pause_status_stop.set()
        if pause_status_task is not None:
            try:
                await asyncio.gather(pause_status_task, return_exceptions=True)
            except Exception:
                pass
        if pause_controller is not None:
            try:
                pause_controller.resume("net")
            except Exception:
                pass
        if net_monitor_task is not None:
            try:
                await asyncio.gather(net_monitor_task, return_exceptions=True)
            except Exception:
                pass

    # Execute cleanup and report with full KeyboardInterrupt protection
    try:
        if worker_eps_collected:
            print(f"{_c('dim')}[*] Recorded {len(worker_eps_collected)} soft-accept Worker-capable endpoint(s).{_c('reset')}")
            worker_file_path = data_store.write_path("cloudflare_workers_ips.txt")
            try:
                existing = set()
                if os.path.exists(worker_file_path):
                    for line in storage.read_text_lines(worker_file_path, encoding="utf-8"):
                        parsed = parse_ip_port(line.strip())
                        if parsed:
                            existing.add(parsed)

                for ep in worker_eps_collected:
                    existing.add(ep)

                try:
                    sorted_ips = sorted(existing, key=lambda i: (ipaddress.ip_address(i[0]), i[1]))
                except Exception:
                    sorted_ips = sorted(existing, key=lambda i: (i[0], i[1]))

                storage.atomic_write_text(
                    worker_file_path,
                    "".join(f"{format_ip_port(ip, port)}\n" for ip, port in sorted_ips),
                    encoding="utf-8"
                )
            except Exception:
                pass

        if _ban_sink:
            seen_ban = set()
            for _ban_key, _ban_ep in _ban_sink:
                entry = (_ban_key, _ban_ep if isinstance(_ban_ep, tuple) else tuple(_ban_ep))
                if entry in seen_ban:
                    continue
                seen_ban.add(entry)
                try:
                    add_ban_entry(_ban_key, _ban_ep, persist=True)
                except Exception:
                    pass
            _ban_sink.clear()

        if routes_changed:
            print(f"{_c('dim')}[*] Saving newly discovered fast-routes to white_routes.txt...{_c('reset')}")
            from utils.route_service import ROUTE_SERVICE as _ROUTE_SERVICE
            await _ROUTE_SERVICE.async_rewrite_routes(STATE.exact_routes(), STATE.wildcard_routes())

        if deep_scan:
            total_end = time.monotonic()
            seed_time = scan_start - total_start
            scan_time = scan_end - scan_start if 'scan_end' in locals() else 0.0
            post_time = total_end - (scan_end if 'scan_end' in locals() else scan_start)
            total_time = total_end - total_start

            completed_display = str(completed)
            total_display = str(total_tasks) if total_tasks is not None else "?"
            endpoint_total = total_tasks if total_tasks is not None else "?"
            unique_ip_total = unique_ips if unique_ips is not None else "?"

            avg_latency = sum(accepted_latencies) / len(accepted_latencies) if accepted_latencies else 0.0
            p50 = _percentile(accepted_latencies, 50)
            p90 = _percentile(accepted_latencies, 90)
            p95 = _percentile(accepted_latencies, 95)
            p99 = _percentile(accepted_latencies, 99)

            throttle_timeout_rate = throttler._window.timeout_rate()
            throttle_median_latency = throttler._window.median_latency_ms()
            throttle_samples = throttler._window.sample_count()
            throttle_gw = throttler._baseline_gw_rtt if throttler._baseline_gw_rtt is not None else 0.0
            throttle_last_action = throttler._last_action

            print(
                "[Debug Report] "
                f"Duration: total={_fmt_duration_hms(total_time)}, seed={_fmt_duration_short(seed_time)}, "
                f"scan={_fmt_duration_hms(scan_time)}, post={_fmt_duration_short(post_time)} "
                f"First result at: {_fmt_duration_short(first_result_at or 0.0)} "
                f"First success at: {_fmt_duration_short(first_success_at or 0.0)} "
                f"Targets: endpoints={endpoint_total}, unique_ips={unique_ip_total}, domains={len(debug_domains)}, cached_eps={len(cached_ep_set)} "
                f"Results: accepted={accepted_count}, soft_only={soft_only_count}, dead={dead_count}, completed={completed_display}/{total_display} "
                f"Latency(ms) accepted: avg={avg_latency:.1f}, p50={p50:.1f}, p90={p90:.1f}, p95={p95:.1f}, p99={p99:.1f} "
                f"Failures: timeouts={timeout_failures}, retries={retry_failures}, non_retryable_rejects={non_retryable_rejects} "
                f"Interrupted: {'yes' if interrupted else 'no'} "
                f"Throttle: initial={throttler._initial}, final={throttler.semaphore.limit}, "
                f"gw_baseline_ms={throttle_gw:.1f}, window_samples={throttle_samples}, "
                f"timeout_rate={throttle_timeout_rate:.3f}, median_latency_ms={throttle_median_latency:.1f}, "
                f"last_action={throttle_last_action} "
                f"DeadIPCull: dead_ips={_dead_ip_tracker.dead_count()}, threshold={_dead_ip_tracker.threshold} "
                "Per-domain results:"
            )

            for dom in debug_domains:
                stats = per_domain_stats.get(dom, {"pass": 0, "soft": 0, "fail": 0, "unknown": 0})
                total_dom = stats["pass"] + stats["soft"] + stats["fail"] + stats["unknown"]
                if total_dom <= 0:
                    total_dom = 1
                pass_rate = (stats["pass"] / total_dom) * 100.0
                soft_rate = (stats["soft"] / total_dom) * 100.0
                fail_rate = (stats["fail"] / total_dom) * 100.0
                print(
                    f"[{dom}](http://{dom}): pass={stats['pass']}, soft={stats['soft']}, "
                    f"fail={stats['fail']}, unknown={stats['unknown']} | rates: "
                    f"pass={pass_rate:.1f}%, soft={soft_rate:.1f}%, fail={fail_rate:.1f}%"
                )

            if failure_reason_counts:
                print("Top failure reasons:")
                for reason, count in sorted(
                    failure_reason_counts.items(),
                    key=lambda item: (-item[1], item[0]),
                ):
                    print(f"{count}x {reason}")

            zero_asn_rows = []
            for asn_key, stats in per_asn_stats.items():
                if stats.get("tested", 0) <= 0:
                    continue
                if stats.get("accepted", 0) == 0:
                    zero_asn_rows.append((asn_key, stats))

            if zero_asn_rows:
                print("ASNs with zero accepted endpoints:")
                for asn_key, stats in sorted(
                    zero_asn_rows,
                    key=lambda item: (-item[1].get("tested", 0), item[0]),
                ):
                    reason_map = per_asn_failure_reasons.get(asn_key, {})
                    top_reasons = ", ".join(
                        f"{count}x {reason}"
                        for reason, count in sorted(
                            reason_map.items(),
                            key=lambda item: (-item[1], item[0]),
                        )[:3]
                    )
                    if not top_reasons:
                        top_reasons = "n/a"
                    print(
                        f"{asn_key}: tested={stats.get('tested', 0)}, "
                        f"soft={stats.get('soft', 0)}, dead={stats.get('dead', 0)} | "
                        f"top_failures: {top_reasons}"
                    )
    except KeyboardInterrupt:
        # If Ctrl+C during cleanup, still ensure we tried to print debug info
        pass

# ==========================================
# === END OF FILE ===
# ==========================================
