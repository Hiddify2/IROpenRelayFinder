import os
import sys
import time
import asyncio
import subprocess
import re
import ssl
import threading
import ipaddress
import math
import random
import shutil
from functools import lru_cache

# --- State and Route Service imports ---
from utils.runtime_state import STATE

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
_EXTRA_PROBE_DOMAINS = ("meet.turns.goog", "gemini.google.com")
_PER_IP_PROBE_CONCURRENCY = 4

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
    if _sudo_keepalive_started: return
    if sys.platform == 'win32' or os.geteuid() == 0: return
    
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
        if not rate.isdigit(): rate = rate_def

        retries = input("[?] Enter packet retries [Default 2]: ").strip()
        if not retries.isdigit(): retries = "2"

        wait = input("[?] Enter end-of-scan wait time [Default 10]: ").strip()
        if not wait.isdigit(): wait = "10"

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
        while not results_stop.is_set():
            try:
                eps = _parse_masscan_output(output_file)
            except Exception:
                eps = set()
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
                with print_lock:
                    sys.stdout.write('\r' + ' ' * 140 + '\r')
                    print()
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

async def execute_masscan_silent(ips, rate, retries, wait, duration=None):
    uid = os.getpid()
    target_file = paths.data_path("tmp", f"masscan_targets_tune_{uid}.txt")
    output_file = paths.data_path("tmp", f"masscan_results_tune_{uid}.txt")
    bare_ips = _extract_bare_ips(ips)
    storage.atomic_write_text(target_file, "".join(f"{ip}\n" for ip in bare_ips), encoding="utf-8")
    
    port_arg = ",".join(str(p) for p in config.TARGET_PORTS)
    cmd = ["masscan", f"-p{port_arg}", "-iL", target_file, "-oL", output_file, "--rate", str(rate), "--retries", str(retries), "--wait", str(wait)]
    if sys.platform != 'win32' and os.geteuid() != 0: 
        cmd.insert(0, "sudo")

    process = None
    open_eps = set()
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        if duration is None:
            await process.wait()
        else:
            try:
                await asyncio.wait_for(process.wait(), timeout=max(0.01, float(duration)))
            except asyncio.TimeoutError:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=3.0)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                    try:
                        await process.wait()
                    except Exception:
                        pass

        if process.returncode not in (None, 0):
            # Return partial results if any were written before exit.
            pass
        open_eps = _parse_masscan_output(output_file)
    except Exception:
        open_eps = _parse_masscan_output(output_file)
    finally:
        cleanup_files(target_file, output_file)

    return list(open_eps)

# ==========================================
# NMAP WRAPPERS
# ==========================================
def _parse_nmap_output(output_file):
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

def run_nmap_preflight(ips, use_cached=False):
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
        if not retries.isdigit(): retries = "2"

        min_rate, max_rate = "", ""
        if timing != "-T2":
            min_def = str(config.TUNED_NMAP_MIN_RATE) if config.TUNED_NMAP_MIN_RATE else "100"
            max_def = str(config.TUNED_NMAP_MAX_RATE) if config.TUNED_NMAP_MAX_RATE else "500"
            min_rate = input(f"\n[?] Minimum packet rate [Default {min_def}]: ").strip()
            if not min_rate.isdigit(): min_rate = min_def
            max_rate = input(f"\n[?] Maximum packet rate [Default {max_def}]: ").strip()
            if not max_rate.isdigit(): max_rate = max_def

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
        while not nmap_results_stop.is_set():
            try:
                eps = _parse_nmap_output(output_file)
            except Exception:
                eps = set()
            new_eps = eps - nmap_seen
            if new_eps:
                nmap_seen.update(new_eps)
                nmap_found_ref[0] = len(nmap_seen)
            nmap_results_stop.wait(timeout=1.0)

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
    cmd = ["nmap", "-p", port_arg, scan_type, "-Pn", "-n", "-iL", target_file, "-oG", output_file, timing, "--max-retries", str(retries), "--host-timeout", str(host_timeout)]
    if timing != "-T2": 
        cmd.extend(["--min-rate", str(min_rate), "--max-rate", str(max_rate)])

    process = None
    open_eps = set()
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )

        if duration is None:
            await process.wait()
        else:
            try:
                await asyncio.wait_for(process.wait(), timeout=max(0.01, float(duration)))
            except asyncio.TimeoutError:
                try:
                    process.terminate()
                    await asyncio.wait_for(process.wait(), timeout=3.0)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                    try:
                        await process.wait()
                    except Exception:
                        pass

        open_eps = _parse_nmap_output(output_file)
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


def _iter_scan_targets(targets):
    """
    Yield normalized (ip, port) pairs without building a second full copy of
    the scan list in memory.
    """
    for target in targets:
        if isinstance(target, tuple) and len(target) >= 2:
            yield str(target[0]), int(target[1])
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


def _count_scan_targets(targets):
    """
    Count the normalized endpoint fan-out without storing the expanded list.
    """
    total = 0
    for target in targets:
        if isinstance(target, tuple) and len(target) >= 2:
            total += 1
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
    unique = set()
    for target in targets:
        if isinstance(target, tuple) and len(target) >= 1:
            ip = str(target[0]).strip()
        else:
            parsed = parse_ip_port(target)
            ip = parsed[0].strip() if parsed else ""
        if ip:
            unique.add(ip)
    return len(unique)


async def run_tcp_scan(targets, concurrency, desc="Scanning"):
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
    tasks: set[asyncio.Task] = set()

    def _spawn_one_task() -> bool:
        try:
            target = next(target_iter)
        except StopIteration:
            return False
        task = asyncio.create_task(_check_tcp_endpoint(target, sem))
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


def _hard_reject_tag(resp: bytes) -> str | None:
    if not resp:
        return None
    resp_lower = resp.lower()
    if any(marker in resp_lower for marker in _EDGE_IP_RESTRICTED_MARKERS):
        return "HARD_REJECT:EDGE_IP_RESTRICTED"
    return None


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
    return any(pattern in resp_lower for pattern in _NON_OVERRIDABLE_HARD_REJECT)


def _is_non_retryable_reject_reason(reason: str) -> bool:
    if not reason:
        return False
    return any(tag in reason for tag in _NON_RETRYABLE_REJECT_TAGS)


def _is_transient_failure_reason(reason: str) -> bool:
    if not reason:
        return True
    if _is_non_retryable_reject_reason(reason):
        return False
    reason_lower = reason.lower()
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


def _ban_endpoint_for_domain_variants(domain: str, endpoint: tuple[str, int]) -> None:
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

    # Keep a compact set while preserving order.
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

    for pattern in _HARD_REJECT:
        if pattern in resp_lower:
            return 'reject'

    for pattern in _SOFT_ACCEPT:
        if pattern in resp_lower:
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

    has_cdn_sig = any(sig in headers for sig in _CDN_SIGS)
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

# ==========================================
# TLS VERIFICATION & DPI EVASION ENGINE
# ==========================================
async def _dpi_tunnel(local_reader, local_writer, target_ip, target_port):
    """
    A micro-proxy that intercepts the OpenSSL ClientHello and fragments it 
    at the TCP layer to blind the DPI firewall.
    """
    try:
        # Give the raw connection 3 seconds to establish
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, target_port), timeout=3.0
        )
    except Exception:
        await _close_writer(local_writer)
        return

    async def forward_local_to_remote():
        try:
            first_packet = True
            while True:
                data = await local_reader.read(8192)
                if not data: break
                
                if first_packet and config.DPI_FRAGMENTATION:
                    # Fragment the ClientHello into tiny 10-byte chunks
                    # The DPI firewall cannot reassemble these fast enough and lets them pass
                    chunk_size = 64
                    for i in range(0, len(data), chunk_size):
                        remote_writer.write(data[i:i+chunk_size])
                        await remote_writer.drain()
                        await asyncio.sleep(0.001)  # 1ms is enough to force a separate segment
                    first_packet = False
                else:
                    remote_writer.write(data)
                    await remote_writer.drain()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            await _close_writer(remote_writer)

    async def forward_remote_to_local():
        try:
            while True:
                data = await remote_reader.read(8192)
                if not data: break
                local_writer.write(data)
                await local_writer.drain()
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            await _close_writer(local_writer)

    tunnel_tasks = [
        asyncio.create_task(forward_local_to_remote()),
        asyncio.create_task(forward_remote_to_local())
    ]
    try:
        await asyncio.gather(*tunnel_tasks)
    except asyncio.CancelledError:
        await _cancel_and_await(tunnel_tasks)
        raise
    finally:
        await _cancel_and_await(tunnel_tasks)

async def _probe_domain(ip: str, domain: str, port: int, timeout: float, use_fragmentation=None):
    start_time = time.perf_counter()
    server = None
    writer = None
    tunnel_tasks = set()
    fragmentation_enabled = config.DPI_FRAGMENTATION if use_fragmentation is None else use_fragmentation

    try:
        if fragmentation_enabled:
            async def handle_client(reader, local_writer):
                task = asyncio.current_task()
                if task is not None:
                    tunnel_tasks.add(task)
                try:
                    await _dpi_tunnel(reader, local_writer, ip, port)
                finally:
                    if task is not None:
                        tunnel_tasks.discard(task)

            server = await asyncio.start_server(handle_client, '127.0.0.1', 0)
            target_host = '127.0.0.1'
            target_port = server.sockets[0].getsockname()[1]
        else:
            target_host = ip
            target_port = port

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port, ssl=config.PROBE_SSL_CONTEXT, server_hostname=domain),
            timeout=timeout
        )

        probe = _PROBE_HEAD + domain.encode("ascii", "ignore") + _PROBE_TAIL
        writer.write(probe)
        await writer.drain()

        # Increased slice sizes to improve probability of finding domain tokens in body,
        # reducing false negatives for APIs/Websites where the domain name is far down.
        # Dropped Range header to avoid 206/416 responses which confuse heuristics.
        _HEADER_BODY_SLICE = 4096
        _HARD_CAP = 8192
        configured_read_timeout = float(getattr(config, 'PROBE_READ_TIMEOUT', 3.5))
        read_timeout = max(2.5, min(7.0, configured_read_timeout))
        resp_buf = bytearray()
        header_end = -1
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=read_timeout)
                if not chunk:
                    break
                resp_buf.extend(chunk)
                if header_end == -1:
                    idx = resp_buf.find(b'\r\n\r\n')
                    if idx != -1:
                        header_end = idx + 4
                        if len(resp_buf) >= header_end + _HEADER_BODY_SLICE:
                            break
                else:
                    if len(resp_buf) >= header_end + _HEADER_BODY_SLICE:
                        break
                if len(resp_buf) >= _HARD_CAP:
                    break
        except asyncio.TimeoutError:
            pass
        resp = bytes(resp_buf)

        resp_lower = resp.lower() if resp else b""
        verdict = classify_response(resp, domain)
        lat = (time.perf_counter() - start_time) * 1000 if verdict in ('accept', 'soft_accept') else 0.0

        reason = "Accepted"
        if verdict == 'reject':
            tag = _hard_reject_tag(resp)
            if tag == "HARD_REJECT:EDGE_IP_RESTRICTED":
                reason = "[HARD_REJECT:EDGE_IP_RESTRICTED] Cloudflare Error 1034 / Edge IP Restricted"
            else:
                status_code = _extract_status_code(resp_lower)
                if (
                    status_code in _TLS_HTTP_FALLBACK_ACCEPT_STATUS
                    and not _has_non_overridable_hard_reject(resp_lower)
                ):
                    verdict = 'accept'
                    lat = (time.perf_counter() - start_time) * 1000
                    reason = "Accepted (TLS+HTTP fallback)"
                else:
                    status_line = resp.split(b'\r\n')[0].decode('utf-8', 'ignore') if resp else "Empty Response"
                    reason = f"Rejected Server Response: {status_line}"
        elif verdict == 'dead':
            reason = "Dead/Empty HTTP Response"
        elif verdict == 'soft_accept':
            reason = "Soft Accept / Cloudflare Block"

        return verdict, lat, reason
    except asyncio.CancelledError:
        raise
    except asyncio.TimeoutError:
        return 'dead', 0.0, 'SSL Handshake Timeout (Blackholed)'
    except ssl.SSLError as e:
        return 'dead', 0.0, f'SSL Error ({getattr(e, "reason", str(e))})'
    except Exception as e:
        op = 'Read' if writer is not None else 'Connection'
        return 'dead', 0.0, f'{op} Error ({type(e).__name__})'
    finally:
        if writer is not None:
            await _close_writer(writer)

        if server:
            server.close()
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=1.0)
            except Exception:
                pass

        if tunnel_tasks:
            await _cancel_and_await(list(tunnel_tasks))

async def _check_ip_tls_logic(ip, port, domains, probe_domains, timeout, probe_sem, skip_tcp=False, deep_scan=False, throttler=None):
    passed_domains = []
    soft_domains = []
    latencies = []
    fail_reasons = {}
    endpoint = (ip, port)

    def _record_outcome(ok: bool, timed_out: bool, latency_ms: float) -> None:
        if throttler is not None:
            try:
                throttler.record_outcome(ok, timed_out, latency_ms)
            except Exception:
                pass

    if not skip_tcp:
        tcp_started = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=timeout
            )
            await _close_writer(writer)
            _record_outcome(True, False, (time.monotonic() - tcp_started) * 1000)
        except Exception as e:
            timed_out = isinstance(e, asyncio.TimeoutError)
            _record_outcome(False, timed_out, (time.monotonic() - tcp_started) * 1000)
            return ip, port, [], 9999, [], {d: f"TCP Port {port} Closed/Timeout ({type(e).__name__})" for d in domains}

    # 1. Fire initial probes with bounded per-task concurrency
    async def probe_and_record(domain):
        verdict, lat, reason = await _probe_domain(ip, domain, port, timeout)
        _record_outcome(verdict == 'accept', verdict == 'dead' and ('Timeout' in reason or 'timeout' in reason.lower()), lat)
        return domain, verdict, lat, reason

    async def probe_and_record_bounded(domain):
        async with probe_sem:
            return await probe_and_record(domain)

    results = await asyncio.gather(*(probe_and_record_bounded(dom) for dom in probe_domains), return_exceptions=True)
    
    failed_domains = []

    for res in results:
        if isinstance(res, Exception):
            continue # Should be caught by _probe_domain, but safety first
            
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
                _ban_endpoint_for_domain_variants(domain, endpoint)
                continue
            if not _is_transient_failure_reason(reason):
                fail_reasons[domain] = reason
                continue
            failed_domains.append(domain)
            fail_reasons[domain] = reason

    # 2. Fire retry loop for failed domains CONCURRENTLY
    if failed_domains:
        async def retry_probe(domain):
            async with probe_sem:  # Enforce the task-level speed limit on retries to prevent retry burst
                last_reason = fail_reasons[domain]
                retry_attempts = max(1, int(getattr(config, 'SCAN_RETRY_ATTEMPTS', 2)))
                for attempt in range(retry_attempts):
                    deep_timeout = timeout + 3.0 + (attempt * 2.0)
                    try:
                        if config.DPI_FRAGMENTATION and attempt == 1:
                            v, l, r = await _probe_domain(ip, domain, port, deep_timeout, use_fragmentation=False)
                        else:
                            v, l, r = await _probe_domain(ip, domain, port, deep_timeout)
                        _record_outcome(v == 'accept', v == 'dead' and ('Timeout' in r or 'timeout' in r.lower()), l)
                        if v == 'accept':
                            return domain, 'accept', l, r
                        elif v == 'soft_accept':
                            return domain, 'soft_accept', l, r
                        elif _is_non_retryable_reject_reason(r):
                            return domain, 'reject', 0.0, r
                        else:
                            last_reason = f"Retry {attempt+1} Failed: {r}"
                    except Exception as e:
                        last_reason = f"Retry Error: {type(e).__name__}"
                    if attempt < retry_attempts - 1:
                        await asyncio.sleep(0.2)
                return domain, 'reject', 0.0, last_reason

        retry_results = await asyncio.gather(*(retry_probe(dom) for dom in failed_domains))
        
        for domain, verdict, lat, reason in retry_results:
            if verdict == 'accept':
                passed_domains.append(domain)
                latencies.append(lat)
                fail_reasons.pop(domain, None) # Remove from failures
            elif verdict == 'soft_accept':
                soft_domains.append(domain)
                latencies.append(lat)
                fail_reasons[domain] = reason
            else:
                fail_reasons[domain] = reason
                if _is_non_retryable_reject_reason(reason):
                    _ban_endpoint_for_domain_variants(domain, endpoint)

    # If it failed literally every domain, drop it.
    if not passed_domains and not soft_domains:
        return ip, port, [], 9999, [], fail_reasons

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
    Accepts a single endpoint plus a shared semaphore and returns the
    same tuple shape produced by check_ip_tls_single.
    """
    if isinstance(endpoint, tuple) and len(endpoint) >= 2:
        ip, port = str(endpoint[0]), int(endpoint[1])
    else:
        parsed = parse_ip_port(endpoint)
        if not parsed:
            return None, 0, [], 9999, [], {}
        ip, port = parsed

    probe_domains = list(dict.fromkeys(list(domains or []) + list(_EXTRA_PROBE_DOMAINS)))
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
    ip, port, domains, probe_domains, semaphore,
    timeout=config.SCAN_TIMEOUT, skip_tcp=False, deep_scan=False, throttler=None
):
    """
    Processes a single (ip, port) pair under the global task semaphore.

    Concurrency contract
    --------------------
    The caller sets semaphore = Semaphore(MAX_CONCURRENT_SCANS).
    Inside this task we open at most _PER_IP_PROBE_CONCURRENCY sockets simultaneously,
    so total live sockets scale with the configured task budget.
    """
    async with semaphore:
        probe_sem = asyncio.Semaphore(min(_PER_IP_PROBE_CONCURRENCY, max(1, len(probe_domains))))

        # Hard timeout: allow enough time for all probe waves + retry waves.
        # Retries hold probe_sem across both attempts, so each retry worker can spend:
        # (timeout+3.0) + 0.2 + (timeout+5.0) = (2*timeout + 8.2) seconds.
        waves = max(1, math.ceil(len(probe_domains) / _PER_IP_PROBE_CONCURRENCY))
        per_retry_worker_budget = (timeout + 3.0) + 0.2 + (timeout + 5.0)
        adaptive_hard_timeout = max(
            config.HARD_SCAN_TIMEOUT,
            (timeout * waves) + (per_retry_worker_budget * waves) + 6.0
        )

        try:
            return await asyncio.wait_for(
                _check_ip_tls_logic(ip, port, domains, probe_domains, timeout, probe_sem, skip_tcp, deep_scan, throttler),
                timeout=adaptive_hard_timeout
            )
        except asyncio.TimeoutError:
            return ip, port, [], 9999, [], {d: f"Hard Scan Timeout (>{adaptive_hard_timeout:.1f}s)" for d in probe_domains}
        except Exception as e:
            return ip, port, [], 9999, [], {d: f"Error ({type(e).__name__})" for d in probe_domains}


async def run_mass_scan(targets, domains, results_list, skip_tcp=False, deep_scan=False):
    if not targets:
        print("\n[*] No IPs provided for async scan.")
        return

    if not isinstance(targets, list):
        targets = list(targets)

    # Count the fully expanded endpoint set without materializing it.
    total_tasks = _count_scan_targets(targets)
    if total_tasks <= 0:
        print("\n[*] No valid endpoints provided for async scan.")
        return

    unique_ips = _count_unique_scan_ips(targets)

    # ── 3. Concurrency math ───────────────────────────────────────────────────
    #
    # MAX_CONCURRENT_SCANS is the user-facing socket budget. Each endpoint task
    # can fan out into several domain probes, so endpoint concurrency must be
    # derived from that budget instead of multiplying it.
    socket_budget = max(1, int(config.MAX_CONCURRENT_SCANS))
    per_task_probe_cap = max(1, min(_PER_IP_PROBE_CONCURRENCY, socket_budget, len(domains) + len(_EXTRA_PROBE_DOMAINS)))
    effective_task_slots = max(1, socket_budget // per_task_probe_cap)
    gateway = _find_default_gateway()
    throttler = AdaptiveThrottler(
        initial=effective_task_slots,
        gateway=gateway,
        max_limit=effective_task_slots,
        verbose=False,
    )
    semaphore = throttler.semaphore
    throttler_task = asyncio.create_task(throttler.run())
    routes_changed = False

    print(f"\n[*] Initializing Async Engine for {total_tasks} IP:Port pairs across {unique_ips} unique IPs...")
    print(
        f"[*] Concurrency: {effective_task_slots} endpoint tasks × ≤{per_task_probe_cap} probes/task "
        f"(socket budget: {socket_budget})"
    )

    cached_eps      = load_white_cache()
    cached_ep_set   = cached_eps
    worker_eps_collected: set[tuple[str, int]] = set()
    asn_cache: dict[str, tuple] = {}
    exact_routes = STATE.exact_routes()
    wildcard_routes = STATE.wildcard_routes()
    banned_routes = STATE.banned_routes()

    probe_domains   = list(dict.fromkeys(domains + list(_EXTRA_PROBE_DOMAINS)))
    total_tested    = len(probe_domains)

    # ── 4. Process in chunks (memory-efficient; each chunk progresses together) ─
    completed      = 0
    scan_start     = time.monotonic()
    _PROGRESS_MIN_INTERVAL = 0.2
    _last_progress_draw = 0.0

    def _render_progress(force: bool = False):
        nonlocal _last_progress_draw
        now = time.monotonic()
        if not force and (now - _last_progress_draw) < _PROGRESS_MIN_INTERVAL:
            return
        elapsed  = max(0.01, now - scan_start)
        rate     = completed / elapsed
        eta_secs = (total_tasks - completed) / rate if rate > 0 else 0
        if eta_secs < 3600:
            eta_str = f"{int(eta_secs // 60)}m{int(eta_secs % 60):02d}s"
        else:
            eta_str = f"{eta_secs / 3600:.1f}h"

        bar_len = 25
        filled  = int(bar_len * completed / total_tasks)
        bar     = '█' * filled + '-' * (bar_len - filled)
        percent = (completed / total_tasks) * 100
        sys.stdout.write(
            f"\r[{bar}] {percent:.1f}% ({completed}/{total_tasks}) "
            f"{rate:.1f}/s ETA:{eta_str}   "
        )
        sys.stdout.flush()
        _last_progress_draw = now
    task_buffer_limit = max(64, min(2048, effective_task_slots * 6))
    target_iter = iter(_iter_scan_targets(targets))

    try:
      tasks: set[asyncio.Task] = set()

      def _spawn_one_task() -> bool:
          try:
              ip, port = next(target_iter)
          except StopIteration:
              return False
          task = asyncio.create_task(
              check_ip_tls_single(
                  ip, port, domains, probe_domains, semaphore,
                  skip_tcp=skip_tcp, deep_scan=deep_scan, throttler=throttler
              )
          )
          tasks.add(task)
          return True

      for _ in range(task_buffer_limit):
          if not _spawn_one_task():
              break

      print(f"\n[*] Processing {total_tasks} endpoints in a bounded async pipeline...")
      _render_progress(force=True)

      try:
          while tasks:
              done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

              for future in done:
                  completed += 1
                  try:
                      res = await future
                      if isinstance(res, Exception):
                          continue

                      ip, port, passed, latency, soft_domains, fail_reasons = res
                      endpoint = (ip, port)

                      if passed or soft_domains:
                          sys.stdout.write('\r' + ' ' * 110 + '\r')

                          # Always append so the UI can integrate it into the IP_POOL
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
                                      add_ban_entry(bd, endpoint, persist=True)
                              except Exception:
                                  pass

                          status_tag = "[NEW]" if endpoint not in cached_ep_set else "[CACHED]"
                          if ip in asn_cache:
                              asn, as_name = asn_cache[ip]
                          else:
                              asn, as_name, _ = get_asn_info(ip)
                              asn_cache[ip] = (asn, as_name)
                          asn_display = f"({asn} - {as_name[:20]}...)" if asn else "(Unknown ASN)"


                          if passed:
                              score_str        = f"{len(passed)}/{total_tested}"
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
                                  # 1. Check if this endpoint is banned for this domain
                                  is_banned = False
                                  for ban_key in (clean_domain, base_domain):
                                      banned_set = banned_routes.get(ban_key)
                                      # Check memory tuple and disk string formats
                                      if banned_set and (endpoint in banned_set or endpoint_str in banned_set):
                                          is_banned = True
                                          break
                                  if not is_banned:
                                      # Map exact domain
                                      if clean_domain not in exact_routes: exact_routes[clean_domain] = {}
                                      exact_routes[clean_domain][port] = ip
                                      # Map base domain
                                      if base_domain not in exact_routes: exact_routes[base_domain] = {}
                                      exact_routes[base_domain][port] = ip
                                      # Map wildcard
                                      w_key = f".{base_domain}"
                                      if w_key not in wildcard_routes: wildcard_routes[w_key] = {}
                                      wildcard_routes[w_key][port] = ip
                                      routes_changed = True
                              # --------------------------------
                          else:
                              print(
                                  f"{_c('yellow')}[~][SOFT]{_c('reset')} {format_ip_port(ip, port):<21} {status_tag:<8} "
                                  f"-> Blocked for: {', '.join(soft_domains)} | {latency}ms {asn_display}"
                              )

                      elif deep_scan and fail_reasons:
                          sys.stdout.write('\r' + ' ' * 110 + '\r')
                          print(f"{_c('red')}[-]{_c('reset')} {format_ip_port(ip, port)} Debug Diagnostics:")
                          for dom, reason in fail_reasons.items():
                              print(f"    -> {dom}: {reason}")

                  except Exception:
                      pass

                  _render_progress(force=(completed == total_tasks))

              while len(tasks) < task_buffer_limit:
                  if not _spawn_one_task():
                      break

      finally:
          await _cancel_and_await(list(tasks))
      print()

    finally:
        throttler_task.cancel()
        await asyncio.gather(throttler_task, return_exceptions=True)

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

    # Add this at the very end of run_mass_scan!
    if routes_changed:
        print(f"{_c('dim')}[*] Saving newly discovered fast-routes to white_routes.txt...{_c('reset')}")
        from utils.route_service import ROUTE_SERVICE as _ROUTE_SERVICE
        await _ROUTE_SERVICE.async_rewrite_routes(STATE.exact_routes(), STATE.wildcard_routes())

# ==========================================
# === END OF FILE ===
# ==========================================
