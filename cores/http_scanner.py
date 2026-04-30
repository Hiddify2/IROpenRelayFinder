"""
HTTP-Only Proxy Scanner — 3-Wave asyncio pipeline.

Strictly isolated from the IROpenRelayFinder routing engine: results are saved to
data/http_proxies.txt (export) and data/http_cache.txt (permanent cross-run
cache). Neither file is read by route_manager.load_ip_pool() — those load
scan_*.json + white_ips_cache.txt only — so verified HTTP proxies are
harvest-only and never enter the routing pool.

Pipeline (per-candidate task model with one asyncio.Semaphore per wave so a
slow Wave 3 verifier cannot bottleneck Wave 1's TCP fan-out):

  Wave 1  TCP Ping              cap 2000   2s    asyncio.open_connection
  Wave 2  Proxy Awareness       cap  500   4s    raw absolute-URI GET, expect 200
  Wave 3  Content Fingerprint     cap  100   8s    GET http://example.com/,
                                                 require 200 + body contains
                                                 "Example Domain" — proves the
                                                 proxy actually forwarded the
                                                 request; admin panels return
                                                 their own HTML, never that.
"""

import asyncio
import os
import random
import shutil
import socket
import sys
import time
from datetime import datetime

import utils.config as config
import utils.data_store as data_store
import utils.storage as storage
import utils.asn_engine as asn_engine
import utils.helpers as helpers
from utils.helpers import parse_ip_port, format_ip_port
from cores.ui_layout import (
    color_text, print_section, print_hint, print_ok, print_warn, print_err,
    draw_header,
)
import cores.ui_prompts as ui_prompts

# ─── Defaults ──────────────────────────────────────────────────────────────
DEFAULT_HTTP_PORTS = [80, 8080, 3128, 8000, 8888, 8118, 8081, 8123]
EXTENDED_HTTP_PORTS = [
    80, 443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083, 8123,
    8443, 8888, 8889, 3128, 3129, 8118, 8119, 9000, 9001, 9090, 9091,
    9999, 1080, 1081, 1082, 1083, 1085, 9050, 9051, 10808
]

W1_CONCURRENCY = 2000
W2_CONCURRENCY = 500
W3_CONCURRENCY = 100

W1_TIMEOUT = 2.0
W2_TIMEOUT = 4.0
W3_TIMEOUT = 8.0

# Isolated cache files. Both are siloed from the routing engine.
HTTP_PROXIES_FILE = "http_proxies.txt"
HTTP_CACHE_FILE = "http_cache.txt"

# Wave 2 — sent verbatim. We accept HTTP/1.0 200 or HTTP/1.1 200 in the head.
_W2_REQUEST = (
    b"GET http://example.com/ HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"Connection: close\r\n\r\n"
)
_W2_OK_PREFIXES = (b"HTTP/1.1 200", b"HTTP/1.0 200")

# Wave 3 — content fingerprint.
# We re-issue the example.com GET but read the full body and verify it
# contains example.com's known page signature.  Admin panels, web apps,
# and "200 to anything" servers serve their own HTML — they will never
# contain "Example Domain", which is unique to example.com (maintained by
# IANA since 2002, extraordinarily stable).  No TLS or CONNECT required,
# so HTTP-only proxies are not penalised.
_W3_REQUEST = (
    b"GET http://example.com/ HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Accept: text/html\r\n"
    b"Accept-Encoding: identity\r\n"
    b"Connection: close\r\n\r\n"
)
_W3_STATUS_OK = (b"HTTP/1.1 200", b"HTTP/1.0 200")
_W3_SIGNATURE = b"Example Domain"


# ─── Isolated cache manager ────────────────────────────────────────────────
def load_http_cache():
    """Load the permanent HTTP-proxy cache as a set of (ip, port) tuples."""
    cache = set()
    for line in storage.read_text_lines(data_store.write_path(HTTP_CACHE_FILE), encoding="utf-8"):
        parsed = parse_ip_port(line.strip())
        if parsed:
            cache.add(parsed)
    return cache


def save_to_http_cache(new_proxies):
    """Append verified HTTP proxies to the permanent cache, dedup'd."""
    cache = load_http_cache()
    before = len(cache)
    for item in new_proxies:
        parsed = parse_ip_port(item)
        if parsed:
            cache.add(parsed)
    if len(cache) <= before:
        return 0
    sorted_cache = sorted(cache, key=lambda ep: (ep[0], int(ep[1])))
    body = "".join(f"{format_ip_port(ip, port)}\n" for ip, port in sorted_cache)
    storage.atomic_write_text(data_store.write_path(HTTP_CACHE_FILE), body, encoding="utf-8")
    return len(cache) - before


def _save_export(proxies):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    body = f"# HTTP-Only Scanner — {ts}\n" + "".join(f"{p}\n" for p in sorted(proxies))
    data_store.write_text(HTTP_PROXIES_FILE, body, encoding="utf-8")
    print_ok(f"Exported {len(proxies)} proxy(ies) to data/{HTTP_PROXIES_FILE}")


# ─── Common helpers ────────────────────────────────────────────────────────
def _safe_close(writer):
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass


def _tune_socket(writer):
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def _expand_targets(raw_lines):
    ips = []
    for line in raw_lines:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        for item in asn_engine.expand_target(s, silent=True):
            ip = str(item).split(":")[0].strip()
            if ip:
                ips.append(ip)
    return list(dict.fromkeys(ips))


# ─── Wave 1: TCP Ping ──────────────────────────────────────────────────────
async def _wave1_tcp(ip, port):
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=W1_TIMEOUT
        )
        return True
    except Exception:
        return False
    finally:
        _safe_close(writer)


# ─── Wave 2: Proxy Awareness ───────────────────────────────────────────────
async def _wave2_proxy_aware(ip, port):
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=W2_TIMEOUT
        )
        _tune_socket(writer)
        writer.write(_W2_REQUEST)
        await asyncio.wait_for(writer.drain(), timeout=W2_TIMEOUT)
        head = await asyncio.wait_for(reader.read(128), timeout=W2_TIMEOUT)
        if not head:
            return False
        return any(head.startswith(p) for p in _W2_OK_PREFIXES)
    except Exception:
        return False
    finally:
        _safe_close(writer)


# ─── Wave 3: CONNECT + TLS Handshake ───────────────────────────────────────
async def _wave3_echo(ip, port):
    """
    Content-fingerprint verification: the proxy must forward the request to
    example.com and return its actual page body.  Servers that blindly return
    200 to any request serve their own HTML — they will never contain
    "Example Domain", which is unique to example.com (IANA, stable since 2002).
    No TLS or CONNECT required, so HTTP-only proxies are not penalised.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=W3_TIMEOUT
        )
        _tune_socket(writer)
        writer.write(_W3_REQUEST)
        await asyncio.wait_for(writer.drain(), timeout=W3_TIMEOUT)

        loop = asyncio.get_event_loop()
        deadline = loop.time() + W3_TIMEOUT
        buf = bytearray()
        while len(buf) < 8192:
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            if _W3_SIGNATURE in buf:
                break

        if not buf:
            return False
        if not any(buf.startswith(p) for p in _W3_STATUS_OK):
            return False
        return _W3_SIGNATURE in buf
    except Exception:
        return False
    finally:
        _safe_close(writer)


# ─── Pipeline driver ───────────────────────────────────────────────────────
def _draw_status(state, total):
    """Render a single live status line covering all three waves."""
    completed = state["w1_done"]
    pct = (completed / total * 100) if total else 100.0
    filled = int(30 * completed / total) if total else 30
    bar = "█" * filled + "─" * (30 - filled)
    sys.stdout.write(
        f"\r [{bar}] {pct:5.1f}% "
        f"W1 {state['w1_pass']}/{state['w1_done']} "
        f"W2 {state['w2_pass']}/{state['w2_done']} "
        f"W3 {state['w3_pass']}/{state['w3_done']}  "
        f"found={len(state['working'])}"
    )
    sys.stdout.flush()


async def _run_pipeline(
    endpoints,
    cache_set,
    w1_cap: int = W1_CONCURRENCY,
    w2_cap: int = W2_CONCURRENCY,
    w3_cap: int = W3_CONCURRENCY,
):
    """
    Per-candidate task model with one Semaphore per wave.

    Wave semaphores throttle active I/O; a separate task-object cap prevents
    spawning all N coroutines into memory at once (important for large ranges
    like /15 subnets with 500 K+ candidates).  At most `_task_cap` Task
    objects live simultaneously; the rest are queued as plain list items.
    """
    total = len(endpoints)
    if total == 0:
        return []

    sem1 = asyncio.Semaphore(w1_cap)
    sem2 = asyncio.Semaphore(w2_cap)
    sem3 = asyncio.Semaphore(w3_cap)

    state = {
        "w1_done": 0, "w1_pass": 0,
        "w2_done": 0, "w2_pass": 0,
        "w3_done": 0, "w3_pass": 0,
        "working": [],
    }
    tick_every = max(1, total // 400)

    # Cap live task objects: wave semaphores already throttle I/O, this just
    # prevents allocating 500 K coroutine + Task wrapper objects up front.
    _task_cap = max(w1_cap * 4, 8192)

    async def process(ep):
        ip, port = ep
        try:
            async with sem1:
                ok = await _wave1_tcp(ip, port)
            state["w1_done"] += 1
            if not ok:
                return
            state["w1_pass"] += 1

            async with sem2:
                ok = await _wave2_proxy_aware(ip, port)
            state["w2_done"] += 1
            if not ok:
                return
            state["w2_pass"] += 1

            async with sem3:
                ok = await _wave3_echo(ip, port)
            state["w3_done"] += 1
            if not ok:
                return
            state["w3_pass"] += 1

            proxy = f"{ip}:{port}"
            state["working"].append(proxy)
            is_cached = (ip, port) in cache_set or (ip, str(port)) in cache_set
            tag = color_text("[Cached]", "dim") if is_cached else color_text("[New]", "ok")
            sys.stdout.write("\r" + " " * 100 + "\r")
            print(f" {color_text('[+]', 'ok')} HTTP: {proxy} {tag}")
        finally:
            if state["w1_done"] % tick_every == 0 or state["w1_done"] == total:
                _draw_status(state, total)

    pending: set = set()
    try:
        for ep in endpoints:
            # Back-pressure: wait for at least one slot to free up before
            # spawning the next task, keeping live task count bounded.
            while len(pending) >= _task_cap:
                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            pending.add(asyncio.create_task(process(ep)))
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
    except KeyboardInterrupt:
        for t in pending:
            if not t.done():
                t.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        raise
    finally:
        _draw_status(state, total)
        print()
    return state["working"]


# ─── Preflight (masscan/nmap) ──────────────────────────────────────────────
def _run_preflight(method, ips, ports):
    """Run masscan/nmap with HTTP ports; restore TARGET_PORTS afterwards."""
    saved = list(config.TARGET_PORTS)
    config.set_target_ports(ports)
    try:
        if method == "masscan":
            from cores.scanner import run_masscan_preflight
            return list(run_masscan_preflight(ips, use_cached=False))
        else:
            from cores.scanner import run_nmap_preflight
            return list(run_nmap_preflight(ips, use_cached=False))
    finally:
        config.set_target_ports(saved)


async def _gather_candidates(method, ips, http_ports):
    if method == "asyncio":
        return [(ip, port) for ip in ips for port in http_ports]

    print_hint(f"Phase 1: {method.capitalize()} port discovery on {len(ips)} IP(s)...")
    print_warn(
        f"Note: {method} may miss 10-30% of open ports under high packet rates. "
        "Use Asyncio mode for complete coverage at the cost of speed."
    )
    found = await asyncio.to_thread(_run_preflight, method, ips, http_ports)
    print()
    print_ok(f"{method.capitalize()} found {len(found)} open endpoint(s).")
    return list(set(found))


# ─── Interactive entry ─────────────────────────────────────────────────────
async def run():
    draw_header()
    sep = color_text("══════════════════════════════════════════════════════════", "dim")
    print(sep)
    print(color_text("   HTTP-ONLY PROXY SCANNER  (3-Wave Pipeline)", "title"))
    print(sep)
    print(f" {color_text('[!]', 'warn')} Results saved to data/{HTTP_PROXIES_FILE} only — NOT loaded into routing.")
    print()

    # ── Source ──────────────────────────────────────────────────────────────
    src = ui_prompts.menu_choice(
        "SCAN SOURCE",
        [
            ("1", "Load IPs/CIDRs/ASNs from text file", None),
            ("2", "Paste IPs/CIDRs/ASNs manually", None),
            ("3", "Use Permanent HTTP proxy cache", None),
            ("4", "Select from IranASN database", None),
            ("0", "Back", None),
        ],
        default="1",
        remember_key="http_scan.source",
    )

    raw_lines = []

    if src == "1":
        fp = input("File path: ").strip()
        if not os.path.exists(fp):
            print_err("File not found.")
            input("Press Enter to return...")
            return
        with open(fp, "r") as f:
            raw_lines = [l.strip() for l in f if l.strip()]

    elif src == "2":
        raw_lines = ui_prompts.read_multiline("Paste targets (empty line to finish):")

    elif src == "3":
        cached = load_http_cache()
        if not cached:
            print_err("HTTP proxy cache is empty.")
            input("Press Enter to return...")
            return
        raw_lines = list(dict.fromkeys(ip for ip, _ in cached))
        print_hint(f"Loaded {len(raw_lines)} IPs from HTTP cache.")

    elif src == "4":
        import cores.ui_asn as ui_asn
        subnets = ui_asn.menu_search_asn()
        if not subnets:
            input("Press Enter to return...")
            return
        raw_lines = list(subnets)

    else:
        return

    print_hint("Expanding targets...")
    ips = _expand_targets(raw_lines)
    if not ips:
        print_err("No valid IPs resolved.")
        input("Press Enter to return...")
        return

    ips, dropped = asn_engine.filter_to_iranian(ips)
    if dropped:
        print_warn(f"{dropped} non-Iranian IP(s) were dropped (not found in IranASN database).")
    if not ips:
        print_err("No Iranian IPs remain after filtering.")
        input("Press Enter to return...")
        return
    print_ok(f"{len(ips)} Iranian IP(s) queued.")

    # ── Ports ───────────────────────────────────────────────────────────────
    print()
    default_str = ", ".join(str(p) for p in DEFAULT_HTTP_PORTS)
    extended_str = ", ".join(str(p) for p in EXTENDED_HTTP_PORTS)
    port_key = ui_prompts.menu_choice(
        "TARGET PORTS",
        [
            ("1", "Default HTTP ports", default_str),
            ("2", "Extended ports", extended_str[:50] + "..."),
            ("3", "Custom ports", None),
        ],
        default="1",
        prompt="Port mode",
        remember_key="http_scan.port_mode",
    )

    if port_key == "2":
        http_ports = list(EXTENDED_HTTP_PORTS)
    elif port_key == "3":
        raw_ports = input("Ports (comma or space separated): ").strip()
        http_ports = [int(p) for p in raw_ports.replace(",", " ").split() if p.strip().isdigit()]
        if not http_ports:
            print_warn("Invalid input, using default ports.")
            http_ports = list(DEFAULT_HTTP_PORTS)
    else:
        http_ports = list(DEFAULT_HTTP_PORTS)

    # ── Method ──────────────────────────────────────────────────────────────
    print()
    has_masscan = shutil.which("masscan") is not None
    has_nmap = shutil.which("nmap") is not None

    method_map = {"1": "asyncio"}
    total_eps = len(ips) * len(http_ports)
    rate_disp = config.TUNED_MASSCAN_RATE or 5000
    method_options = [("1", "Asyncio direct", f"{total_eps} probes ({len(ips)} IPs x {len(http_ports)} ports), no extra tools")]
    opt = 2
    if has_masscan:
        method_map[str(opt)] = "masscan"
        method_options.append((str(opt), "Masscan preflight", f"{rate_disp} pps, then 3-wave verify"))
        opt += 1
    if has_nmap:
        method_map[str(opt)] = "nmap"
        method_options.append((str(opt), "Nmap preflight", "Reliable port scan, then 3-wave verify"))

    saved_method = str(ui_prompts.get_pref("http_scan.method", "asyncio")).strip().lower()
    method_default = next((k for k, v in method_map.items() if v == saved_method), "1")
    method_key = ui_prompts.menu_choice(
        "SCAN METHOD",
        method_options,
        default=method_default,
        prompt="Method",
        remember_key="http_scan.method_key",
    )
    method = method_map.get(method_key, "asyncio")
    ui_prompts.set_pref("http_scan.method", method)

    # ── Asyncio concurrency (only relevant for asyncio mode) ─────────────────
    w1_cap, w2_cap, w3_cap = W1_CONCURRENCY, W2_CONCURRENCY, W3_CONCURRENCY
    if method == "asyncio":
        print()
        conc = ui_prompts.menu_choice(
            "CONCURRENCY PROFILE",
            [
                ("1", "Light", "W1=500 / W2=150 / W3=40"),
                ("2", "Normal", "W1=2000 / W2=500 / W3=100"),
                ("3", "Aggressive", "W1=4000 / W2=1000 / W3=200"),
                ("4", "Custom", "Enter values manually"),
            ],
            default="2",
            prompt="Profile",
            remember_key="http_scan.profile",
        )
        if conc == "1":
            w1_cap, w2_cap, w3_cap = 500, 150, 40
        elif conc == "3":
            w1_cap, w2_cap, w3_cap = 4000, 1000, 200
        elif conc == "4":
            w1_cap = ui_prompts.prompt_int(
                "  W1 TCP-ping concurrency",
                W1_CONCURRENCY,
                min_value=1,
                remember_key="http_scan.custom_w1",
            )
            w2_cap = ui_prompts.prompt_int(
                "  W2 proxy-aware concurrency",
                W2_CONCURRENCY,
                min_value=1,
                remember_key="http_scan.custom_w2",
            )
            w3_cap = ui_prompts.prompt_int(
                "  W3 fingerprint concurrency",
                W3_CONCURRENCY,
                min_value=1,
                remember_key="http_scan.custom_w3",
            )

    # ── Run ─────────────────────────────────────────────────────────────────
    helpers.clear_screen()
    draw_header()
    print(color_text("   HTTP-ONLY SCANNER — RUNNING", "title"))
    print(f" {color_text('Limits', 'dim')}: W1={w1_cap} ({W1_TIMEOUT}s) | "
          f"W2={w2_cap} ({W2_TIMEOUT}s) | W3={w3_cap} ({W3_TIMEOUT}s)")
    print()

    working = []
    try:
        candidates = await _gather_candidates(method, ips, http_ports)
        if not candidates:
            print_warn("No candidate endpoints to verify.")
            input("\nPress Enter to return...")
            return

        random.shuffle(candidates)
        print()
        print_hint(f"Phase 2: 3-wave verification on {len(candidates)} candidate(s)...")
        print()
        cache_set = load_http_cache()
        working = await _run_pipeline(candidates, cache_set, w1_cap, w2_cap, w3_cap)

    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted.")

    # ── Results ─────────────────────────────────────────────────────────────
    print()
    print(sep)
    print(color_text("   SCAN COMPLETE", "title"))
    print(sep)

    if working:
        print_ok(f"Found {len(working)} working HTTP proxy(ies)!")
        _save_export(working)
        added = save_to_http_cache(working)
        if added:
            print_ok(f"Added {added} new proxy(ies) to permanent HTTP cache.")
        print_hint("These proxies are NOT loaded into the routing pool — export only.")
    else:
        print_warn("No working HTTP proxies found in the scanned range.")

    input("\nPress Enter to return to main menu...")


if __name__ == "__main__":
    asyncio.run(run())
