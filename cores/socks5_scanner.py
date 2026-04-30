import asyncio
import os
import random
import shutil
import socket
import struct
import sys
import time
from datetime import datetime

import utils.config as config
import utils.data_store as data_store
import utils.asn_engine as asn_engine
import utils.helpers as helpers
from cores.ui_layout import (
    color_text, print_section, print_hint, print_ok, print_warn, print_err,
    draw_header,
)
import cores.ui_prompts as ui_prompts

DEFAULT_SOCKS5_PORTS = [1080, 1081, 1082, 1083, 1085, 3128, 8080, 8118, 9050, 9051, 10808]
EXTENDED_SOCKS5_PORTS = [
    1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
    80, 443, 8000, 8001, 8002, 8003, 8008, 8080, 8081, 8082, 8083,
    8118, 8119, 8443, 8888, 8889, 3128, 3129, 9000, 9001, 9050,
    9051, 9090, 9091, 9999, 10808
]

# End-to-end verification target. We CONNECT to 1.1.1.1:80 through the proxy
# and require a real "HTTP/" reply — this is what proves the proxy routes
# both directions, not just our uplink bytes.
_VERIFY_ADDR = bytes([1, 1, 1, 1])
_VERIFY_PORT = 80
_VERIFY_REQUEST = (
    b"HEAD / HTTP/1.0\r\n"
    b"Host: 1.1.1.1\r\n"
    b"User-Agent: Mozilla/5.0\r\n"
    b"Connection: close\r\n\r\n"
)
_VERIFY_RESP_PREFIX = b"HTTP/"


def _expand_targets(raw_lines):
    """Expand raw input (IPs, CIDRs, ASNs) into a deduplicated list of IP strings."""
    ips = []
    for line in raw_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        for item in asn_engine.expand_target(line, silent=True):
            ip = str(item).split(':')[0].strip()
            if ip:
                ips.append(ip)
    return list(dict.fromkeys(ips))


def _tune_socket(writer):
    """TCP_NODELAY: flush the 3-byte greeting immediately instead of waiting on Nagle."""
    try:
        sock = writer.get_extra_info('socket')
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass


def _safe_close(writer):
    """Close without awaiting wait_closed — that can stall a worker for the
    full close timeout on a half-broken peer. The transport finishes cleanup
    in the event loop background and the OS reclaims the fd."""
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass


async def _try_socks5(ip, port, timeout):
    """
    RFC 1928 SOCKS5 no-auth probe with full end-to-end verification.

    Greeting + CONNECT 1.1.1.1:80 + HTTP HEAD round-trip. We require an
    "HTTP/" prefix in the response. This catches "uplink-only" proxies
    that accept the SOCKS5 CONNECT but silently drop our payload or
    never relay the upstream response — they would otherwise pass a
    REP=0-only check.
    """
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        _tune_socket(writer)

        # ─── Greeting: VER=5 NMETHODS=1 METHOD=NO_AUTH ─────────────────
        writer.write(b'\x05\x01\x00')
        await writer.drain()

        resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if resp[0] != 0x05 or resp[1] != 0x00:
            return False

        # ─── CONNECT: VER=5 CMD=CONNECT RSV=0 ATYP=IPv4 + addr + port ──
        writer.write(b'\x05\x01\x00\x01' + _VERIFY_ADDR + struct.pack('>H', _VERIFY_PORT))
        await writer.drain()

        # IPv4 reply is exactly 10 bytes: VER REP RSV ATYP BND.ADDR(4) BND.PORT(2)
        connect_resp = await asyncio.wait_for(reader.readexactly(10), timeout=timeout)
        if connect_resp[0] != 0x05 or connect_resp[1] != 0x00:
            return False

        # ─── End-to-end data round-trip ────────────────────────────────
        # REP=0 alone doesn't prove the tunnel works. Send a real HTTP
        # HEAD and require a real HTTP reply. Catches:
        #   - proxies that drop uplink bytes after CONNECT
        #   - proxies that never relay the upstream response (no downlink)
        #   - honeypots/non-proxies that happened to mimic the handshake
        writer.write(_VERIFY_REQUEST)
        await writer.drain()

        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        buf = b""
        need = len(_VERIFY_RESP_PREFIX)
        while len(buf) < need:
            remaining = deadline - loop.time()
            if remaining <= 0:
                return False
            try:
                chunk = await asyncio.wait_for(reader.read(64), timeout=remaining)
            except asyncio.TimeoutError:
                return False
            if not chunk:
                return False
            buf += chunk
        return buf.startswith(_VERIFY_RESP_PREFIX)

    except Exception:
        return False
    finally:
        _safe_close(writer)


def _draw_progress(completed, total, extra_label, extra_value):
    pct = completed / total * 100
    filled = int(30 * completed / total)
    bar = '█' * filled + '─' * (30 - filled)
    sys.stdout.write(
        f"\r [{bar}] {pct:.1f}% ({completed}/{total}) {extra_label}={extra_value}"
    )
    sys.stdout.flush()


async def _run_worker_pool(items, concurrency, body):
    """
    Generic worker-pool driver. N workers pull from a queue and call
    `body(item)`. Avoids creating one Task per item — important for
    /16-scale sweeps where that would mean millions of Task objects.
    """
    total = len(items)
    if total == 0:
        return
    queue = asyncio.Queue()
    for it in items:
        queue.put_nowait(it)

    async def worker():
        while True:
            try:
                item = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                await body(item)
            except Exception:
                pass

    n = max(1, min(concurrency, total))
    workers = [asyncio.create_task(worker()) for _ in range(n)]
    try:
        await asyncio.gather(*workers)
    except KeyboardInterrupt:
        for t in workers:
            if not t.done():
                t.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        raise


async def _probe_socks5(endpoints, concurrency, timeout, label="SOCKS5", existing_cache=None):
    """Worker-pool SOCKS5 probe. Returns a list of "ip:port" strings."""
    total = len(endpoints)
    if total == 0:
        return []

    cache_set = existing_cache or set()
    working = []
    state = {"completed": 0, "last_print": 0}
    tick = max(1, total // 400)

    async def body(ep):
        ip, port = ep
        ok = await _try_socks5(ip, port, timeout)
        if ok:
            proxy = f"{ip}:{port}"
            working.append(proxy)
            is_cached = (ip, port) in cache_set or (ip, str(port)) in cache_set
            tag = color_text("[cached]", "dim") if is_cached else color_text("[new]", "ok")
            sys.stdout.write('\r' + ' ' * 80 + '\r')
            print(f" {color_text('[+]', 'ok')} {label}: {proxy} {tag}")
        state["completed"] += 1
        if state["completed"] - state["last_print"] >= tick or state["completed"] == total:
            state["last_print"] = state["completed"]
            _draw_progress(state["completed"], total, "found", len(working))

    await _run_worker_pool(endpoints, concurrency, body)
    print()
    return working


def _run_preflight(method, ips, ports):
    """
    Run masscan or nmap port-scan preflight with the given SOCKS5 ports.
    This is a blocking function — always call it via asyncio.to_thread() so
    the internal asyncio.run() calls inside the preflight work correctly.
    Temporarily overrides config.TARGET_PORTS and restores it afterward.
    """
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


async def _gather_candidates(method, ips, socks5_ports):
    """Phase 1: get the candidate (ip, port) list to hand to SOCKS5 verification."""
    if method == "asyncio":
        return [(ip, port) for ip in ips for port in socks5_ports]

    print_hint(f"Phase 1: {method.capitalize()} port discovery on {len(ips)} IP(s)...")
    print_warn(
        f"Note: {method} may miss 10-30% of open ports under high packet rates. "
        "Use Asyncio mode for complete coverage at the cost of speed."
    )
    found = await asyncio.to_thread(_run_preflight, method, ips, socks5_ports)
    print()
    print_ok(f"{method.capitalize()} found {len(found)} open endpoint(s).")
    return list(set(found))


def _save_results(proxies):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = f"# SOCKS5 Scanner — {ts}\n" + "".join(f"{p}\n" for p in sorted(proxies))
    data_store.write_text("socks5_proxies.txt", content, encoding="utf-8")
    print_ok(f"Saved {len(proxies)} proxy(ies) to data/socks5_proxies.txt")


async def run():
    draw_header()
    sep = color_text("══════════════════════════════════════════════════════════", "dim")
    print(sep)
    print(color_text("   SOCKS5 PROXY SCANNER", "title"))
    print(sep)
    print(f" {color_text('[!]', 'warn')} Results are saved to file only — NOT added to routing.")
    print()

    # ── 1. Target Source ─────────────────────────────────────────────────────
    src = ui_prompts.menu_choice(
        "SCAN SOURCE",
        [
            ("1", "Load IPs/CIDRs/ASNs from text file", None),
            ("2", "Paste IPs/CIDRs/ASNs manually", None),
            ("3", "Use Permanent SOCKS5 cache", None),
            ("4", "Select from IranASN database", None),
            ("0", "Back", None),
        ],
        default="1",
        remember_key="socks5_scan.source",
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
        cached = helpers.load_socks5_cache()
        if not cached:
            print_err("SOCKS5 cache is empty.")
            input("Press Enter to return...")
            return
        raw_lines = list(dict.fromkeys(ip for ip, _ in cached))
        print_hint(f"Loaded {len(raw_lines)} IPs from SOCKS5 cache.")

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

    # ── 2. Ports ─────────────────────────────────────────────────────────────
    print()
    default_str = ", ".join(str(p) for p in DEFAULT_SOCKS5_PORTS)
    extended_str = ", ".join(str(p) for p in EXTENDED_SOCKS5_PORTS)
    port_key = ui_prompts.menu_choice(
        "TARGET PORTS",
        [
            ("1", "Default SOCKS5 ports", default_str),
            ("2", "Extended ports", extended_str[:50] + "..."),
            ("3", "Custom ports", None),
        ],
        default="1",
        prompt="Port mode",
        remember_key="socks5_scan.port_mode",
    )

    if port_key == "2":
        socks5_ports = list(EXTENDED_SOCKS5_PORTS)
    elif port_key == "3":
        raw_ports = input("Ports (comma or space separated): ").strip()
        socks5_ports = [int(p) for p in raw_ports.replace(',', ' ').split() if p.strip().isdigit()]
        if not socks5_ports:
            print_warn("Invalid input, using default ports.")
            socks5_ports = list(DEFAULT_SOCKS5_PORTS)
    else:
        socks5_ports = list(DEFAULT_SOCKS5_PORTS)

    # ── 3. Scan Method ────────────────────────────────────────────────────────
    print()
    has_masscan = shutil.which("masscan") is not None
    has_nmap    = shutil.which("nmap")    is not None

    total_eps = len(ips) * len(socks5_ports)
    rate_disp = config.TUNED_MASSCAN_RATE or 5000
    method_map = {"1": "asyncio"}
    method_options = [("1", "Asyncio direct", f"{total_eps} probes ({len(ips)} IPs x {len(socks5_ports)} ports), no extra tools")]
    opt = 2
    if has_masscan:
        method_map[str(opt)] = "masscan"
        method_options.append((str(opt), "Masscan preflight", f"{rate_disp} pps, asyncio recovery sweep, then SOCKS5 verify"))
        opt += 1
    if has_nmap:
        method_map[str(opt)] = "nmap"
        method_options.append((str(opt), "Nmap preflight", "Reliable port scan, asyncio recovery sweep, then SOCKS5 verify"))

    saved_method = str(ui_prompts.get_pref("socks5_scan.method", "asyncio")).strip().lower()
    method_default = next((k for k, v in method_map.items() if v == saved_method), "1")
    method_key = ui_prompts.menu_choice(
        "SCAN METHOD",
        method_options,
        default=method_default,
        prompt="Method",
        remember_key="socks5_scan.method_key",
    )
    method = method_map.get(method_key, "asyncio")
    ui_prompts.set_pref("socks5_scan.method", method)

    # ── 4. Tuning ─────────────────────────────────────────────────────────────
    print()
    timeout = ui_prompts.prompt_float(
        "[?] Connection timeout in seconds",
        3.0,
        min_value=0.2,
        remember_key="socks5_scan.timeout",
    )

    concurrency = ui_prompts.prompt_int(
        "[?] Concurrency (parallel connections)",
        500,
        min_value=1,
        remember_key="socks5_scan.concurrency",
    )

    # ── 6. Run ────────────────────────────────────────────────────────────────
    helpers.clear_screen()
    draw_header()
    print(color_text("   SOCKS5 SCANNER — RUNNING", "title"))
    print()

    working = []

    try:
        candidates = await _gather_candidates(method, ips, socks5_ports)
        if not candidates:
            print_warn("No candidate endpoints to verify.")
            input("\nPress Enter to return...")
            return

        print()
        print_hint(f"Phase 2: SOCKS5 verification (Full: CONNECT + HTTP round-trip) on {len(candidates)} candidate(s)...")
        print()
        existing_cache = helpers.load_socks5_cache()
        working = await _probe_socks5(candidates, concurrency, timeout, existing_cache=existing_cache)

    except KeyboardInterrupt:
        print("\n\n[-] Scan interrupted.")

    # ── 6. Results ────────────────────────────────────────────────────────────
    print()
    print(sep)
    print(color_text("   SCAN COMPLETE", "title"))
    print(sep)

    if working:
        print_ok(f"Found {len(working)} working SOCKS5 proxy(ies)!")
        _save_results(working)
        added = helpers.save_to_socks5_cache(working)
        if added:
            print_ok(f"Added {added} new proxy(ies) to permanent SOCKS5 cache.")
    else:
        print_warn("No working SOCKS5 proxies found in the scanned range.")

    input("\nPress Enter to return to main menu...")


if __name__ == "__main__":
    asyncio.run(run())
