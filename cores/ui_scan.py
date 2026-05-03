import asyncio
import json
import os
import random
import select
import sys
import threading
import time
from datetime import datetime

import utils.asn_engine as asn_engine
from utils.app_service import APP_SERVICE
import utils.config as config
import utils.helpers as helpers
import utils.paths as paths
import utils.data_store as data_store
import utils.storage as storage
from utils.route_service import ROUTE_SERVICE
from utils.scan_service import SCAN_SERVICE

import cores.ui_asn as ui_asn
import cores.ui_layout as ui_layout


def prompt_target_ports():
    default_ports = ", ".join(str(p) for p in config.DEFAULT_TARGET_PORTS)
    last_ports = ", ".join(str(p) for p in config.LAST_TARGET_PORTS)
    ui_layout.print_section("TARGET PORTS")
    print(f" [1] Use default ports ({default_ports}) [Default]")
    print(" [2] Enter custom ports")
    print(f" [3] Use last used profile ({last_ports})")
    choice = input("\nChoice (press Enter for default, or enter ports directly): ").strip()
    
    if not choice or choice == "1":
        selected_ports = list(config.DEFAULT_TARGET_PORTS)
    elif choice == "2":
        raw_ports = input("Enter ports (comma or space separated, e.g. 443,2053,8443): ").strip()
        selected_ports = helpers.parse_port_list(raw_ports, fallback_ports=config.DEFAULT_TARGET_PORTS)
    elif choice == "3":
        selected_ports = list(config.LAST_TARGET_PORTS)
    else:
        # Direct port input (e.g., "443, 8443", "80 443 8080")
        selected_ports = helpers.parse_port_list(choice, fallback_ports=config.DEFAULT_TARGET_PORTS)
        if not selected_ports:
            selected_ports = list(config.DEFAULT_TARGET_PORTS)
    
    config.set_target_ports(selected_ports, persist=True, remember=True)
    return selected_ports


def _has_explicit_port(item):
    if isinstance(item, tuple):
        return len(item) >= 2
    raw = str(item).strip()
    if not raw:
        return False
    if ":" not in raw:
        return False
    _, port_part = raw.rsplit(":", 1)
    return port_part.isdigit()


def build_scan_endpoints(raw_items, base_ports, strip_explicit_ports=False):
    """
    Expands raw target items into concrete (ip, port) endpoints.

    If strip_explicit_ports is False:
      - ip:port inputs scan only that explicit port
      - flat IPs scan with the selected base_ports

    If strip_explicit_ports is True:
      - all inputs scan with the selected base_ports

    Returns (exact_endpoints, expanded_targets, preflight_ips, merged_port_list)
    """
    if not base_ports:
        base_ports = config.DEFAULT_TARGET_PORTS

    merged_ports = list(dict.fromkeys(base_ports))
    exact_endpoints = []
    expanded_targets = []
    preflight_ips = []
    seen_exact = set()
    seen_expanded = set()
    seen_preflight = set()

    for item in raw_items:
        parsed = helpers.parse_ip_port(item, default_port=base_ports[0] if base_ports else None)
        if not parsed:
            continue
        ip, parsed_port = parsed
        has_explicit_port = _has_explicit_port(item)

        if has_explicit_port and not strip_explicit_ports:
            endpoint = (ip, int(parsed_port))
            if endpoint not in seen_exact:
                seen_exact.add(endpoint)
                exact_endpoints.append(endpoint)
            if endpoint not in seen_expanded:
                seen_expanded.add(endpoint)
                expanded_targets.append(endpoint)
            continue

        if ip not in seen_preflight:
            seen_preflight.add(ip)
            preflight_ips.append(ip)

        for port in base_ports:
            endpoint = (ip, int(port))
            if endpoint in seen_expanded:
                continue
            seen_expanded.add(endpoint)
            expanded_targets.append(endpoint)

    return exact_endpoints, expanded_targets, preflight_ips, merged_ports


def _start_scan_pause_listener(pause_controller):
    stop_event = threading.Event()

    def _handle_cmd(cmd: str) -> None:
        if cmd in ("p", "pause"):
            pause_controller.pause("user")
            ui_layout.print_warn("Scan paused. Press 'r' to resume.")
        elif cmd in ("r", "resume"):
            pause_controller.resume("user")
            ui_layout.print_ok("\nScan resumed.")

    def _listen_line():
        while not stop_event.is_set():
            try:
                line = sys.stdin.readline()
            except Exception:
                time.sleep(0.1)
                continue
            if not line:
                time.sleep(0.1)
                continue
            _handle_cmd(line.strip().lower())

    def _listen_keypress():
        fd = sys.stdin.fileno()
        try:
            import termios
            import tty
        except Exception:
            _listen_line()
            return

        try:
            old_settings = termios.tcgetattr(fd)
        except Exception:
            _listen_line()
            return

        try:
            tty.setcbreak(fd)
            while not stop_event.is_set():
                try:
                    ready, _, _ = select.select([sys.stdin], [], [], 0.2)
                except Exception:
                    continue
                if not ready:
                    continue
                try:
                    ch = sys.stdin.read(1)
                except Exception:
                    continue
                if not ch:
                    continue
                _handle_cmd(ch.strip().lower())
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            except Exception:
                pass

    def _listen_windows():
        try:
            import msvcrt
        except Exception:
            _listen_line()
            return
        while not stop_event.is_set():
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                _handle_cmd(ch.strip().lower())
            else:
                time.sleep(0.1)

    def _listen():
        if sys.platform == "win32":
            _listen_windows()
        elif sys.stdin.isatty():
            _listen_keypress()
        else:
            _listen_line()

    threading.Thread(target=_listen, daemon=True).start()
    return stop_event


def menu_scan():
    ui_layout.draw_header(ui_mode="white")
    ui_layout.print_section("SCAN SOURCE")
    print(" [1] Load IPs/CIDRs/ASNs from text file")
    print(" [2] Paste IPs/CIDRs/ASNs manually")
    print(" [3] Use Permanent White IP cache")
    print(" [4] Mine IPs from Cloudflare CNAMEs")
    print(" [5] Select from IranASN database")
    print(" [0] Back")
    choice = input("\nChoice: ").strip()

    raw_targets = []
    if choice == "1":
        filepath = input("Enter path to file: ").strip()
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                for line in f:
                    if line.strip():
                        raw_targets.append(line.strip())
        else:
            input(ui_layout.color_text("[-] File not found. Press Enter to return...", "err"))
            return
    elif choice == "2":
        print("Paste your IPs/CIDRs/ASNs (Press Enter on an empty line to finish):")
        while True:
            line = input().strip()
            if not line:
                break
            raw_targets.append(line)
    elif choice == "3":
        cached_ips = helpers.load_white_cache()
        if not cached_ips:
            input(ui_layout.color_text("[-] White IPs Cache is empty. Press Enter to return...", "err"))
            return
        ui_layout.print_hint(f"Queued {len(cached_ips)} active cached endpoints.")
        raw_targets = list(cached_ips)
    elif choice == "4":
        import socket

        rounds_str = input("[?] DNS resolution rounds [Default 5]: ").strip()
        rounds = int(rounds_str) if rounds_str.isdigit() else 5
        delay_str = input("[?] Delay between rounds in seconds [Default 2]: ").strip()
        delay = int(delay_str) if delay_str.isdigit() else 2

        mined_ips = set()
        ui_layout.print_hint(f"Mining {len(config.CLOUDFLARE_CNAME_DOMAINS)} Cloudflare domains over {rounds} rounds...")
        for r in range(rounds):
            sys.stdout.write(f"\r[*] Round {r+1}/{rounds} - Discovered IPs so far: {len(mined_ips)}     ")
            sys.stdout.flush()
            random.shuffle(config.CLOUDFLARE_CNAME_DOMAINS)
            for domain in config.CLOUDFLARE_CNAME_DOMAINS:
                try:
                    _, _, ip_list = socket.gethostbyname_ex(domain)
                    mined_ips.update(ip_list)
                except Exception:
                    pass
            if r < rounds - 1:
                time.sleep(delay)

        print(f"\r{ui_layout.color_text('[*] Mining complete!', 'dim')} Discovered {len(mined_ips)} unique IPs.            \n")

        if not mined_ips:
            input(ui_layout.color_text("[-] No IPs discovered. Press Enter to return...", "err"))
            return
        raw_targets = list(mined_ips)
    elif choice == "5":
        subnets = ui_asn.menu_search_asn()
        if not subnets:
            input("Press Enter to return...")
            return
        raw_targets.extend(subnets)
    else:
        return

    raw_targets = list(dict.fromkeys(raw_targets))
    if choice != "4":
        ui_layout.print_hint("Expanding targets into concrete IP list...")

    expanded_items = []
    for t in raw_targets:
        if isinstance(t, tuple) and len(t) == 2:
            expanded_items.append(t)
        else:
            expanded_items.extend(asn_engine.expand_target(t))

    if not expanded_items:
        input(ui_layout.color_text("[-] No valid IPs to scan. Press Enter to return...", "err"))
        return

    selected_ports = prompt_target_ports()
    has_explicit_ports = any(_has_explicit_port(item) for item in expanded_items)
    strip_explicit_ports = False
    if has_explicit_ports:
        strip_choice = input("[?] Some targets include explicit ports. Strip them and scan only the selected target ports instead? (y/N): ").strip().lower()
        strip_explicit_ports = strip_choice == 'y'

    exact_endpoints, endpoints, preflight_ips, merged_ports = build_scan_endpoints(
        expanded_items,
        selected_ports,
        strip_explicit_ports=strip_explicit_ports,
    )
    config.set_target_ports(merged_ports, persist=True, remember=True)

    if not endpoints:
        input(ui_layout.color_text("[-] No endpoints derived from provided IPs. Press Enter to return...", "err"))
        return

    base_ips = list(dict.fromkeys(preflight_ips))
    if not base_ips:
        base_ips = list(dict.fromkeys(ip for ip, _ in endpoints))
    random.shuffle(base_ips)

    import shutil

    has_masscan = shutil.which("masscan") is not None
    has_nmap = shutil.which("nmap") is not None

    selected_tool = "normal"
    is_debug_mode = False
    options = {"1": "normal"}
    opt_num = 2
    if has_masscan:
        options[str(opt_num)] = "masscan"
        opt_num += 1
    if has_nmap:
        options[str(opt_num)] = "nmap"

    while True:
        ui_layout.draw_header(ui_mode="white")
        ui_layout.print_section("SCAN METHOD")
        ui_layout.print_hint(f"Target IPs queued: {len(base_ips)}")

        print("\n [1] Normal scan (Python asyncio)")
        print(f"     Accuracy-first, concurrency={config.MAX_CONCURRENT_SCANS}")

        if has_masscan:
            mass_option_num = [k for k, v in options.items() if v == "masscan"][0]
            mass_rate_disp = config.TUNED_MASSCAN_RATE if config.TUNED_MASSCAN_RATE else "5000"
            print(f" [{mass_option_num}] Masscan (ultra-fast, requires sudo, {mass_rate_disp} pps)")

        if has_nmap:
            nmap_option_num = [k for k, v in options.items() if v == "nmap"][0]
            nmap_rate_disp = f"{config.TUNED_NMAP_MIN_RATE}-{config.TUNED_NMAP_MAX_RATE}" if config.TUNED_NMAP_MIN_RATE else "100-500"
            print(f" [{nmap_option_num}] Nmap (adaptive, highly reliable, {nmap_rate_disp} pps)")

        debug_status = "ON" if is_debug_mode else "OFF"
        print(f" [d] Toggle Debug Mode (Current: {debug_status})")

        selected_method_label = "Normal"
        if selected_tool == "masscan":
            selected_method_label = "Masscan"
        elif selected_tool == "nmap":
            selected_method_label = "Nmap"

        print("\n" + ui_layout.color_text(" Selection", "nav"))
        print(f" Method: {selected_method_label} | Debug Mode: {debug_status}")
        print(" [s] Start scan with current settings")
        print(" [0] Back")

        method_choice = input("\nAction (press Enter to start, [d] toggle debug, [0] back): ").strip().lower()
        if not method_choice:
            # Empty input = start scan with current settings
            break
        if method_choice == "0":
            return
        if method_choice == "d":
            is_debug_mode = not is_debug_mode
            continue
        if method_choice == "s":
            break
        selected_tool = options.get(method_choice, selected_tool)

    # Asyncio concurrency — only asked for asyncio mode; masscan/nmap prompt
    # their own rate inside run_masscan_preflight / run_nmap_preflight.
    if selected_tool == "asyncio":
        ui_layout.print_section("CONCURRENCY")
        print(f" Current setting: {config.MAX_CONCURRENT_SCANS} concurrent connections")
        conc_s = input(f"[?] Concurrent connections for this scan [Default {config.MAX_CONCURRENT_SCANS}]: ").strip()
        if conc_s.isdigit() and int(conc_s) > 0:
            config.MAX_CONCURRENT_SCANS = int(conc_s)

    ui_layout.print_section("SCAN OPTIONS")
    is_cyclic = input("[?] Run cyclic continuous scan? (y/N): ").strip().lower() == 'y'

    preflighted_targets = [(ip, port) for ip in base_ips for port in config.TARGET_PORTS]
    all_successful_results = {}
    round_num = 1

    if is_cyclic:
        cyclic_filename = data_store.write_path("scan_cyclic_continuous.json")
        if os.path.exists(cyclic_filename):
            try:
                prev_data = storage.read_json(cyclic_filename, default=[])
                if isinstance(prev_data, list):
                    for r in prev_data:
                        port = int(r.get('port', config.primary_target_port()))
                        r['port'] = port
                        all_successful_results[(r.get('ip'), port)] = r
                ui_layout.print_ok(f"Smart resume: loaded {len(all_successful_results)} historical IPs.")
                time.sleep(2)
            except Exception:
                pass

    while True:
        ui_layout.draw_header(ui_mode="white")
        if is_cyclic:
            ui_layout.print_section(f"CYCLIC SCAN - ROUND {round_num}")

        current_ips = list(base_ips)
        random.shuffle(current_ips)
        skip_tcp = False

        if selected_tool in ["masscan", "nmap"]:
            if not is_cyclic or (round_num % 5 == 1):
                print(f"\n[*] Running Preflight Pruning (Round {round_num})...")
                if selected_tool == "masscan":
                    preflighted_targets = SCAN_SERVICE.run_masscan_preflight(current_ips, use_cached=(round_num > 1))
                elif selected_tool == "nmap":
                    preflighted_targets = SCAN_SERVICE.run_nmap_preflight(current_ips, use_cached=(round_num > 1))
                time.sleep(2)
            else:
                cached_round = ((round_num - 1) // 5) * 5 + 1
                print(f"\n[*] Using cached preflight results from Round {cached_round}...")

            current_targets = list(dict.fromkeys(exact_endpoints + list(preflighted_targets)))
            random.shuffle(current_targets)
            skip_tcp = True
        else:
            current_targets = list(endpoints)
            random.shuffle(current_targets)

        if not current_targets:
            if is_cyclic:
                print("[-] No IPs survived pre-flight. Skipping to next round in 5s...")
                try:
                    time.sleep(5)
                except KeyboardInterrupt:
                    print("\n\n[!] Scan INTERRUPTED by user. Exiting cyclic loop...")
                    break
                round_num += 1
                continue
            else:
                input(ui_layout.color_text("[-] No IPs survived pre-flight or scan cancelled. Press Enter to return...", "err"))
                return

        print(f"[*] Target IPs loaded for TLS Verification: {len(current_targets)}")
        print("[!] Press Ctrl+C at any time to STOP the scan and save current results.")
        ui_layout.print_hint("Press 'p' to pause, 'r' to resume while the scan runs.")
        print()

        successful_results = []
        interrupted = False
        pause_controller = SCAN_SERVICE.new_pause_controller()
        pause_stop = _start_scan_pause_listener(pause_controller)
        try:
            asyncio.run(
                SCAN_SERVICE.run_mass_scan(
                    current_targets,
                    config.DEFAULT_DOMAINS,
                    successful_results,
                    skip_tcp=skip_tcp,
                    deep_scan=is_debug_mode,
                    pause_controller=pause_controller,
                )
            )
        except KeyboardInterrupt:
            print("\n\n[!] Scan INTERRUPTED by user. Finalizing saved IPs...")
            interrupted = True
        finally:
            pause_stop.set()
            pause_controller.resume()

        for r in successful_results:
            port = int(r.get('port', config.primary_target_port()))
            r['port'] = port
            key = (r['ip'], port)
            if key not in all_successful_results or r['score'] > all_successful_results[key]['score']:
                all_successful_results[key] = r

        if all_successful_results:
            sorted_results = sorted(all_successful_results.values(), key=lambda x: (-x["score"], x["latency_ms"]))

            if is_cyclic:
                storage.atomic_write_json(cyclic_filename, sorted_results, indent=4)
                print(f"\n[✓] Aggregated and updated {len(sorted_results)} verified White IPs in {os.path.basename(cyclic_filename)}")

                try:
                    archive_dir = paths.archive_path()
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    round_file = os.path.join(archive_dir, f"round_{round_num}_{ts}.json")
                    storage.atomic_write_json(round_file, successful_results, indent=4)
                except Exception:
                    pass
            else:
                filename = paths.timestamped_scan_filename(prefix="scan")
                storage.atomic_write_json(filename, sorted_results, indent=4)
                print(f"\n[✓] Saved {len(sorted_results)} verified White IPs to {os.path.basename(filename)}")

                scan_files = paths.list_scan_files(include_cyclic=False)
                for old_file in scan_files[:-5]:
                    try:
                        os.remove(old_file)
                    except OSError:
                        pass

            pool_payload = {
                (r['ip'], int(r.get('port', config.primary_target_port()))): (r['domains'][0] if r.get('domains') else None)
                for r in sorted_results[:50]
            }
            pool_size = APP_SERVICE.set_ip_pool(pool_payload)
            print(f"[+] Loaded top {pool_size} endpoints into Dynamic Pool.")

            successful_eps = [(r['ip'], int(r.get('port', config.primary_target_port()))) for r in sorted_results]
            newly_cached = helpers.save_to_white_cache(successful_eps)
            if newly_cached > 0:
                print(f"[+] Added {newly_cached} new IPs to the permanent White IP cache.")
        else:
            print("\n[-] Scan round complete. No working IPs found.")

        if interrupted or not is_cyclic:
            break

        try:
            print(f"\n[*] Round {round_num} complete. Next round starting in 5 seconds... (Press Ctrl+C to abort)")
            time.sleep(5)
            round_num += 1
        except KeyboardInterrupt:
            print("\n\n[!] Scan INTERRUPTED by user. Exiting cyclic loop...")
            break

    input("\nPress Enter to return to main menu...")


def menu_instant_connect():
    ui_layout.draw_header(ui_mode="white")
    ui_layout.print_section("INSTANT CONNECT")
    print(" [1] Load IPs from text file")
    print(" [2] Paste IPs manually")
    print(" [0] Back")
    choice = input("\nChoice: ").strip()

    raw_items = []
    if choice == "1":
        filepath = input("Enter path to file: ").strip()
        if os.path.exists(filepath):
            with open(filepath, "r") as f:
                for line in f:
                    if line.strip():
                        raw_items.extend(asn_engine.expand_target(line.strip()))
        else:
            input(ui_layout.color_text("[-] File not found. Press Enter to return...", "err"))
            return
    elif choice == "2":
        print("Paste your IPs/CIDRs/ASNs (Press Enter on an empty line to finish):")
        while True:
            line = input().strip()
            if not line:
                break
            raw_items.extend(asn_engine.expand_target(line))
    else:
        return

    raw_items = list(dict.fromkeys(raw_items))
    if not raw_items:
        input(ui_layout.color_text("[-] No valid IPs parsed. Press Enter to return...", "err"))
        return

    exact_endpoints, endpoints, _, _ = build_scan_endpoints(
        raw_items,
        config.TARGET_PORTS,
        strip_explicit_ports=False,
    )
    if not endpoints:
        input(ui_layout.color_text("[-] No endpoints derived from provided IPs. Press Enter to return...", "err"))
        return

    random.shuffle(endpoints)
    ui_layout.print_hint(f"Verifying {len(endpoints)} endpoint(s) before loading Dynamic Pool...")

    successful_results = []
    interrupted = False
    pause_controller = SCAN_SERVICE.new_pause_controller()
    pause_stop = _start_scan_pause_listener(pause_controller)
    try:
        asyncio.run(
            SCAN_SERVICE.run_mass_scan(
                endpoints,
                config.DEFAULT_DOMAINS,
                successful_results,
                skip_tcp=False,
                deep_scan=False,
                pause_controller=pause_controller,
            )
        )
    except KeyboardInterrupt:
        print("\n\n[!] Instant-connect verification interrupted by user. Using collected results...")
        interrupted = True
    finally:
        pause_stop.set()
        pause_controller.resume()

    if not successful_results:
        input(ui_layout.color_text("[-] No usable IP:Port pairs found. Press Enter to return...", "err"))
        return

    best_by_endpoint = {}
    for result in successful_results:
        ip = result.get("ip")
        try:
            port = int(result.get("port", config.primary_target_port()))
        except Exception:
            port = config.primary_target_port()
        key = (ip, port)
        prev = best_by_endpoint.get(key)
        if prev is None or result.get("score", 0) > prev.get("score", 0):
            best_by_endpoint[key] = result

    usable_results = sorted(
        best_by_endpoint.values(),
        key=lambda x: (-x.get("score", 0), x.get("latency_ms", 9999))
    )

    pool_payload = {
        (
            r["ip"],
            int(r.get("port", config.primary_target_port()))
        ): (r.get("domains") or [None])[0]
        for r in usable_results[:150]
    }
    pool_size = APP_SERVICE.set_ip_pool(pool_payload)

    explicit_count = len(exact_endpoints)
    ui_layout.print_ok(f"Instant connect: loaded {pool_size} usable endpoints into Dynamic Pool.")
    if explicit_count:
        ui_layout.print_hint(f"Preserved {explicit_count} explicit IP:Port target(s) without port expansion.")
    if len(usable_results) > 150:
        ui_layout.print_warn("Usable list truncated to top 150 endpoints for stable racing performance.")
    if interrupted:
        ui_layout.print_warn("Verification was interrupted; pool reflects partial discovered results.")

    usable_eps = [(r["ip"], int(r.get("port", config.primary_target_port()))) for r in usable_results]
    newly_cached = helpers.save_to_white_cache(usable_eps)
    if newly_cached > 0:
        print(f"[+] Added {newly_cached} IPs to the permanent White IP cache.")
    input("Press Enter to return to main menu...")


def menu_manage_pool():
    count = ROUTE_SERVICE.load_ip_pool()
    ui_layout.draw_header(ui_mode="white")
    ui_layout.print_section("RELOAD DYNAMIC POOL")
    if count > 0:
        ui_layout.print_ok(f"Loaded {count} fastest IPs into Dynamic Pool.")
        print()
        latest_file = paths.latest_scan_file(include_cyclic=False)
        if latest_file:
            try:
                results = storage.read_json(latest_file, default=[])
                if not isinstance(results, list):
                    results = []
                for r in results[:50]:
                    ip = r['ip']
                    port = int(r.get('port', config.primary_target_port()))
                    domains_list = r.get('domains') or []
                    domains = ", ".join(domains_list) if domains_list else "-"
                    asn, as_name, _ = asn_engine.get_asn_info(ip)
                    clean_as_name = as_name[:25] + "..." if len(as_name) > 25 else as_name
                    asn_display = f"({asn} - {clean_as_name})" if asn else "(Unknown ASN)"
                    print(f"  -> {helpers.format_ip_port(ip, port):<21} | {asn_display:<40} | Domains: [{domains}]")
            except Exception:
                pass
    else:
        ui_layout.print_err("No scan files found. Run a scan first.")
    input("\nPress Enter to return...")
