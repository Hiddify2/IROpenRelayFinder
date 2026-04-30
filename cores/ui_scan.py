import asyncio
import json
import os
import random
import sys
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
import cores.ui_prompts as ui_prompts


def prompt_target_ports():
    current_ports = ", ".join(str(p) for p in config.TARGET_PORTS)
    ui_layout.print_section("TARGET PORTS")
    print(f" [1] Use configured ports ({current_ports})")
    print(" [2] Enter custom ports")
    saved_mode = str(ui_prompts.get_pref("white_scan.port_mode", "1")).strip().lower()
    if saved_mode not in {"1", "2"}:
        saved_mode = "1"
    choice = input(f"\nPort mode [Default {saved_mode}, or type ports directly]: ").strip().lower()
    
    if not choice:
        choice = saved_mode

    if choice == "1":
        ui_prompts.set_pref("white_scan.port_mode", "1")
        selected_ports = list(config.TARGET_PORTS)
    elif choice == "2":
        ui_prompts.set_pref("white_scan.port_mode", "2")
        raw_ports = input("Enter ports (comma or space separated, e.g. 443,2053,8443): ").strip()
        selected_ports = helpers.parse_port_list(raw_ports, fallback_ports=config.TARGET_PORTS)
    else:
        ui_prompts.set_pref("white_scan.port_mode", "custom")
        selected_ports = helpers.parse_port_list(choice, fallback_ports=config.TARGET_PORTS)
    
    config.set_target_ports(selected_ports)
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


def menu_scan():
    ui_layout.draw_header(ui_mode="white")
    choice = ui_prompts.menu_choice(
        "SCAN SOURCE",
        [
            ("1", "Load IPs/CIDRs/ASNs from text file", None),
            ("2", "Paste IPs/CIDRs/ASNs manually", None),
            ("3", "Use Permanent White IP cache", None),
            ("4", "Select from IranASN database", None),
            ("0", "Back", None),
        ],
        default="1",
        remember_key="white_scan.source",
    )

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
        subnets = ui_asn.menu_search_asn()
        if not subnets:
            input("Press Enter to return...")
            return
        raw_targets.extend(subnets)
    elif choice == "0":
        return
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

    expanded_items, dropped = asn_engine.filter_to_iranian(expanded_items)
    if dropped:
        ui_layout.print_warn(f"{dropped} non-Iranian IP(s) were dropped (not found in IranASN database).")
    if not expanded_items:
        input(ui_layout.color_text("[-] No Iranian IPs remain after filtering. Press Enter to return...", "err"))
        return

    selected_ports = prompt_target_ports()
    has_explicit_ports = any(_has_explicit_port(item) for item in expanded_items)
    strip_explicit_ports = False
    if has_explicit_ports:
        strip_explicit_ports = ui_prompts.prompt_yes_no(
            "[?] Some targets include explicit ports. Strip them and scan only selected target ports",
            default=False,
        )

    exact_endpoints, endpoints, preflight_ips, merged_ports = build_scan_endpoints(
        expanded_items,
        selected_ports,
        strip_explicit_ports=strip_explicit_ports,
    )
    config.set_target_ports(merged_ports)

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

    selected_tool = str(ui_prompts.get_pref("white_scan.method", "asyncio")).strip().lower()
    if selected_tool not in {"asyncio", "masscan", "nmap"}:
        selected_tool = "asyncio"
    is_debug_mode = False
    options = {"1": "asyncio"}
    opt_num = 2
    if has_masscan:
        options[str(opt_num)] = "masscan"
        opt_num += 1
    if has_nmap:
        options[str(opt_num)] = "nmap"
    if selected_tool == "masscan" and not has_masscan:
        selected_tool = "asyncio"
    if selected_tool == "nmap" and not has_nmap:
        selected_tool = "asyncio"

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

        method_choice = input("\nAction [Default s] ([s] start, [d] debug, [1..] method, [0] back): ").strip().lower()
        if not method_choice:
            break
        if method_choice == "0":
            return
        if method_choice == "d":
            is_debug_mode = not is_debug_mode
            continue
        if method_choice == "s":
            ui_prompts.set_pref("white_scan.method", selected_tool)
            break
        selected_tool = options.get(method_choice, selected_tool)

    # Asyncio concurrency — only asked for asyncio mode; masscan/nmap prompt
    # their own rate inside run_masscan_preflight / run_nmap_preflight.
    if selected_tool == "asyncio":
        ui_layout.print_section("CONCURRENCY")
        print(f" Current setting: {config.MAX_CONCURRENT_SCANS} concurrent connections")
        config.MAX_CONCURRENT_SCANS = ui_prompts.prompt_int(
            "[?] Concurrent connections for this scan",
            config.MAX_CONCURRENT_SCANS,
            min_value=1,
            remember_key="white_scan.asyncio_concurrency",
        )

    ui_layout.print_section("SCAN OPTIONS")
    is_cyclic = ui_prompts.prompt_yes_no(
        "[?] Run cyclic continuous scan",
        default=False,
        remember_key="white_scan.cyclic",
    )

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
        print("[!] Press Ctrl+C at any time to STOP the scan and save current results.\n")

        successful_results = []
        interrupted = False
        try:
            asyncio.run(SCAN_SERVICE.run_mass_scan(current_targets, config.DEFAULT_DOMAINS, successful_results, skip_tcp=skip_tcp, deep_scan=is_debug_mode))
        except KeyboardInterrupt:
            print("\n\n[!] Scan INTERRUPTED by user. Finalizing saved IPs...")
            interrupted = True

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
    choice = ui_prompts.menu_choice(
        "INSTANT CONNECT",
        [
            ("1", "Load IPs from text file", None),
            ("2", "Paste IPs manually", None),
            ("0", "Back", None),
        ],
        default="1",
        remember_key="instant_connect.source",
    )

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
    elif choice == "0":
        return
    else:
        return

    raw_items = list(dict.fromkeys(raw_items))
    if not raw_items:
        input(ui_layout.color_text("[-] No valid IPs parsed. Press Enter to return...", "err"))
        return

    raw_items, dropped = asn_engine.filter_to_iranian(raw_items)
    if dropped:
        ui_layout.print_warn(f"{dropped} non-Iranian IP(s) were dropped (not found in IranASN database).")
    if not raw_items:
        input(ui_layout.color_text("[-] No Iranian IPs remain after filtering. Press Enter to return...", "err"))
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
    try:
        asyncio.run(
            SCAN_SERVICE.run_mass_scan(
                endpoints,
                config.DEFAULT_DOMAINS,
                successful_results,
                skip_tcp=False,
                deep_scan=False,
            )
        )
    except KeyboardInterrupt:
        print("\n\n[!] Instant-connect verification interrupted by user. Using collected results...")
        interrupted = True

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
