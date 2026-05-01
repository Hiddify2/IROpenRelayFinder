import os
import time

import utils.asn_engine as asn_engine
from utils.app_service import APP_SERVICE
import utils.config as config
import utils.helpers as helpers

import cores.ui_asn as ui_asn
import cores.ui_layout as ui_layout
import cores.ui_prompts as ui_prompts


def menu_reroute_domain():
    ui_layout.draw_header(ui_mode="white")
    ui_layout.print_section("FORCE REROUTE", tone="mode_white")
    ui_layout.print_hint("Isolates a bad IP for one domain while keeping it usable for others.")
    domain = ui_prompts.prompt_text(
        "\nEnter domain (e.g. chatgpt.com)",
        remember_key="force_reroute.domain",
    ).strip().lower()
    if not domain:
        return

    result = APP_SERVICE.force_reroute_domain(domain)

    if result["status"] == "rerouted":
        base_domain = result["base_domain"]
        bad_ip = result["bad_ip"]
        ui_layout.print_ok(f"Found bad route: {base_domain} -> {bad_ip}")
        ui_layout.print_ok("Route removed from cache.")
        ui_layout.print_ok(f"Banned {bad_ip} for {base_domain} only.")
        print("\n" + ui_layout.color_text("[✓] Done. Visit the site again to force a new race.", "ok"))
    else:
        ui_layout.print_err(f"No active route found for {domain}.")
        if result.get("removed_failed"):
            ui_layout.print_ok("Removed from failed domains list so it can be raced again.")

    ui_prompts.pause("\nPress Enter to return...", action_label="Return to Main Menu")


def menu_inspect_ips():
    ui_layout.draw_header(ui_mode="white")
    ui_layout.print_section("INSPECT IPS", tone="mode_white")
    print(" [1] Current Dynamic Pool (working IPs)")
    print(" [2] Permanent White IP cache")
    print(" [3] Custom IPs (file or paste)")
    print(" [4] Browse full ASN database (IranASNs)")
    print(" [0] Back")

    choice = input("\nChoice: ").strip()
    ips_to_check = []
    if choice == "1":
        ips_to_check = list(config.IP_POOL.keys())
        if not ips_to_check:
            ui_prompts.pause(ui_layout.color_text("[-] Dynamic Pool is empty. Press Enter to return...", "err"), action_label="Return to Main Menu")
            return
    elif choice == "2":
        ips_to_check = list(helpers.load_white_cache())
        if not ips_to_check:
            ui_prompts.pause(ui_layout.color_text("[-] White Cache is empty. Press Enter to return...", "err"), action_label="Return to Main Menu")
            return
    elif choice == "3":
        print("Paste IPs/CIDRs/ASNs or enter file path (Press Enter on empty line to finish):")
        while True:
            line = input().strip()
            if not line:
                break
            if os.path.exists(line):
                with open(line, 'r') as f:
                    for f_line in f:
                        if f_line.strip():
                            ips_to_check.extend(asn_engine.expand_target(f_line.strip()))
            else:
                ips_to_check.extend(asn_engine.expand_target(line))
        ips_to_check = [(ip, port) for ip in set(ips_to_check) for port in config.TARGET_PORTS]
        if not ips_to_check:
            return
    elif choice == "4":
        ui_asn.menu_browse_asn_db()
        return
    else:
        return

    ui_layout.print_hint("Looking up ASN information...")
    print("-" * 108)
    print(f"| {'IP:PORT':<21} | {'ASN':<8} | {'TYPE':<10} | {'AS NAME':<55} |")
    print("-" * 108)

    for item in ips_to_check:
        parsed = helpers.parse_ip_port(item)
        if not parsed:
            continue
        ip, port = parsed
        asn, as_name, as_type = asn_engine.get_asn_info(ip)
        asn_str = asn if asn else "N/A"
        as_name_short = (as_name[:52] + "...") if len(as_name) > 55 else as_name
        print(f"| {helpers.format_ip_port(ip, port):<21} | {asn_str:<8} | {as_type:<10} | {as_name_short:<55} |")

    print("-" * 108)
    print(f"[*] Total endpoints inspected: {len(ips_to_check)}")
    ui_prompts.pause("\nPress Enter to return...", action_label="Return to Main Menu")


def menu_manage_route_rules():
    while True:
        ui_layout.draw_header(ui_mode="white")
        ui_layout.print_section("ROUTING RULES", tone="mode_white")
        ui_layout.print_hint("DO_NOT_ROUTE = native only | ALWAYS_ROUTE = force white IP routing")

        current = APP_SERVICE.get_route_policy_lists()
        always_list = current.get("always", [])
        do_not_list = current.get("do_not", [])

        print(f"\nAlways Route ({len(always_list)}):")
        if always_list:
            for pattern in always_list:
                print(f"  - {pattern}")
        else:
            print("  (empty)")

        print(f"\nDo Not Route ({len(do_not_list)}):")
        if do_not_list:
            for pattern in do_not_list:
                print(f"  - {pattern}")
        else:
            print("  (empty)")

        print("\n [1] Add Do-Not-Route pattern (native only)")
        print(" [2] Add Always-Route pattern (force white routing)")
        print(" [3] Remove Do-Not-Route pattern")
        print(" [4] Remove Always-Route pattern")
        print(" [0] Back")

        choice = input("\nChoice: ").strip().lower()
        if choice == "0":
            return

        if choice == "1":
            pattern = input("Enter domain/glob/regex (e.g. example.com, *.ir, re:^.*\\.ir$): ").strip().lower()
            result = APP_SERVICE.add_do_not_route_pattern(pattern)
            if result["status"] == "added":
                ui_layout.print_ok(f"Added to DO_NOT_ROUTE: {result['pattern']}")
            elif result["status"] == "exists":
                ui_layout.print_warn(f"Pattern already exists: {result['pattern']}")
            elif result["status"] == "conflict":
                ui_layout.print_err(f"Conflict: '{result['pattern']}' already exists in ALWAYS_ROUTE.")
            elif result["status"] == "invalid":
                ui_layout.print_err(f"Invalid pattern: {result['pattern']}")
            else:
                ui_layout.print_err("Pattern is empty.")
            ui_prompts.pause("\nPress Enter to continue...", action_label="Continue")

        elif choice == "2":
            pattern = input("Enter domain/glob/regex (e.g. gemini.google.com, *.google.com, re:^gemini\\.): ").strip().lower()
            result = APP_SERVICE.add_always_route_pattern(pattern)
            if result["status"] == "added":
                ui_layout.print_ok(f"Added to ALWAYS_ROUTE: {result['pattern']}")
            elif result["status"] == "exists":
                ui_layout.print_warn(f"Pattern already exists: {result['pattern']}")
            elif result["status"] == "conflict":
                ui_layout.print_err(f"Conflict: '{result['pattern']}' already exists in DO_NOT_ROUTE.")
            elif result["status"] == "invalid":
                ui_layout.print_err(f"Invalid pattern: {result['pattern']}")
            else:
                ui_layout.print_err("Pattern is empty.")
            ui_prompts.pause("\nPress Enter to continue...", action_label="Continue")

        elif choice == "3":
            pattern = input("Pattern to remove from DO_NOT_ROUTE: ").strip().lower()
            result = APP_SERVICE.remove_do_not_route_pattern(pattern)
            if result["status"] == "removed":
                ui_layout.print_ok(f"Removed from DO_NOT_ROUTE: {result['pattern']}")
            elif result["status"] == "missing":
                ui_layout.print_warn(f"Pattern not found: {result['pattern']}")
            else:
                ui_layout.print_err("Pattern is empty.")
            ui_prompts.pause("\nPress Enter to continue...", action_label="Continue")

        elif choice == "4":
            pattern = input("Pattern to remove from ALWAYS_ROUTE: ").strip().lower()
            result = APP_SERVICE.remove_always_route_pattern(pattern)
            if result["status"] == "removed":
                ui_layout.print_ok(f"Removed from ALWAYS_ROUTE: {result['pattern']}")
            elif result["status"] == "missing":
                ui_layout.print_warn(f"Pattern not found: {result['pattern']}")
            else:
                ui_layout.print_err("Pattern is empty.")
            ui_prompts.pause("\nPress Enter to continue...", action_label="Continue")
