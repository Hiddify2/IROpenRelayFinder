import time

from utils.app_service import APP_SERVICE
import utils.config as config
import utils.data_store as data_store
import utils.helpers as helpers
import cores.ui_layout as ui_layout


def load_desync_pairs():
    pairs_raw = data_store.read_json("desync_pairs.json", default={}) or {}
    if not isinstance(pairs_raw, dict):
        return {}

    pairs = {}
    for sni, ips in pairs_raw.items():
        if not isinstance(sni, str):
            continue
        if not isinstance(ips, (list, tuple, set)):
            continue
        clean_ips = [str(ip).strip() for ip in ips if str(ip).strip()]
        if clean_ips:
            pairs[sni] = clean_ips

    return pairs


def prompt_manual_dpi_target():
    ui_layout.print_section("MANUAL DPI TARGET", tone="mode_desync")
    new_sni = input(f"\n[?] Fake SNI to spoof [Current: {config.DPI_SNI}]: ").strip()
    selected_sni = new_sni if new_sni else None

    new_ip = input(
        f"[?] Clean IP for this SNI [Current: {config.DPI_IP if config.DPI_IP else 'Auto-resolve'}] (Type 'none' to clear): "
    ).strip()
    selected_ip = None
    if new_ip.lower() == 'none':
        selected_ip = ""
    elif new_ip:
        selected_ip = new_ip

    if selected_sni is not None or selected_ip is not None:
        APP_SERVICE.set_dpi_target(sni=selected_sni, ip=selected_ip)


def prompt_dpi_target_from_pairs(pairs):
    ui_layout.print_ok("Found locally mined Desync pairs.")
    ui_layout.print_section("SNI SELECTION", tone="mode_desync")
    print("  [0] Enter SNI and IP manually")
    sni_list = sorted(pairs.keys(), key=lambda k: len(pairs[k]), reverse=True)
    top_limit = min(10, len(sni_list))
    for i, s in enumerate(sni_list[:top_limit]):
        print(f"  [{i+1}] {s} ({len(pairs[s])} IPs)")

    sel = input(f"\n[?] Select SNI [0-{top_limit}] (Default 0): ").strip()
    if not (sel.isdigit() and 1 <= int(sel) <= top_limit):
        prompt_manual_dpi_target()
        return

    selected_sni = sni_list[int(sel) - 1]

    available_ips = list(pairs[selected_sni])
    ui_layout.print_section(f"IP SELECTION FOR {selected_sni}", tone="mode_desync")
    preview_limit = min(15, len(available_ips))
    for idx, ip in enumerate(available_ips[:preview_limit]):
        print(f"    [{idx+1}] {ip}")
    if len(available_ips) > preview_limit:
        print(f"    ... and {len(available_ips) - preview_limit} more.")

    ip_sel = input(
        f"\n[?] Select IP [1-{preview_limit}], or type custom IP (Default 1): "
    ).strip()
    if ip_sel.isdigit() and 1 <= int(ip_sel) <= len(available_ips):
        selected_ip = available_ips[int(ip_sel) - 1]
    elif ip_sel and not ip_sel.isdigit():
        selected_ip = ip_sel
    else:
        selected_ip = available_ips[0]

    APP_SERVICE.set_dpi_target(sni=selected_sni, ip=selected_ip)

    ui_layout.print_ok(f"Selected DPI target: SNI={config.DPI_SNI}, IP={config.DPI_IP}")
    time.sleep(1)


def menu_manage_dpi_strategies():
    all_strats = [
        {"id": "oob", "desc": "Out-of-Bounds Sequence (Healthy Checksum) [Default]"},
        {"id": "bad_csum", "desc": "Invalid TCP Checksum (In-Bounds Sequence)"},
        {"id": "ttl", "desc": "TTL Expiration (Expires before reaching CDN)"},
        {"id": "syn", "desc": "TCP SYN Insertion (Fake SYN payload)"},
        {"id": "rst", "desc": "TCP RST Insertion (Fake RST payload)"},
        {"id": "fin", "desc": "TCP FIN Insertion (Fake FIN payload)"},
        {"id": "classic", "desc": "Segment Only (No Fake Packet, Relies on TCP Chunking)"}
    ]

    selected = set(config.DPI_STRATEGIES)

    while True:
        helpers.clear_screen()
        line = ui_layout.color_text("═" * 50, "dim")
        print(line)
        print(ui_layout.color_text(" DPI DESYNC STRATEGY SELECTION", "mode_desync"))
        print(line + "\n")

        frag_status = "ON" if getattr(config, 'DPI_FRAGMENTATION', False) else "OFF"
        log_status = "ON" if getattr(config, 'ALWAYS_SHOW_DPI_LOGS', False) else "OFF (Auto-hide)"
        print(f"  [f] Toggle TCP Fragmentation (Current: {frag_status})")
        print(f"  [l] Toggle DPI Logs Visibility (Current: {log_status})\n")

        ui_layout.print_section("INJECTION STRATEGIES", tone="section")
        for i, s in enumerate(all_strats):
            checkbox = "[X]" if s["id"] in selected else "[ ]"
            print(f"  {i+1:>2}. {checkbox} {s['id'].upper():<10} : {s['desc']}")

        print("\n" + ui_layout.color_text(" Commands", "nav"))
        print("  [1, 2...] Toggle selection")
        print("  [f]       Toggle TCP Fragmentation")
        print("  [l]       Toggle DPI Logs visibility")
        print("  [d]       Done & Save")
        print("  [0]       Cancel")

        cmd = input("\nAction: ").strip().lower()
        if not cmd:
            continue
        elif cmd in ['0', 'q']:
            return
        elif cmd == 'f':
            APP_SERVICE.toggle_dpi_fragmentation()
            continue
        elif cmd == 'l':
            APP_SERVICE.toggle_dpi_logs()
            continue
        elif cmd == 'd':
            if not selected:
                ui_layout.print_err("You must select at least one strategy.")
                time.sleep(1)
                continue
            APP_SERVICE.set_dpi_strategies(list(selected))
            ui_layout.print_ok(f"DPI strategies saved: {', '.join(config.DPI_STRATEGIES).upper()}")
            time.sleep(1.5)
            break
        else:
            try:
                parts = cmd.replace(',', ' ').split()
                for p in parts:
                    if p.isdigit():
                        i = int(p)
                        if 1 <= i <= len(all_strats):
                            key = all_strats[i - 1]["id"]
                            if key in selected:
                                selected.remove(key)
                            else:
                                selected.add(key)
            except Exception:
                pass
