import os
import sys
import time
import asyncio
import subprocess

import utils.config as config
import utils.helpers as helpers
import utils.asn_engine as asn_engine
from utils.app_service import APP_SERVICE
from utils.route_service import ROUTE_SERVICE

import cores.ui_layout as ui_layout
import cores.ui_scan as ui_scan
import cores.ui_tools as ui_tools
import cores.ui_dpi as ui_dpi


def draw_header(ui_mode=None):
    ui_layout.draw_header(ui_mode=ui_mode)


def main():
    """Main CLI Execution Loop"""
    config.load_config()
    ROUTE_SERVICE.load_ip_pool()
    ROUTE_SERVICE.load_banned_routes()
    asn_engine.load_asn_data()

    def execute_core(module):
        if hasattr(module, 'run'):
            asyncio.run(module.run())
        elif hasattr(module, 'main'):
            if asyncio.iscoroutinefunction(module.main):
                asyncio.run(module.main())
            else:
                module.main()

    def launch_ir_open_relay_finder():
        APP_SERVICE.set_connection_mode("white_ip", persist=True)
        import cores.white_core as proxy_core
        try:
            execute_core(proxy_core)
        except KeyboardInterrupt:
            pass

    def launch_desync_or_mixed(choice):
        pairs = ui_dpi.load_desync_pairs()
        if pairs:
            ui_dpi.prompt_dpi_target_from_pairs(pairs)
        else:
            ui_dpi.prompt_manual_dpi_target()

        APP_SERVICE.set_connection_mode("dpi_desync" if choice == "d" else "mixed", persist=True)

        is_admin = False
        if sys.platform == 'win32':
            import ctypes
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            except Exception:
                is_admin = False
        else:
            is_admin = os.geteuid() == 0

        if not is_admin:
            print("\n[*] Elevating privileges (required for Raw Sockets)...")
            time.sleep(1)
            try:
                if sys.platform == 'win32':
                    import ctypes
                    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv + ["-c", "white_core"]), None, 1)
                else:
                    subprocess.run(["sudo", sys.executable, sys.argv[0], "-c", "white_core"])
            except KeyboardInterrupt:
                pass
            except Exception as e:
                print(f"[-] Failed to elevate privileges: {e}")
                time.sleep(2)
        else:
            import cores.white_core as proxy_core
            try:
                execute_core(proxy_core)
            except KeyboardInterrupt:
                pass

    ui_mode = "desync" if config.CONNECTION_MODE in ["dpi_desync", "mixed"] else "white"

    while True:
        draw_header(ui_mode=ui_mode)
        ui_layout.print_main_menu(ui_mode=ui_mode)

        try:
            choice = input("\nAction: ").strip().lower()

            if ui_mode == "white":
                if choice == "1":
                    ui_scan.menu_scan()
                elif choice == "2":
                    ui_scan.menu_manage_pool()
                elif choice == "3":
                    ui_scan.menu_instant_connect()
                elif choice == "4":
                    new_port = input(f"Enter new port (Current {config.PROXY_PORT}): ").strip()
                    if new_port.isdigit() and 1 <= int(new_port) <= 65535:
                        APP_SERVICE.set_proxy_port(int(new_port))
                    else:
                        print("[-] Invalid port number.")
                        time.sleep(1)
                elif choice == "5":
                    if APP_SERVICE.clear_route_cache():
                        print("[+] Cache cleared successfully.")
                    else:
                        print("[-] Cache already empty.")
                    time.sleep(1)
                elif choice == "6":
                    ui_tools.menu_reroute_domain()
                elif choice == "7":
                    ui_tools.menu_inspect_ips()
                elif choice == "8":
                    import cores.autotuner as autotuner_core
                    execute_core(autotuner_core)
                elif choice == "9":
                    ui_tools.menu_manage_route_rules()
                elif choice == "c":
                    ui_tools.menu_install_mmdf_ca()
                elif choice == "s":
                    import cores.socks5_scanner as socks5_scanner_core
                    execute_core(socks5_scanner_core)
                elif choice == "h":
                    import cores.http_scanner as http_scanner_core
                    execute_core(http_scanner_core)
                elif choice == "w":
                    launch_ir_open_relay_finder()
                elif choice == "x":
                    ui_mode = "desync"
                elif choice == "0":
                    helpers.clear_screen()
                    print("[*] Shutting down...")
                    break

            else:
                if choice == "1":
                    ui_dpi.menu_manage_dpi_strategies()
                elif choice == "2":
                    pairs = ui_dpi.load_desync_pairs()
                    if pairs:
                        ui_dpi.prompt_dpi_target_from_pairs(pairs)
                    else:
                        ui_dpi.prompt_manual_dpi_target()
                elif choice == "3":
                    import cores.desync_scanner as desync_scanner_core
                    execute_core(desync_scanner_core)
                elif choice == "4":
                    try:
                        import cores.sni_scanner as sni_scanner_core
                        execute_core(sni_scanner_core)
                    except ImportError:
                        print("\n[-] SNI Scanner module not yet created. Ready for next update!")
                        time.sleep(2)
                elif choice == "s":
                    import cores.socks5_scanner as socks5_scanner_core
                    execute_core(socks5_scanner_core)
                elif choice == "h":
                    import cores.http_scanner as http_scanner_core
                    execute_core(http_scanner_core)
                elif choice == "5":
                    new_port = input(f"Enter new port (Current {config.PROXY_PORT}): ").strip()
                    if new_port.isdigit() and 1 <= int(new_port) <= 65535:
                        APP_SERVICE.set_proxy_port(int(new_port))
                    else:
                        print("[-] Invalid port number.")
                        time.sleep(1)
                elif choice == "6":
                    if APP_SERVICE.clear_route_cache():
                        print("[+] Cache cleared successfully.")
                    else:
                        print("[-] Cache already empty.")
                    time.sleep(1)
                elif choice == "c":
                    ui_tools.menu_install_mmdf_ca()
                elif choice in ["d", "m"]:
                    launch_desync_or_mixed(choice)
                elif choice == "x":
                    ui_mode = "white"
                elif choice == "0":
                    helpers.clear_screen()
                    print("[*] Shutting down...")
                    break
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
