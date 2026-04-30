import os
import sys

import utils.config as config
import utils.helpers as helpers


_ANSI_ENABLED = None


def _supports_ansi():
    global _ANSI_ENABLED
    if _ANSI_ENABLED is not None:
        return _ANSI_ENABLED

    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        _ANSI_ENABLED = False
        return _ANSI_ENABLED

    if os.environ.get("NO_COLOR") is not None:
        _ANSI_ENABLED = False
        return _ANSI_ENABLED

    if os.environ.get("TERM", "").lower() == "dumb":
        _ANSI_ENABLED = False
        return _ANSI_ENABLED

    if os.name == 'nt':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint()
            if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass

    _ANSI_ENABLED = True
    return _ANSI_ENABLED


def _c(text, code):
    if not _supports_ansi():
        return text
    return f"\033[{code}m{text}\033[0m"


def color_text(text, tone="default"):
    tones = {
        "default": "0",
        "title": "1;36",
        "mode_white": "1;36",
        "section": "1;34",
        "launch": "1;32",
        "nav": "1;33",
        "ok": "1;32",
        "warn": "1;33",
        "err": "1;31",
        "dim": "90",
    }
    return _c(text, tones.get(tone, tones["default"]))


def print_section(title, tone="section"):
    print(color_text(f" {title}", tone))


def print_hint(text):
    print(color_text(f" [*] {text}", "dim"))


def print_ok(text):
    print(color_text(f" [+] {text}", "ok"))


def print_warn(text):
    print(color_text(f" [!] {text}", "warn"))


def print_err(text):
    print(color_text(f" [-] {text}", "err"))


def _mode_label(connection_mode):
    return "White Routing"


def draw_header(ui_mode=None):
    helpers.clear_screen()
    line = color_text("═" * 60, "dim")
    title = color_text(f" IROpenRelayFinder v{config.VERSION} ", "title")
    print(line)
    print(title)
    print(line)

    pool_size = len(config.IP_POOL)
    active_ui = "IROpenRelayFinder"
    print(f" {color_text('UI Mode', 'section'):12}: {active_ui}")
    print(f" {color_text('Conn Mode', 'section'):12}: {_mode_label(config.CONNECTION_MODE)}")
    print(f" {color_text('Proxy', 'section'):12}: {config.PROXY_HOST}:{config.PROXY_PORT} (Local: {helpers.get_local_ip()})")

    print(f" {color_text('IP Pool', 'section'):12}: {pool_size} loaded")

    if config.TUNED_MASSCAN_RATE or config.TUNED_NMAP_MIN_RATE or config.MAX_CONCURRENT_SCANS != 100:
        nmap_disp = f"{config.TUNED_NMAP_MIN_RATE}-{config.TUNED_NMAP_MAX_RATE}" if config.TUNED_NMAP_MIN_RATE else "N/A"
        mass_disp = config.TUNED_MASSCAN_RATE if config.TUNED_MASSCAN_RATE else "N/A"
        print(f" {color_text('Tuning', 'section'):12}: Async={config.MAX_CONCURRENT_SCANS} | Masscan={mass_disp} | Nmap={nmap_disp}")

    print(line + "\n")


def print_main_menu(ui_mode="white"):
    print(color_text(" IROpenRelayFinder MODE", "mode_white"))
    print(" [1] Scan Targets and Build IP Pool")
    print(" [2] Reload IP Pool from Latest Scan")
    print(" [3] Instant Connect (Load IPs without scan)")
    print(" [4] Change Proxy Port")
    print(f" [5] Clear Routing Cache ({os.path.basename(config.HOSTS_FILE)})")
    print(" [6] Force Reroute Domain and Ban IP")
    print(" [7] Inspect IPs (ASN and Type)")
    print(" [8] Auto-Tune Scan Rates")
    print(" [9] Manage Routing Rules (Whitelist/Blacklist)")
    print(" [s] SOCKS5 Proxy Scanner")
    print(" [h] HTTP-Only Proxy Scanner")
    print("\n" + color_text(" Launch", "launch"))
    print(" [w] Start Proxy (White Routing)")
    print("\n" + color_text(" Navigation", "nav"))
    print(" [x] Switch to Desync Mode")
    print(" [0] Exit")
