import os
import sys
import time
import asyncio
import curses
import builtins
import re

import utils.config as config
import utils.helpers as helpers
import utils.asn_engine as asn_engine
from utils.app_service import APP_SERVICE
from utils.route_service import ROUTE_SERVICE

import cores.ui_layout as ui_layout
import cores.ui_scan as ui_scan
import cores.ui_tools as ui_tools
import cores.ui_prompts as ui_prompts


_COLOR = {}


def _init_curses_ui():
    """Initialize curses features that are safe on plain terminals too."""
    try:
        curses.curs_set(0)
    except curses.error:
        pass

    if curses.has_colors():
        try:
            curses.start_color()
            curses.use_default_colors()
            pairs = {
                "title": (curses.COLOR_CYAN, -1),
                "section": (curses.COLOR_BLUE, -1),
                "accent": (curses.COLOR_GREEN, -1),
                "warn": (curses.COLOR_YELLOW, -1),
                "err": (curses.COLOR_RED, -1),
                "dim": (curses.COLOR_WHITE, -1),
                "selected": (curses.COLOR_BLACK, curses.COLOR_CYAN),
                "desync": (curses.COLOR_MAGENTA, -1),
            }
            for idx, (name, colors) in enumerate(pairs.items(), start=1):
                curses.init_pair(idx, colors[0], colors[1])
                _COLOR[name] = curses.color_pair(idx)
        except curses.error:
            _COLOR.clear()


def _attr(name, fallback=0):
    return _COLOR.get(name, fallback)


def _safe_addnstr(win, y, x, text, width, attr=0):
    if width <= 0:
        return
    try:
        win.addnstr(y, x, str(text), width, attr)
    except curses.error:
        pass


def _safe_hline(win, y, x, ch, width, attr=0):
    if width <= 0:
        return
    try:
        win.hline(y, x, ch, width, attr)
    except curses.error:
        pass


def _choice_from_line_click(line, x_pos):
    """
    Convert a clicked line from print/input submenus into the same text a user
    would type. Supports single and multi-digit bracket choices, explicit
    command tokens, and numbered checklist rows such as "  12. [X] ...".
    """
    if line is None:
        return None

    text = str(line)
    leading = re.match(r"^\s*(\d{1,4})[\.\)]\s+", text)
    bracket_matches = list(re.finditer(r"\[\s*([^\]]{1,64}?)\s*\]", text))

    def _normalize_token(raw):
        token = raw.strip()
        lower = token.lower()
        # Ignore checkbox markers in list rows.
        if token in {"", "X"}:
            return None
        if lower in {"!", "?", "default", "recommended"}:
            return None
        return lower

    # Exact token click: useful for "Commands: [n] Next [p] Previous [0] Back".
    for match in bracket_matches:
        if match.start() <= x_pos <= match.end():
            token = _normalize_token(match.group(1))
            if token is not None:
                return token

    # Menu rows are usually clickable across the whole label, not only the key.
    if bracket_matches:
        token = _normalize_token(bracket_matches[0].group(1))
        if token is not None:
            return token

    if leading:
        return leading.group(1)

    return None


class _CursesConsole:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.lines = []
        self.max_lines = 5000
        self._orig_print = None
        self._orig_input = None
        self._orig_clear_screen = None
        self._orig_no_color = None
        self._screen_lines = {}
        self._screen_line_indices = {}
        self._input_queue = []
        self._scroll_offset = 0
        self._input_box_confirm = None

    def _sanitize(self, text):
        if text is None:
            return ""
        return str(text).replace("\r", "")

    def _append(self, text):
        text = self._sanitize(text)
        if not self.lines:
            self.lines.append("")

        for ch in text:
            if ch == "\n":
                self.lines.append("")
            elif ch == "\r":
                self.lines[-1] = ""
            else:
                self.lines[-1] += ch
        if len(self.lines) > self.max_lines:
            self.lines = self.lines[-self.max_lines:]
        self._scroll_offset = 0

    def _line_attr(self, line):
        stripped = line.strip()
        lower = stripped.lower()
        upper = stripped.upper()
        if not stripped:
            return 0
        if stripped.startswith(("[-]", "[-")) or "error" in lower or "invalid" in lower:
            return _attr("err", curses.A_BOLD)
        if stripped.startswith(("[!]", "[!]")) or "warning" in lower:
            return _attr("warn", curses.A_BOLD)
        if stripped.startswith(("[+]", "[✓]", "[*]")):
            return _attr("accent", curses.A_BOLD)
        if any(token in upper for token in ("MODE", "SCANNER", "BROWSER", "SELECTION", "COMMANDS", "SOURCE")):
            return _attr("title", curses.A_BOLD)
        if re.match(r"^\s*\[[A-Za-z0-9]\]", line) or re.match(r"^\s*\d+\.\s", line):
            return _attr("section", curses.A_BOLD)
        return 0

    def _draw_log(self, prompt="", input_buffer="", selected_row=None):
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()

        if h <= 1 or w <= 1:
            self.stdscr.refresh()
            return

        # Strip leading newlines — prompts use \n for spacing in plain terminals
        # but in curses the bottom line is a single row.
        clean_prompt = prompt.lstrip('\n')
        prompt_line = f"{clean_prompt}{input_buffer}"
        content_rows = max(1, h - 2)
        max_offset = max(0, len(self.lines) - content_rows)
        self._scroll_offset = max(0, min(self._scroll_offset, max_offset))
        end = len(self.lines) - self._scroll_offset
        start = max(0, end - content_rows)
        visible = self.lines[start:end]
        self._screen_lines = {}
        self._screen_line_indices = {}

        for row, line in enumerate(visible):
            line_index = start + row
            if row < h - 2:
                attr = _attr("selected", curses.A_REVERSE) if row == selected_row else self._line_attr(line)
                _safe_addnstr(self.stdscr, row, 0, line, max(1, w - 1), attr)
                self._screen_lines[row] = line
                self._screen_line_indices[row] = line_index

        _safe_addnstr(self.stdscr, h - 2, 0, "-" * max(1, w - 1), max(1, w - 1), _attr("dim"))
        if self._scroll_offset:
            marker = f" scroll {self._scroll_offset} lines above | PgDn/End to bottom "
            _safe_addnstr(self.stdscr, h - 2, max(0, w - len(marker) - 1), marker, len(marker), _attr("warn"))
        _safe_addnstr(self.stdscr, h - 1, 0, prompt_line, max(1, w - 1), _attr("accent", curses.A_BOLD))
        try:
            self.stdscr.move(h - 1, min(len(prompt_line), max(0, w - 2)))
        except curses.error:
            pass
        self.stdscr.refresh()

    def _visible_choices(self):
        choices = []
        seen = set()
        for row, line in sorted(self._screen_lines.items()):
            value = _choice_from_line_click(line, len(line))
            if value is None:
                continue
            if "commands:" in line.lower() and len(re.findall(r"\[[^\]]+\]", line)) > 1:
                continue
            key = (row, value)
            if key in seen:
                continue
            seen.add(key)
            choices.append((row, value))

        if not choices:
            return choices

        # Constrain navigation to the most recent visible choice cluster.
        recent_rows = {row for row, _value in choices}
        recent_start = max(0, max(recent_rows) - 24)
        filtered = [(row, value) for row, value in choices if row >= recent_start]
        return filtered or choices

    def _infer_default_choice_index(self, prompt, choices):
        if not choices:
            return 0
        prompt_l = (prompt or "").lower()
        match = re.search(r"default\s*([a-z0-9_/\-]+)", prompt_l)
        if match:
            token = match.group(1).strip()
            for idx, (_row, value) in enumerate(choices):
                if value == token:
                    return idx

        for _row, line in sorted(self._screen_lines.items()):
            if "default" not in line.lower():
                continue
            token = _choice_from_line_click(line, 0)
            if token is None:
                continue
            for idx, (_crow, value) in enumerate(choices):
                if value == token:
                    return idx
        return 0

    def _find_row_for_buffer(self, value, choices):
        if not value or not choices:
            return None
        lower = value.lower()
        # Slash commands are free-form search/regex inputs in ASN views.
        if lower.startswith("/"):
            return None
        exact = next((row for row, token in choices if token == lower), None)
        if exact is not None:
            return exact
        if lower.isdigit():
            return next((row for row, token in choices if token.startswith(lower)), None)
        return None

    def _is_choice_prompt(self, prompt):
        if not prompt:
            return True
        p = prompt.lower()
        if any(k in p for k in ("choice", "action", "select", "mode", "profile", "source", "method")):
            return True
        return False

    def _patched_print(self, *args, sep=' ', end='\n', file=None, flush=False):
        if file not in (None, sys.stdout, sys.stderr):
            if self._orig_print:
                self._orig_print(*args, sep=sep, end=end, file=file, flush=flush)
            return
        msg = sep.join(str(a) for a in args) + end
        self._append(msg)
        self._draw_log()

    def _patched_input(self, prompt=""):
        if self._input_queue:
            value = self._input_queue.pop(0)
            self._append(f"{prompt}{value}\n")
            self._draw_log()
            return value
        if self._should_use_input_box(prompt):
            value = self._capture_text_input_box(prompt)
            self._append(f"{prompt}{value}\n")
            self._draw_log()
            return value
        if not prompt and self._should_start_paste_mode():
            queued = self._capture_paste_block()
            if queued:
                self._input_queue = queued[1:] + [""]
                value = queued[0]
                self._append(f"{prompt}{value}\n")
                self._draw_log()
                return value
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        buf = []
        selected_idx = 0
        selection_active = True
        default_initialized = False
        try:
            while True:
                current = "".join(buf)
                choices = self._visible_choices()
                if choices:
                    selected_idx = selected_idx % len(choices)
                if choices and not default_initialized:
                    selected_idx = self._infer_default_choice_index(prompt, choices)
                    selection_active = True
                    default_initialized = True

                typed_row = self._find_row_for_buffer(current, choices)
                selected_row = None
                if typed_row is not None:
                    selected_row = typed_row
                elif choices and selection_active:
                    selected_row = choices[selected_idx][0]

                self._draw_log(prompt=prompt, input_buffer=current, selected_row=selected_row)
                key = self.stdscr.getch()

                if key in (10, 13, curses.KEY_ENTER):
                    if self._is_choice_prompt(prompt) and selection_active and choices and not buf:
                        value = choices[selected_idx][1]
                        self._append(f"{prompt}{value}\n")
                        self._draw_log()
                        return value
                    value = "".join(buf)
                    self._append(f"{prompt}{value}\n")
                    self._draw_log()
                    return value
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    if buf:
                        buf.pop()
                    if not buf:
                        selection_active = True
                    continue
                if key in (curses.KEY_UP,):
                    if choices:
                        selected_idx = (selected_idx - 1) % len(choices)
                        selection_active = True
                    continue
                if key in (curses.KEY_DOWN, 9):
                    if choices:
                        selected_idx = (selected_idx + 1) % len(choices)
                        selection_active = True
                    continue
                if key in (curses.KEY_PPAGE,):
                    self._scroll_offset += max(1, self.stdscr.getmaxyx()[0] - 3)
                    continue
                if key in (curses.KEY_NPAGE, curses.KEY_END):
                    self._scroll_offset = max(0, self._scroll_offset - max(1, self.stdscr.getmaxyx()[0] - 3))
                    continue
                if key == curses.KEY_HOME:
                    self._scroll_offset = max(0, len(self.lines))
                    continue
                if key in (27, curses.KEY_RESIZE):
                    continue
                if key == curses.KEY_MOUSE:
                    selected = self._handle_mouse_choice()
                    if selected is not None:
                        self._append(f"{prompt}{selected}\n")
                        self._draw_log()
                        return selected
                    continue
                if 0 <= key <= 255:
                    ch = chr(key)
                    if ch.isprintable():
                        buf.append(ch)
                        selection_active = True
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass

    def _patched_clear_screen(self):
        self.lines = []
        self._draw_log()

    def _handle_mouse_choice(self):
        try:
            _, mx, my, _, bstate = curses.getmouse()
        except Exception:
            return None
        if bstate & getattr(curses, "BUTTON4_PRESSED", 0):
            self._scroll_offset += 3
            return None
        if bstate & getattr(curses, "BUTTON5_PRESSED", 0):
            self._scroll_offset = max(0, self._scroll_offset - 3)
            return None
        if not (bstate & (curses.BUTTON1_CLICKED | curses.BUTTON1_PRESSED | curses.BUTTON1_RELEASED)):
            return None
        line = self._screen_lines.get(my)
        if not line:
            return None
        return _choice_from_line_click(line, mx)

    def _should_start_paste_mode(self):
        for line in self._screen_lines.values():
            text = line.lower()
            if "paste" in text and "press enter on an empty line" in text:
                return True
            if "paste your ips" in text:
                return True
            if "paste ips" in text and "empty line" in text:
                return True
        return False

    def _draw_paste_box(self, lines, current):
        h, w = self.stdscr.getmaxyx()
        box_h = min(14, max(8, h - 6))
        box_w = min(92, max(36, w - 8))
        top = max(0, (h - box_h) // 2)
        left = max(0, (w - box_w) // 2)
        right = left + box_w - 1
        bottom = top + box_h - 1

        self.stdscr.erase()
        _draw_box(self.stdscr, top, left, box_h, box_w, " Paste Targets ", _attr("section"))
        subtitle = "Paste IP/CIDR/ASN lines. Submit an empty line to finish."
        _safe_addnstr(self.stdscr, top + 1, left + 2, subtitle, box_w - 4, _attr("dim"))
        _safe_hline(self.stdscr, top + 2, left + 1, ord('-'), box_w - 2, _attr("dim"))

        inner_h = box_h - 5
        inner_w = box_w - 2
        view = lines[-inner_h:]
        for idx, line in enumerate(view):
            _safe_addnstr(self.stdscr, top + 3 + idx, left + 1, line, inner_w, _attr("accent"))
        input_row = top + 3 + min(len(view), inner_h - 1)
        _safe_addnstr(self.stdscr, input_row, left + 1, current, inner_w, _attr("warn", curses.A_BOLD))
        try:
            self.stdscr.move(input_row, min(right - 1, left + 1 + len(current)))
        except curses.error:
            pass

        footer = f"Lines: {len(lines)}"
        _safe_hline(self.stdscr, bottom - 1, left + 1, ord('-'), box_w - 2, _attr("dim"))
        _safe_addnstr(self.stdscr, bottom, left + 2, footer, max(1, box_w - 4), _attr("dim"))
        _safe_addnstr(self.stdscr, bottom, right - 24, "Enter: add  Empty: finish", 23, _attr("dim"))
        self.stdscr.refresh()

    def _capture_paste_block(self):
        lines = []
        current = []
        while True:
            self._draw_paste_box(lines, "".join(current))
            key = self.stdscr.getch()
            if key in (10, 13, curses.KEY_ENTER):
                line = "".join(current).strip()
                if not line:
                    break
                lines.append(line)
                current = []
                continue
            if key in (curses.KEY_BACKSPACE, 127, 8):
                if current:
                    current.pop()
                continue
            if key in (27, curses.KEY_RESIZE):
                continue
            if key == curses.KEY_MOUSE:
                continue
            if 0 <= key <= 255:
                ch = chr(key)
                if ch.isprintable():
                    current.append(ch)
        return lines

    def _should_use_input_box(self, prompt):
        if not prompt:
            return False
        p = prompt.lower()
        return (
            "search query" in p
            or "enter domain" in p
            or "domain" in p and "e.g." in p
            or "timeout" in p
        )

    def _capture_text_input_box(self, prompt):
        try:
            curses.curs_set(1)
        except curses.error:
            pass
        try:
            prefill, clear_on_type = self._parse_input_box_default(prompt)
            buf = list(prefill)
            cleared_prefill = False
            while True:
                self._draw_text_input_box(prompt, "".join(buf))
                key = self.stdscr.getch()
                if key in (10, 13, curses.KEY_ENTER):
                    return "".join(buf)
                if key in (curses.KEY_BACKSPACE, 127, 8):
                    if buf:
                        buf.pop()
                        cleared_prefill = True
                    continue
                if key in (27, curses.KEY_RESIZE):
                    continue
                if key == curses.KEY_MOUSE:
                    if self._handle_input_box_click():
                        return "".join(buf)
                    continue
                if 0 <= key <= 255:
                    ch = chr(key)
                    if ch.isprintable():
                        if clear_on_type and prefill and not cleared_prefill:
                            buf = [ch]
                            cleared_prefill = True
                            continue
                        buf.append(ch)
        finally:
            try:
                curses.curs_set(0)
            except curses.error:
                pass

    def _parse_input_box_default(self, prompt):
        if not prompt:
            return "", False
        match = re.search(r"\[\s*default\s+([^\]]+)\]", prompt, flags=re.IGNORECASE)
        default_value = match.group(1).strip() if match else ""
        clear_on_type = "enter domain" in prompt.lower() and bool(default_value)
        return default_value, clear_on_type

    def _handle_input_box_click(self):
        if not self._input_box_confirm:
            return False
        try:
            _, mx, my, _, bstate = curses.getmouse()
        except Exception:
            return False
        if not (bstate & (curses.BUTTON1_CLICKED | curses.BUTTON1_PRESSED | curses.BUTTON1_RELEASED)):
            return False
        row, start_x, end_x = self._input_box_confirm
        return my == row and start_x <= mx <= end_x

    def _draw_text_input_box(self, prompt, current):
        h, w = self.stdscr.getmaxyx()
        box_h = min(8, max(6, h - 6))
        box_w = min(96, max(42, w - 10))
        top = max(0, (h - box_h) // 2)
        left = max(0, (w - box_w) // 2)
        right = left + box_w - 1

        self.stdscr.erase()
        _draw_box(self.stdscr, top, left, box_h, box_w, " Input ", _attr("section"))
        title = prompt.strip().rstrip(":")
        _safe_addnstr(self.stdscr, top + 1, left + 2, title, box_w - 4, _attr("dim"))
        _safe_hline(self.stdscr, top + 2, left + 1, ord('-'), box_w - 2, _attr("dim"))
        _safe_addnstr(self.stdscr, top + 4, left + 2, current, box_w - 4, _attr("warn", curses.A_BOLD))
        try:
            self.stdscr.move(top + 4, min(right - 1, left + 2 + len(current)))
        except curses.error:
            pass
        footer = "Enter: submit  Esc: ignore"
        _safe_addnstr(self.stdscr, top + box_h - 1, left + 2, footer, box_w - 4, _attr("dim"))
        button = "[Confirm]"
        btn_start = right - len(button) - 2
        btn_end = btn_start + len(button)
        if btn_start > left + 2:
            _safe_addnstr(self.stdscr, top + box_h - 1, btn_start, button, len(button), _attr("section", curses.A_BOLD))
            self._input_box_confirm = (top + box_h - 1, btn_start, btn_end)
        else:
            self._input_box_confirm = None
        self.stdscr.refresh()

    def install(self):
        self._orig_print = builtins.print
        self._orig_input = builtins.input
        self._orig_clear_screen = helpers.clear_screen
        self._orig_no_color = os.environ.get("NO_COLOR")
        os.environ["NO_COLOR"] = "1"
        try:
            import cores.scanner as scanner_core
            scanner_core._COLOR_SUPPORTED = False
        except Exception:
            pass
        builtins.print = self._patched_print
        builtins.input = self._patched_input
        helpers.clear_screen = self._patched_clear_screen
        ui_layout._ANSI_ENABLED = False

    def uninstall(self):
        if self._orig_print is not None:
            builtins.print = self._orig_print
        if self._orig_input is not None:
            builtins.input = self._orig_input
        if self._orig_clear_screen is not None:
            helpers.clear_screen = self._orig_clear_screen
        if self._orig_no_color is None:
            os.environ.pop("NO_COLOR", None)
        else:
            os.environ["NO_COLOR"] = self._orig_no_color


def _mode_label(connection_mode):
    return "White Routing"


def _main_menu_entries(ui_mode):
    return [(key, label) for _section, entries in _main_menu_sections(ui_mode) for key, label, _desc in entries]


def _main_menu_sections(ui_mode):
    return [
        ("Main Actions", [
            ("1", "Scan Targets", "Load IPs, CIDRs, or ASNs, scan ports, and build the dynamic pool."),
            ("2", "Reload Latest Scan", "Load the fastest saved scan results into the dynamic pool."),
            ("3", "Instant Connect", "Verify pasted or file-loaded targets and load usable endpoints."),
            ("4", "Proxy Port", "Change the local listener port."),
            ("5", f"Clear Route Cache", f"Remove cached host routes from {os.path.basename(config.HOSTS_FILE)}."),
            ("6", "Force Reroute Domain", "Ban a bad endpoint for one domain and race it again."),
            ("7", "Inspect IPs", "Look up ASN and network type for pools, cache, or custom targets."),
            ("8", "Auto-Tune Rates", "Tune asyncio, masscan, and nmap rates for this network."),
            ("9", "Routing Rules", "Manage do-not-route and always-route domain policies."),
        ]),
        ("Scanners", [
            ("s", "SOCKS5 Scanner", "Export SOCKS5 proxies without changing routing."),
            ("h", "HTTP Proxy Scanner", "Export HTTP-only proxies without changing routing."),
        ]),
        ("Launch", [
            ("w", "Start White Routing", "Run the proxy using the verified white IP pool."),
        ]),
        ("Navigation", [("0", "Exit", "Close the UI.")]),
    ]


def _status_lines(ui_mode):
    lines = [
        ("UI Mode", "White Routing"),
        ("Conn Mode", _mode_label(config.CONNECTION_MODE)),
        ("Proxy", f"{config.PROXY_HOST}:{config.PROXY_PORT}"),
        ("Local IP", helpers.get_local_ip()),
    ]
    lines.append(("IP Pool", f"{len(config.IP_POOL)} loaded"))
    if config.TUNED_MASSCAN_RATE or config.TUNED_NMAP_MIN_RATE or config.MAX_CONCURRENT_SCANS != 100:
        nmap_disp = f"{config.TUNED_NMAP_MIN_RATE}-{config.TUNED_NMAP_MAX_RATE}" if config.TUNED_NMAP_MIN_RATE else "N/A"
        mass_disp = str(config.TUNED_MASSCAN_RATE) if config.TUNED_MASSCAN_RATE else "N/A"
        lines.append(("Tuning", f"Async={config.MAX_CONCURRENT_SCANS} Masscan={mass_disp} Nmap={nmap_disp}"))
    return lines


def _draw_box(stdscr, top, left, height, width, title=None, attr=0):
    if height < 3 or width < 4:
        return
    right = left + width - 1
    bottom = top + height - 1
    _safe_hline(stdscr, top, left + 1, ord('-'), width - 2, attr)
    _safe_hline(stdscr, bottom, left + 1, ord('-'), width - 2, attr)
    for y in range(top + 1, bottom):
        try:
            stdscr.addch(y, left, ord('|'), attr)
            stdscr.addch(y, right, ord('|'), attr)
        except curses.error:
            pass
    for y, x, ch in ((top, left, '+'), (top, right, '+'), (bottom, left, '+'), (bottom, right, '+')):
        try:
            stdscr.addch(y, x, ord(ch), attr)
        except curses.error:
            pass
    if title:
        _safe_addnstr(stdscr, top, left + 2, f" {title} ", max(1, width - 4), _attr("title", curses.A_BOLD))


def _draw_main_screen(stdscr, ui_mode, selected_idx):
    stdscr.erase()
    h, w = stdscr.getmaxyx()
    if h <= 1 or w <= 1:
        stdscr.refresh()
        return []

    if h < 15 or w < 58:
        _safe_addnstr(stdscr, 0, 0, "Terminal is too small. Resize to at least 58x15.", w - 1, _attr("warn", curses.A_BOLD))
        stdscr.refresh()
        return []

    title = f"IROpenRelayFinder v{config.VERSION}"
    mode = "White Routing Workspace"
    _safe_addnstr(stdscr, 0, 2, title, w - 4, _attr("title", curses.A_BOLD))
    _safe_addnstr(stdscr, 1, 2, mode, w - 4, _attr("accent", curses.A_BOLD))
    _safe_hline(stdscr, 2, 0, ord('-'), w - 1, _attr("dim"))

    status_w = min(36, max(24, w // 3))
    menu_left = status_w + 2
    menu_w = w - menu_left - 1
    body_top = 4
    body_h = h - 7

    _draw_box(stdscr, body_top, 0, body_h, status_w, "Status", _attr("dim"))
    row = body_top + 2
    for label, value in _status_lines(ui_mode):
        if row >= body_top + body_h - 1:
            break
        _safe_addnstr(stdscr, row, 2, f"{label}:", status_w - 4, _attr("section", curses.A_BOLD))
        _safe_addnstr(stdscr, row + 1, 2, str(value), status_w - 4)
        row += 3

    _draw_box(stdscr, body_top, menu_left, body_h, menu_w, "Actions", _attr("dim"))

    option_map = []
    flat_index = 0
    row = body_top + 2
    for section, entries in _main_menu_sections(ui_mode):
        if row >= body_top + body_h - 2:
            break
        _safe_addnstr(stdscr, row, menu_left + 2, section.upper(), menu_w - 4, _attr("section", curses.A_BOLD))
        row += 1
        for key, label, desc in entries:
            if row >= body_top + body_h - 1:
                break
            selected = flat_index == selected_idx
            attr = _attr("selected", curses.A_REVERSE) if selected else 0
            line = f" {key.upper():>2}  {label}"
            desc_text = f" - {desc}" if menu_w >= 70 else ""
            text = f"{line}{desc_text}"
            _safe_addnstr(stdscr, row, menu_left + 2, text, menu_w - 4, attr)
            option_map.append((row, menu_left + 1, menu_left + menu_w - 2, key, flat_index))
            row += 1
            flat_index += 1
        row += 1

    footer = "Up/Down or Tab: move | Enter: select | key: direct action | mouse: click | q/0: exit/back"
    _safe_hline(stdscr, h - 3, 0, ord('-'), w - 1, _attr("dim"))
    _safe_addnstr(stdscr, h - 2, 2, footer, w - 4, _attr("dim"))
    selected_entries = _main_menu_entries(ui_mode)
    if selected_entries:
        key, label = selected_entries[max(0, min(selected_idx, len(selected_entries) - 1))]
        _safe_addnstr(stdscr, h - 1, 2, f"Selected: {key.upper()} - {label}", w - 4, _attr("accent", curses.A_BOLD))
    stdscr.refresh()
    return option_map


def _get_main_choice(stdscr, ui_mode):
    entries = _main_menu_entries(ui_mode)
    if not entries:
        return "0"
    selected_idx = 0
    allowed = {key for key, _ in entries}
    while True:
        selected_idx = max(0, min(selected_idx, len(entries) - 1))
        option_map = _draw_main_screen(stdscr, ui_mode, selected_idx)
        ch = stdscr.getch()
        if ch == curses.KEY_MOUSE:
            try:
                _, mx, my, _, bstate = curses.getmouse()
            except Exception:
                continue
            if not (bstate & (curses.BUTTON1_CLICKED | curses.BUTTON1_PRESSED | curses.BUTTON1_RELEASED)):
                continue
            for row, start_x, end_x, key, idx in option_map:
                if my == row and start_x <= mx <= end_x:
                    selected_idx = idx
                    return key
            continue

        if ch in (curses.KEY_UP, ord('k')):
            selected_idx = (selected_idx - 1) % len(entries)
            continue
        if ch in (curses.KEY_DOWN, ord('j'), 9):
            selected_idx = (selected_idx + 1) % len(entries)
            continue
        if ch in (curses.KEY_HOME,):
            selected_idx = 0
            continue
        if ch in (curses.KEY_END,):
            selected_idx = len(entries) - 1
            continue
        if ch in (10, 13, curses.KEY_ENTER):
            return entries[selected_idx][0]
        if ch in (27, curses.KEY_RESIZE):
            continue
        if 0 <= ch <= 255:
            key = chr(ch).lower()
            if key == "q":
                return "0"
            if key in allowed:
                return key


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

    def launch_relay_finder():
        APP_SERVICE.set_connection_mode("white_ip", persist=True)
        import cores.white_core as proxy_core
        try:
            execute_core(proxy_core)
        except KeyboardInterrupt:
            pass

    def show_message_screen(title, lines, tone="section"):
        ui_layout.draw_header(ui_mode="white")
        ui_layout.print_section(title, tone=tone)
        for line in lines:
            print(line)
        ui_prompts.pause("\nPress Enter to continue...", action_label="Continue")

    def menu_change_proxy_port():
        ui_layout.draw_header(ui_mode="white")
        ui_layout.print_section("CHANGE PROXY PORT")
        print(f" Current: {config.PROXY_HOST}:{config.PROXY_PORT}")
        print(" Enter a value between 1 and 65535.")
        raw = input(" New port (blank to cancel): ").strip()
        if not raw:
            return
        if raw.isdigit() and 1 <= int(raw) <= 65535:
            APP_SERVICE.set_proxy_port(int(raw))
            show_message_screen("PROXY PORT", [f"[+] Proxy port changed to {raw}."])
            return
        show_message_screen("PROXY PORT", ["[-] Invalid port number."], tone="err")

    def run_curses(stdscr):
        _init_curses_ui()
        stdscr.keypad(True)
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        APP_SERVICE.set_connection_mode("white_ip", persist=False)

        console = _CursesConsole(stdscr)
        console.install()
        try:
            while True:
                try:
                    curses.curs_set(0)
                    choice = _get_main_choice(stdscr, "white")

                    if choice == "1":
                        ui_scan.menu_scan()
                    elif choice == "2":
                        ui_scan.menu_manage_pool()
                    elif choice == "3":
                        ui_scan.menu_instant_connect()
                    elif choice == "4":
                        menu_change_proxy_port()
                    elif choice == "5":
                        cleared = APP_SERVICE.clear_route_cache()
                        if cleared:
                            show_message_screen("ROUTE CACHE", ["[+] Cache cleared successfully."])
                        else:
                            show_message_screen("ROUTE CACHE", ["[-] Cache already empty."], tone="warn")
                    elif choice == "6":
                        ui_tools.menu_reroute_domain()
                    elif choice == "7":
                        ui_tools.menu_inspect_ips()
                    elif choice == "8":
                        import cores.autotuner as autotuner_core
                        execute_core(autotuner_core)
                    elif choice == "9":
                        ui_tools.menu_manage_route_rules()
                    elif choice == "s":
                        import cores.socks5_scanner as socks5_scanner_core
                        execute_core(socks5_scanner_core)
                    elif choice == "h":
                        import cores.http_scanner as http_scanner_core
                        execute_core(http_scanner_core)
                    elif choice == "w":
                        launch_relay_finder()
                    elif choice == "0":
                        helpers.clear_screen()
                        print("[*] Shutting down...")
                        time.sleep(0.5)
                        break
                except KeyboardInterrupt:
                    pass
        finally:
            console.uninstall()

    curses.wrapper(run_curses)


if __name__ == "__main__":
    main()
