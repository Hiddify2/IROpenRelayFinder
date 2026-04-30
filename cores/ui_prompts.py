from __future__ import annotations

from typing import Iterable

import cores.ui_layout as ui_layout
import utils.data_store as data_store


_PREFS_FILE = "scanner_ui_prefs.json"


def _load_prefs():
    data = data_store.read_json(_PREFS_FILE, default={})
    if isinstance(data, dict):
        return data
    return {}


def _save_prefs(prefs):
    data_store.write_json(_PREFS_FILE, prefs, indent=2)


def get_pref(key, default=None):
    prefs = _load_prefs()
    return prefs.get(key, default)


def set_pref(key, value):
    prefs = _load_prefs()
    prefs[key] = value
    _save_prefs(prefs)


def pause(message="Press Enter to continue..."):
    input(message)


def read_multiline(prompt="Paste entries (empty line to finish):"):
    print(prompt)
    lines = []
    while True:
        line = input().strip()
        if not line:
            break
        lines.append(line)
    return lines


def prompt_yes_no(prompt, default=False, remember_key=None):
    if remember_key is not None:
        default = bool(get_pref(remember_key, default))
    hint = "Y/n" if default else "y/N"
    raw = input(f"{prompt} ({hint}): ").strip().lower()
    if not raw:
        value = default
    else:
        value = raw in {"y", "yes"}
    if remember_key is not None:
        set_pref(remember_key, bool(value))
    return value


def prompt_int(prompt, default, min_value=1, remember_key=None):
    if remember_key is not None:
        saved = get_pref(remember_key, default)
        if isinstance(saved, int) and saved >= min_value:
            default = saved
    raw = input(f"{prompt} [Default {default}]: ").strip()
    if not raw:
        value = default
    elif raw.isdigit():
        value = int(raw)
        if value < min_value:
            ui_layout.print_warn(f"Invalid number. Using default: {default}")
            value = default
    else:
        ui_layout.print_warn(f"Invalid number. Using default: {default}")
        value = default
    if remember_key is not None:
        set_pref(remember_key, int(value))
    return value


def prompt_float(prompt, default, min_value=0.1, remember_key=None):
    if remember_key is not None:
        saved = get_pref(remember_key, default)
        if isinstance(saved, (int, float)) and float(saved) >= min_value:
            default = float(saved)
    raw = input(f"{prompt} [Default {default}]: ").strip()
    if not raw:
        value = default
    else:
        try:
            value = float(raw)
            if value < min_value:
                raise ValueError
        except Exception:
            ui_layout.print_warn(f"Invalid number. Using default: {default}")
            value = default
    if remember_key is not None:
        set_pref(remember_key, float(value))
    return value


def menu_choice(
    title: str,
    options: Iterable[tuple[str, str, str | None]],
    *,
    default: str | None = None,
    prompt: str = "Choice",
    tone: str = "section",
    remember_key: str | None = None,
):
    """
    Display a normalized menu and return a valid normalized key.
    options: iterable of (key, label, hint_or_none)
    """
    normalized = []
    keys = set()
    for key, label, hint in options:
        k = str(key).strip().lower()
        normalized.append((k, label, hint))
        keys.add(k)

    if remember_key is not None:
        saved = str(get_pref(remember_key, default)).strip().lower() if get_pref(remember_key, default) is not None else None
        if saved in keys:
            default = saved

    while True:
        ui_layout.print_section(title, tone=tone)
        for key, label, hint in normalized:
            text = f" [{key}] {label}"
            if hint:
                text = f"{text}  {ui_layout.color_text('- ' + hint, 'dim')}"
            print(text)

        default_hint = f" [Default {default}]" if default else ""
        raw = input(f"\n{prompt}{default_hint}: ").strip().lower()
        if not raw and default is not None:
            chosen = default.lower()
        elif raw in keys:
            chosen = raw
        else:
            ui_layout.print_warn("Invalid choice. Please select one of the listed options.")
            continue
        if remember_key is not None:
            set_pref(remember_key, chosen)
        return chosen
