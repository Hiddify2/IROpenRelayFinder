import json
import os
import tempfile


_PERMISSIVE_ROUTE_FILES = {"white_routes.txt", "banned_routes.txt"}


def _should_force_permissive_mode(path):
    return os.path.basename(path) in _PERMISSIVE_ROUTE_FILES


def _force_permissive_mode(path):
    if not _should_force_permissive_mode(path):
        return
    try:
        os.chmod(path, 0o666)
    except OSError:
        pass


def read_text_lines(path, encoding="utf-8"):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding=encoding) as f:
        return [line.rstrip("\n") for line in f]


def append_line(path, line, encoding="utf-8"):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding=encoding) as f:
        if line.endswith("\n"):
            f.write(line)
        else:
            f.write(f"{line}\n")
    _force_permissive_mode(path)


def atomic_write_text(path, content, encoding="utf-8"):
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".tmp_", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as tmp:
            tmp.write(content)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.replace(temp_path, path)
        _force_permissive_mode(path)
    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass


def atomic_write_json(path, payload, indent=4):
    atomic_write_text(path, json.dumps(payload, indent=indent), encoding="utf-8")


def read_json(path, default=None):
    if not os.path.exists(path):
        return default
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
