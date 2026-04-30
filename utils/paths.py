import os
import re
import sys
from datetime import datetime


APP_DIR_NAME = "iropen-relay-finder"
ENV_HOME = "IRORF_HOME"
ENV_DATA_DIR = "IRORF_DATA_DIR"
ENV_ARCHIVE_DIR = "IRORF_ARCHIVE_DIR"


def _is_packaged():
    return bool(
        getattr(sys, "frozen", False)
        or "__compiled__" in globals()
        or hasattr(sys.modules.get("__main__"), "__compiled__")
    )


def _bundle_root():
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def project_root():
    """Return the source tree root, or the onefile extraction root when packaged."""
    return _bundle_root()


def root_path(*parts):
    """Path to bundled read-only files shipped with the app."""
    return os.path.join(project_root(), *parts)


def _executable_dir():
    candidate = sys.argv[0] if sys.argv and sys.argv[0] else sys.executable
    if candidate and candidate not in ("-c", "-m"):
        return os.path.dirname(os.path.abspath(candidate))
    return os.getcwd()


def _user_data_home():
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        return os.path.join(base, APP_DIR_NAME)
    if sys.platform == "darwin":
        return os.path.expanduser(os.path.join("~", "Library", "Application Support", APP_DIR_NAME))
    base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser(os.path.join("~", ".local", "share"))
    return os.path.join(base, APP_DIR_NAME)


def _dir_is_writable(path):
    if not os.path.isdir(path):
        return False
    if not os.access(path, os.W_OK | os.X_OK):
        return False
    try:
        import tempfile

        fd, probe = tempfile.mkstemp(prefix=".write_check_", dir=path)
        os.close(fd)
        os.remove(probe)
        return True
    except OSError:
        return False


def runtime_root():
    """Return the persistent writable root for generated app files."""
    override = os.environ.get(ENV_HOME)
    if override:
        return os.path.abspath(os.path.expanduser(override))

    if not _is_packaged():
        return project_root()

    exe_dir = _executable_dir()
    if _dir_is_writable(exe_dir):
        return exe_dir
    return _user_data_home()


def runtime_path(*parts):
    return os.path.join(runtime_root(), *parts)


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def _managed_dir(env_var, default_name):
    override = os.environ.get(env_var)
    return ensure_dir(
        os.path.abspath(os.path.expanduser(override)) if override else runtime_path(default_name)
    )


def _managed_file_path(base, parts):
    if not parts:
        return base
    path = os.path.join(base, *parts)
    parent = os.path.dirname(path)
    if parent and parent != base:
        ensure_dir(parent)
    return path


def data_path(*parts):
    base = _managed_dir(ENV_DATA_DIR, "data")
    return _managed_file_path(base, parts)


def archive_path(*parts):
    base = _managed_dir(ENV_ARCHIVE_DIR, "cyclic_archives")
    return _managed_file_path(base, parts)


def legacy_path(filename):
    return runtime_path(filename)


def first_existing(*candidates):
    for path in candidates:
        if path and os.path.exists(path):
            return path
    return candidates[0] if candidates else None


def list_scan_files(include_cyclic=False):
    canonical_data = data_path()
    search_roots = [canonical_data, runtime_root()]
    files_by_name = {}

    for root in search_roots:
        try:
            names = os.listdir(root)
        except OSError:
            continue

        for name in names:
            if not (name.startswith("scan_") and name.endswith(".json")):
                continue
            if not include_cyclic and name.startswith("scan_cyclic"):
                continue
            full = os.path.join(root, name)
            # Prefer the canonical data/ copy when both data/ and legacy root exist.
            if name not in files_by_name or root == canonical_data:
                files_by_name[name] = full

    pattern = re.compile(r"^scan_(\d{8}_\d{6})\.json$")

    def sort_key(path):
        name = os.path.basename(path)
        match = pattern.match(name)
        if match:
            return (1, match.group(1))
        return (0, name)

    return sorted(files_by_name.values(), key=sort_key, reverse=True)


def latest_scan_file(include_cyclic=False):
    files = list_scan_files(include_cyclic=include_cyclic)
    return files[0] if files else None


def timestamped_scan_filename(prefix="scan"):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return data_path(f"{prefix}_{ts}.json")
