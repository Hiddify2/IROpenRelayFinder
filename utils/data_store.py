import os
import shutil

from utils import paths
from utils import storage


def read_path(filename):
    modern = paths.data_path(filename)
    legacy = paths.legacy_path(filename)
    if os.path.exists(modern):
        return modern
    if os.path.exists(legacy):
        return legacy
    return modern


def write_path(filename, migrate_legacy=True):
    modern = paths.data_path(filename)
    legacy = paths.legacy_path(filename)

    if migrate_legacy and (not os.path.exists(modern)) and os.path.exists(legacy):
        try:
            shutil.copy2(legacy, modern)
        except OSError:
            pass

    return modern


def read_lines(filename, encoding="utf-8"):
    return storage.read_text_lines(read_path(filename), encoding=encoding)


def read_json(filename, default=None):
    return storage.read_json(read_path(filename), default=default)


def append_line(filename, line, encoding="utf-8"):
    storage.append_line(write_path(filename), line, encoding=encoding)


def write_json(filename, payload, indent=4):
    storage.atomic_write_json(write_path(filename), payload, indent=indent)


def write_text(filename, content, encoding="utf-8"):
    storage.atomic_write_text(write_path(filename), content, encoding=encoding)
