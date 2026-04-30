"""Packaged executable self-check used by CI."""

import importlib
import os

from utils import paths
from utils import storage


CORE_MODULES = [
    "adaptive_throttle",
    "autotuner",
    "http_scanner",
    "scanner",
    "smoke",
    "socks5_scanner",
    "ui",
    "ui_asn",
    "ui_layout",
    "ui_scan",
    "ui_tools",
    "white_core",
]

UTIL_MODULES = [
    "app_service",
    "asn_engine",
    "config",
    "data_store",
    "helpers",
    "paths",
    "route_manager",
    "route_service",
    "runtime_state",
    "scan_service",
    "storage",
    "workers",
]

DATA_FILES = [
    ("assets", "cf-domains.txt"),
    ("IranASNs", "filtered_ipv4.csv"),
    ("IranASNs", "filtered_ipv6.csv"),
]


def _check_imports(package, module_names):
    for module_name in module_names:
        importlib.import_module(f"{package}.{module_name}")


def _check_data_files():
    missing = []
    for parts in DATA_FILES:
        path = paths.root_path(*parts)
        if not os.path.exists(path):
            missing.append(os.path.join(*parts))
    if missing:
        raise RuntimeError(f"Missing packaged data files: {', '.join(missing)}")


def _check_writable_runtime_dirs():
    data_probe = paths.data_path("tmp", ".package_check")
    archive_probe = paths.archive_path("tmp", ".package_check")

    storage.atomic_write_text(data_probe, "ok\n")
    storage.atomic_write_text(archive_probe, "ok\n")

    for path in (data_probe, archive_probe):
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    _check_imports("utils", UTIL_MODULES)
    _check_imports("cores", CORE_MODULES)
    _check_data_files()
    _check_writable_runtime_dirs()
    print("[+] Package self-check passed.")


if __name__ == "__main__":
    main()
