"""
CA-cert lifecycle for MMDF (Man-in-the-Middle + Domain Fronting).

MMDF intercepts client TLS, presents an "instant" leaf certificate signed by a
locally-generated CA, then re-encrypts outbound to the real target IP using a
fronting SNI. For the client to trust the leaf cert, the local CA must be
installed in the OS / browser trust store. This module:

  * generates the CA key + cert on first use
  * persists them in the runtime data directory
  * provides OS-specific install / detection (mac / windows / linux)

Two cert backends are supported transparently — whichever is available wins:

  * ``cryptography`` (preferred): pure-Python x509, no fork overhead per leaf.
  * ``openssl`` CLI (fallback): zero Python deps, slightly slower (one
    subprocess per fresh SNI; results are disk-cached).

If neither is present, MMDF stays disabled and the proxy falls back to the
normal (non-fronted) routing path for Meet/YouTube/etc.
"""
import datetime
import glob
import functools
import importlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile

from utils import data_store

CA_COMMON_NAME = "IROpenRelayFinder MMDF Root CA"
CA_CERT_FILENAME = "mmdf_ca.crt"
CA_KEY_FILENAME = "mmdf_ca.key"
CA_FINGERPRINT_FILENAME = "mmdf_ca.sha1"
NSS_NICKNAME = "IROpenRelayFinder MMDF CA"


def ca_cert_path():
    return data_store.write_path(CA_CERT_FILENAME)


def ca_key_path():
    return data_store.write_path(CA_KEY_FILENAME)


def _ca_fingerprint_cache_path():
    return data_store.write_path(CA_FINGERPRINT_FILENAME)


def openssl_available():
    return shutil.which("openssl") is not None


@functools.lru_cache(maxsize=1)
def _cryptography_import_check():
    try:
        importlib.import_module("cryptography")
        importlib.import_module("cryptography.x509")
        importlib.import_module("cryptography.hazmat.primitives")
        importlib.import_module("cryptography.hazmat.primitives.asymmetric")
        importlib.import_module("cryptography.x509.oid")
        return True, None
    except Exception as exc:
        return False, repr(exc)


def cryptography_available():
    return _cryptography_import_check()[0]


def cryptography_import_error():
    return _cryptography_import_check()[1]


def select_backend():
    """Return the preferred cert backend: 'cryptography', 'openssl', or None.

    cryptography is preferred when present (no fork-per-leaf overhead);
    openssl CLI is the zero-dep fallback.
    """
    if cryptography_available():
        return "cryptography"
    if openssl_available():
        return "openssl"
    return None


def any_backend_available():
    return select_backend() is not None


def ca_files_exist():
    return os.path.exists(ca_cert_path()) and os.path.exists(ca_key_path())


def _run(cmd, check=False, **kwargs):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check, **kwargs)
    except FileNotFoundError:
        return None
    except subprocess.CalledProcessError as e:
        return e


def _generate_ca_files():
    """Create a self-signed CA key + cert. Dispatches to the active backend.

    The CA must have keyCertSign + cRLSign so per-connection leaf certs
    chain validly to it.
    """
    backend = select_backend()
    if backend is None:
        raise RuntimeError(
            "No cert backend available. Install one of: "
            "Python `cryptography` (pip install cryptography) "
            "or the OpenSSL CLI (apt/brew/choco install openssl)."
        )

    cert_path = ca_cert_path()
    key_path = ca_key_path()
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)

    if backend == "cryptography":
        _generate_ca_cryptography(cert_path, key_path)
    else:
        _generate_ca_openssl(cert_path, key_path)

    try:
        os.chmod(key_path, 0o600)
    except Exception:
        pass

    fp_cache = _ca_fingerprint_cache_path()
    if os.path.exists(fp_cache):
        try:
            os.remove(fp_cache)
        except OSError:
            pass


def _generate_ca_cryptography(cert_path, key_path):
    from cryptography import x509  # type: ignore[import-not-found]
    from cryptography.hazmat.primitives import hashes, serialization  # type: ignore[import-not-found]
    from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore[import-not-found]
    from cryptography.x509.oid import NameOID  # type: ignore[import-not-found]

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IROpenRelayFinder"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )


def _generate_ca_openssl(cert_path, key_path):
    cmd = [
        "openssl", "req", "-x509",
        "-newkey", "rsa:3072",
        "-sha256",
        "-days", "3650",
        "-nodes",
        "-keyout", key_path,
        "-out", cert_path,
        "-subj", f"/CN={CA_COMMON_NAME}/O=IROpenRelayFinder",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    ]
    res = _run(cmd)
    if res is None or res.returncode != 0:
        raise RuntimeError(
            f"openssl CA generation failed: {(res.stderr or res.stdout or '').strip() if res else 'no output'}"
        )


def ensure_ca_files():
    """Generate the CA on demand. Returns (cert_path, key_path)."""
    if not ca_files_exist():
        _generate_ca_files()
    return ca_cert_path(), ca_key_path()


# --------------------------------------------------------------------- detection

def _read_cert_fingerprint(cert_path):
    """Return the SHA1 fingerprint of a PEM cert as upper-case hex."""
    if not os.path.exists(cert_path):
        return None
    if cryptography_available():
        try:
            from cryptography import x509  # type: ignore[import-not-found]
            from cryptography.hazmat.primitives import hashes  # type: ignore[import-not-found]
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            return cert.fingerprint(hashes.SHA1()).hex().upper()
        except Exception:
            pass
    if openssl_available():
        res = _run(["openssl", "x509", "-in", cert_path, "-noout", "-fingerprint", "-sha1"])
        if res is None or res.returncode != 0:
            return None
        line = (res.stdout or "").strip()
        if "=" in line:
            return line.split("=", 1)[1].strip().replace(":", "").upper()
    return None


def is_ca_installed():
    """Best-effort check that our CA cert is in the OS / browser trust store.

    Returns True if confirmed installed, False if confirmed missing,
    None if we cannot tell (e.g. tools unavailable).
    """
    if not ca_files_exist():
        return False

    fp = _read_cert_fingerprint(ca_cert_path())
    sysplat = sys.platform

    if sysplat.startswith("linux"):
        for store in (
            "/usr/local/share/ca-certificates/iropenrelayfinder-mmdf-ca.crt",
            "/etc/ca-certificates/trust-source/anchors/iropenrelayfinder-mmdf-ca.crt",
            "/etc/pki/ca-trust/source/anchors/iropenrelayfinder-mmdf-ca.crt",
        ):
            if os.path.exists(store):
                return True
        for nss_db in _candidate_nss_dbs():
            if _nss_has_cert(nss_db):
                return True
        return False

    if sysplat == "darwin":
        if not fp:
            return None
        result = _run(["security", "find-certificate", "-c", CA_COMMON_NAME, "-Z",
                       "/Library/Keychains/System.keychain"])
        if result is None:
            return None
        if result.returncode != 0:
            return False
        haystack = (result.stdout or "").replace(":", "").lower()
        return fp.lower() in haystack

    if sysplat == "win32":
        if not fp:
            return None
        result = _run(["certutil", "-store", "Root"])
        if result is None:
            return None
        if result.returncode != 0:
            return None
        haystack = (result.stdout or "").replace(" ", "").replace("\t", "").lower()
        return fp.lower() in haystack

    return None


# --------------------------------------------------------- NSS DB (Linux browsers)

def _candidate_nss_dbs():
    home = os.path.expanduser("~")
    candidates = set()

    chrome = os.path.join(home, ".pki", "nssdb")
    if os.path.isdir(chrome):
        candidates.add(chrome)

    for ff_root in (
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "snap", "firefox", "common", ".mozilla", "firefox"),
        os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla", "firefox"),
    ):
        if not os.path.isdir(ff_root):
            continue
        for prof in glob.glob(os.path.join(ff_root, "*")):
            if not os.path.isdir(prof):
                continue
            if os.path.exists(os.path.join(prof, "cert9.db")) or os.path.exists(os.path.join(prof, "cert8.db")):
                candidates.add(prof)

    return sorted(candidates)


def _nss_db_uri(path):
    if os.path.exists(os.path.join(path, "cert9.db")):
        return f"sql:{path}"
    return path


def _nss_has_cert(db_path):
    if shutil.which("certutil") is None:
        return False
    res = _run(["certutil", "-d", _nss_db_uri(db_path), "-L", "-n", NSS_NICKNAME])
    return bool(res and res.returncode == 0)


def _nss_install_into(db_path, cert_path):
    if shutil.which("certutil") is None:
        return False, "certutil missing (install libnss3-tools)"
    db_uri = _nss_db_uri(db_path)
    _run(["certutil", "-d", db_uri, "-D", "-n", NSS_NICKNAME])
    res = _run([
        "certutil", "-d", db_uri, "-A", "-t", "C,,", "-n", NSS_NICKNAME, "-i", cert_path,
    ])
    if res is None:
        return False, "certutil invocation failed"
    if res.returncode == 0:
        return True, None
    return False, (res.stderr or res.stdout or "").strip()


def _install_into_all_nss_dbs(cert_path):
    installed = []
    errors = []
    for db in _candidate_nss_dbs():
        ok, err = _nss_install_into(db, cert_path)
        if ok:
            installed.append(db)
        else:
            errors.append((db, err))
    return installed, errors


# ----------------------------------------------------------------------- install

def _is_admin():
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def install_ca():
    """Install the local CA into the OS trust store. Generates the CA if missing.

    Returns a dict: {ok, message, requires_elevation?}
    """
    if not any_backend_available():
        return {
            "ok": False,
            "message": "No cert backend found. Install Python `cryptography` (pip install cryptography) "
                       "or the OpenSSL CLI (apt/brew/choco install openssl).",
        }

    try:
        cert_path, _ = ensure_ca_files()
    except Exception as e:
        return {"ok": False, "message": f"Could not generate CA: {e}"}

    sysplat = sys.platform
    if sysplat.startswith("linux"):
        return _install_linux(cert_path)
    if sysplat == "darwin":
        return _install_macos(cert_path)
    if sysplat == "win32":
        return _install_windows(cert_path)
    return {"ok": False, "message": f"Unsupported platform: {sysplat}"}


def _install_linux(cert_path):
    targets = []
    if os.path.isdir("/usr/local/share/ca-certificates"):
        targets.append((
            "/usr/local/share/ca-certificates/iropenrelayfinder-mmdf-ca.crt",
            ["update-ca-certificates"],
        ))
    if os.path.isdir("/etc/pki/ca-trust/source/anchors"):
        targets.append((
            "/etc/pki/ca-trust/source/anchors/iropenrelayfinder-mmdf-ca.crt",
            ["update-ca-trust", "extract"],
        ))
    if os.path.isdir("/etc/ca-certificates/trust-source/anchors"):
        targets.append((
            "/etc/ca-certificates/trust-source/anchors/iropenrelayfinder-mmdf-ca.crt",
            ["trust", "extract-compat"],
        ))

    sys_failure = None
    if not targets:
        sys_failure = (
            "No supported trust store directory found "
            "(/usr/local/share/ca-certificates, /etc/pki/ca-trust/source/anchors, "
            "or /etc/ca-certificates/trust-source/anchors)."
        )
    else:
        cmds = []
        for dest, refresh in targets:
            cmds.append(["cp", cert_path, dest])
            cmds.append(refresh)

        if _is_admin():
            for cmd in cmds:
                res = _run(cmd)
                if res is None or res.returncode != 0:
                    stderr = (res.stderr or "").strip() if res else ""
                    sys_failure = f"Command failed ({' '.join(cmd)}): {stderr}"
                    break
        elif shutil.which("sudo") is None:
            sys_failure = (
                "Root privileges required for system trust store. Manual: "
                f"sudo cp '{cert_path}' " + targets[0][0] + " && sudo " + " ".join(targets[0][1])
            )
        else:
            script_lines = [" ".join(_shell_quote(p) for p in cmd) for cmd in cmds]
            res = _run(["sudo", "sh", "-c", " && ".join(script_lines)])
            if res is None:
                sys_failure = "sudo not available"
            elif res.returncode != 0:
                sys_failure = f"sudo install failed: {(res.stderr or res.stdout or '').strip()}"

    nss_paths, nss_errs = _install_into_all_nss_dbs(cert_path)

    msg_parts = []
    overall_ok = sys_failure is None or bool(nss_paths)

    if sys_failure is None:
        msg_parts.append("System trust store: installed.")
    else:
        msg_parts.append(f"System trust store: FAILED ({sys_failure}).")

    if nss_paths:
        msg_parts.append(
            "Browser NSS DBs updated: " + ", ".join(_friendly_nss_label(p) for p in nss_paths) + "."
        )
    elif _candidate_nss_dbs():
        if shutil.which("certutil") is None:
            msg_parts.append(
                "Browser NSS DBs detected but `certutil` is missing. "
                "Install with: sudo apt install libnss3-tools (or your distro's equivalent)."
            )
        else:
            details = "; ".join(f"{_friendly_nss_label(p)}: {e}" for p, e in nss_errs)
            msg_parts.append(f"Browser NSS DBs FAILED: {details}")
    else:
        msg_parts.append("No browser NSS DBs found (browsers may already be using the system store).")

    msg_parts.append("Restart your browser so it picks up the new trusted root.")
    return {"ok": overall_ok, "message": " ".join(msg_parts)}


def _friendly_nss_label(path):
    home = os.path.expanduser("~")
    rel = path[len(home):] if path.startswith(home) else path
    if "firefox" in rel:
        return f"Firefox ({os.path.basename(path)})"
    if rel.endswith("/.pki/nssdb") or rel == "/.pki/nssdb":
        return "Chrome/Chromium"
    return rel


def _install_macos(cert_path):
    cmd = [
        "security", "add-trusted-cert", "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain", cert_path,
    ]
    if _is_admin():
        res = _run(cmd)
    else:
        if shutil.which("sudo") is None:
            return {
                "ok": False,
                "requires_elevation": True,
                "message": f"Run manually with admin: sudo {' '.join(cmd)}",
            }
        res = _run(["sudo"] + cmd)
    if res is None:
        return {"ok": False, "message": "Could not invoke 'security' tool."}
    if res.returncode == 0:
        return {"ok": True, "message": "CA installed into System keychain."}
    return {"ok": False, "message": f"security failed: {(res.stderr or res.stdout or '').strip()}"}


def _install_windows(cert_path):
    cmd = ["certutil", "-addstore", "-f", "Root", cert_path]
    res = _run(cmd)
    if res is None:
        return {"ok": False, "message": "certutil not found on PATH."}
    if res.returncode == 0:
        return {"ok": True, "message": "CA added to 'Trusted Root Certification Authorities'."}
    if not _is_admin():
        return {
            "ok": False,
            "requires_elevation": True,
            "message": (
                "Administrator rights required. Re-run as Administrator, or import manually:\n"
                f"  certutil -addstore -f Root \"{cert_path}\""
            ),
        }
    return {"ok": False, "message": f"certutil failed: {(res.stderr or res.stdout or '').strip()}"}


def _shell_quote(s):
    if not s:
        return "''"
    safe = "@%+=:,./-_"
    if all(c.isalnum() or c in safe for c in s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


# ----------------------------------------------------------------------- summary

def status_summary():
    """Returns a dict suitable for UI display."""
    summary = {
        "openssl": openssl_available(),
        "cryptography": cryptography_available(),
        "cryptography_error": cryptography_import_error(),
        "backend": select_backend(),
        "ca_files_present": ca_files_exist(),
        "cert_path": ca_cert_path(),
        "key_path": ca_key_path(),
        "platform": platform.system(),
        "is_installed": None,
    }
    if summary["ca_files_present"]:
        try:
            summary["is_installed"] = is_ca_installed()
        except Exception:
            summary["is_installed"] = None
    return summary
