"""
MMDF (Man-in-the-Middle + Domain Fronting) engine.

Adapted from https://github.com/patterniha/MMDF (v5 of the technique). The
trojan transport layer is dropped, only the "instant certificate" TLS-MITM
core remains, wired into white-proxy's routing engine.

Per connection:
  1. The client opens TLS to the real target hostname (Meet, YouTube, ...).
     We terminate that TLS using a leaf cert generated on the fly and signed
     by the local MMDF CA — the client trusts it because the CA is in the
     OS / browser trust store.
  2. We open a *new* TLS connection out to the target's edge fleet using a
     real sibling hostname as SNI (e.g. ``www.google.com`` for any Google
     service). The DPI/SNI filter only sees the front SNI in the outbound
     ClientHello and lets the connection through; the edge accepts because
     it serves the front cert; the inner HTTP Host header routes to the
     real service.
  3. We pump cleartext bytes back and forth between the two TLS endpoints.

Key contract: the outbound SNI must be a *real* hostname served by the same
edge fleet — random fake SNIs do not work because the edge has no cert for
them and either closes the connection or serves a default vhost.
"""
import asyncio
import os
import ssl
import struct
import subprocess
import threading

from utils import config


_INSTANT_CTX = None
_INSTANT_CTX_ERR = None
_CTX_LOCK = threading.Lock()


# --- TLS ClientHello SNI / ALPN parsing ------------------------------------

def _parse_ext(buf: bytes, ext_id: int):
    """Yield (offset_into_extension_data, ext_size) for the requested ext."""
    try:
        if len(buf) < 43 or buf[0] != 0x16:
            return None, 0
        session_id_len = buf[43]
        offset = 44 + session_id_len
        if offset + 2 > len(buf):
            return None, 0
        cipher_suites_len = struct.unpack("!H", buf[offset:offset + 2])[0]
        offset += 2 + cipher_suites_len
        if offset + 1 > len(buf):
            return None, 0
        comp_methods_len = buf[offset]
        offset += 1 + comp_methods_len
        if offset + 2 > len(buf):
            return None, 0
        ext_len = struct.unpack("!H", buf[offset:offset + 2])[0]
        offset += 2
        end = min(offset + ext_len, len(buf))
        while offset + 4 <= end:
            ext_type = struct.unpack("!H", buf[offset:offset + 2])[0]
            ext_size = struct.unpack("!H", buf[offset + 2:offset + 4])[0]
            offset += 4
            if ext_type == ext_id:
                return offset, ext_size
            offset += ext_size
    except Exception:
        return None, 0
    return None, 0


def _parse_sni_from_client_hello(buf: bytes):
    offset, _size = _parse_ext(buf, 0)
    if offset is None:
        return None
    try:
        if offset + 5 > len(buf):
            return None
        name_len = struct.unpack("!H", buf[offset + 3:offset + 5])[0]
        name_start = offset + 5
        return buf[name_start:name_start + name_len].decode("utf-8", errors="ignore")
    except Exception:
        return None


def _parse_alpn_from_client_hello(buf: bytes):
    offset, size = _parse_ext(buf, 0x10)
    if offset is None:
        return []
    try:
        end = offset + size
        list_len = struct.unpack("!H", buf[offset:offset + 2])[0]
        p = offset + 2
        stop = min(p + list_len, end)
        out = []
        while p < stop:
            L = buf[p]
            p += 1
            out.append(buf[p:p + L].decode("ascii", "ignore"))
            p += L
        return out
    except Exception:
        return []


# --- "Instant Certificate" server-side context ------------------------------

class InstantCertContext:
    """Per-SNI leaf certs signed by the local MMDF CA. Two cert backends are
    supported transparently:

      * ``cryptography`` — pure-Python, in-memory signing, no fork overhead.
      * ``openssl`` CLI — zero Python deps, signs each leaf via subprocess.

    The leaf private key is generated once and reused across SNIs — clients
    verify the CA signature on the leaf, not the keypair identity. Bundles
    (leaf key + leaf cert + CA cert) are cached on disk per SNI so the
    second hit on the same hostname is essentially free.
    """

    def __init__(self, ca_cert_path, ca_key_path, backend):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.backend = backend
        self._ctx_cache = {}
        self._cache_lock = threading.Lock()
        self._mint_lock = threading.Lock()
        self._cert_dir = None
        # openssl-only state
        self._leaf_key_path = None
        self._leaf_csr_path = None
        # cryptography-only state
        self._issuer_cert = None
        self._issuer_key = None
        self._leaf_priv_pem = None
        self._leaf_pub_obj = None
        self._init_backend()

    def _init_backend(self):
        from utils import paths
        scratch = paths.data_path("mmdf_certs")
        os.makedirs(scratch, exist_ok=True)
        try:
            os.chmod(scratch, 0o700)
        except Exception:
            pass
        self._cert_dir = scratch

        if self.backend == "cryptography":
            self._init_cryptography()
        else:
            self._init_openssl()

    def _init_cryptography(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        with open(self.ca_cert_path, "rb") as f:
            self._issuer_cert = x509.load_pem_x509_certificate(f.read())
        with open(self.ca_key_path, "rb") as f:
            self._issuer_key = serialization.load_pem_private_key(f.read(), password=None)

        leaf_priv = ec.generate_private_key(ec.SECP256R1())
        self._leaf_pub_obj = leaf_priv.public_key()
        self._leaf_priv_pem = leaf_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def _init_openssl(self):
        leaf_key = os.path.join(self._cert_dir, "leaf.key")
        leaf_csr = os.path.join(self._cert_dir, "leaf.csr")
        if not os.path.exists(leaf_key):
            res = subprocess.run(
                ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", leaf_key],
                capture_output=True, text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"openssl genkey failed: {res.stderr.strip()}")
            try:
                os.chmod(leaf_key, 0o600)
            except Exception:
                pass
        if not os.path.exists(leaf_csr):
            res = subprocess.run(
                [
                    "openssl", "req", "-new",
                    "-key", leaf_key,
                    "-out", leaf_csr,
                    "-subj", "/CN=mmdf.leaf.local",
                ],
                capture_output=True, text=True,
            )
            if res.returncode != 0:
                raise RuntimeError(f"openssl CSR failed: {res.stderr.strip()}")
        self._leaf_key_path = leaf_key
        self._leaf_csr_path = leaf_csr

    def _safe_sni_label(self, hostname):
        return "".join(c if c.isalnum() else "_" for c in hostname)[:96]

    def _bundle_path(self, hostname):
        return os.path.join(self._cert_dir, f"leaf_{self._safe_sni_label(hostname)}.pem")

    def _mint_leaf(self, hostname):
        """Sign a leaf cert for ``hostname`` and write the full PEM bundle.

        Returns the bundle path. Threadsafe — concurrent first-hits on the
        same SNI are serialized so we don't sign twice.
        """
        bundle_path = self._bundle_path(hostname)
        with self._mint_lock:
            if os.path.exists(bundle_path):
                return bundle_path
            if self.backend == "cryptography":
                self._mint_leaf_cryptography(hostname, bundle_path)
            else:
                self._mint_leaf_openssl(hostname, bundle_path)
            try:
                os.chmod(bundle_path, 0o600)
            except Exception:
                pass
            return bundle_path

    def _mint_leaf_cryptography(self, hostname, bundle_path):
        import datetime as _dt
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
            .issuer_name(self._issuer_cert.subject)
            .public_key(self._leaf_pub_obj)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=True,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False,
                    crl_sign=False, encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(self._leaf_pub_obj), critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._issuer_cert.public_key()),
                critical=False,
            )
            .sign(self._issuer_key, hashes.SHA256())
        )
        leaf_pem = cert.public_bytes(serialization.Encoding.PEM)
        ca_pem = self._issuer_cert.public_bytes(serialization.Encoding.PEM)

        tmp = bundle_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(self._leaf_priv_pem + leaf_pem + ca_pem)
        os.replace(tmp, bundle_path)

    def _mint_leaf_openssl(self, hostname, bundle_path):
        tmp_leaf = os.path.join(
            self._cert_dir, f".pending_{os.getpid()}_{self._safe_sni_label(hostname)}.pem"
        )
        cmd = [
            "openssl", "x509", "-req",
            "-in", self._leaf_csr_path,
            "-CA", self.ca_cert_path,
            "-CAkey", self.ca_key_path,
            "-CAcreateserial",
            "-out", tmp_leaf,
            "-days", "365",
            "-sha256",
            "-extfile", "/dev/stdin",
        ]
        extfile = (
            f"subjectAltName=DNS:{hostname}\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth,clientAuth\n"
            "subjectKeyIdentifier=hash\n"
            "authorityKeyIdentifier=keyid,issuer\n"
        )
        res = subprocess.run(cmd, input=extfile, capture_output=True, text=True)
        if res.returncode != 0 or not os.path.exists(tmp_leaf):
            # /dev/stdin isn't readable on every OpenSSL/Windows build —
            # retry with a real temp extfile.
            import tempfile
            with tempfile.NamedTemporaryFile("w", suffix=".cnf", delete=False) as f:
                f.write(extfile)
                extfile_path = f.name
            try:
                cmd[-1] = extfile_path
                res = subprocess.run(cmd, capture_output=True, text=True)
            finally:
                try:
                    os.remove(extfile_path)
                except OSError:
                    pass
            if res.returncode != 0 or not os.path.exists(tmp_leaf):
                raise RuntimeError(
                    f"openssl x509 sign failed for {hostname}: "
                    f"{(res.stderr or res.stdout or '').strip()}"
                )

        with open(self._leaf_key_path, "rb") as f:
            key_pem = f.read()
        with open(tmp_leaf, "rb") as f:
            leaf_pem = f.read()
        with open(self.ca_cert_path, "rb") as f:
            ca_pem = f.read()

        tmp = bundle_path + ".tmp"
        with open(tmp, "wb") as f:
            f.write(key_pem + leaf_pem + ca_pem)
        os.replace(tmp, bundle_path)
        try:
            os.remove(tmp_leaf)
        except OSError:
            pass

    def get_context_for_sni(self, hostname, alpn_offered):
        """Return an SSLContext that will present a leaf for ``hostname`` and
        only accept the ALPN values in ``alpn_offered`` (single value forces a
        specific protocol; multi-value follows the client's offer)."""
        if not hostname:
            hostname = "default.local"
        alpn_key = tuple(alpn_offered or ())
        cache_key = (hostname.lower(), alpn_key)
        with self._cache_lock:
            cached = self._ctx_cache.get(cache_key)
        if cached:
            return cached

        pem_path = self._mint_leaf(hostname)
        ctx = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            if alpn_key:
                ctx.set_alpn_protocols(list(alpn_key))
        except Exception:
            pass
        ctx.load_cert_chain(pem_path)

        with self._cache_lock:
            if len(self._ctx_cache) > 256:
                self._ctx_cache.clear()
            self._ctx_cache[cache_key] = ctx
        return ctx


def _ensure_instant_ctx():
    global _INSTANT_CTX, _INSTANT_CTX_ERR
    if _INSTANT_CTX is not None:
        return _INSTANT_CTX, None
    if _INSTANT_CTX_ERR is not None:
        return None, _INSTANT_CTX_ERR

    with _CTX_LOCK:
        if _INSTANT_CTX is not None:
            return _INSTANT_CTX, None
        if _INSTANT_CTX_ERR is not None:
            return None, _INSTANT_CTX_ERR
        try:
            from utils import mmdf_ca
            backend = mmdf_ca.select_backend()
            if backend is None:
                _INSTANT_CTX_ERR = (
                    "no cert backend available — install Python `cryptography` "
                    "or the OpenSSL CLI"
                )
                return None, _INSTANT_CTX_ERR
            cert, key = mmdf_ca.ensure_ca_files()
            _INSTANT_CTX = InstantCertContext(cert, key, backend)
            return _INSTANT_CTX, None
        except Exception as e:
            _INSTANT_CTX_ERR = repr(e)
            return None, _INSTANT_CTX_ERR


def reset_instant_ctx():
    global _INSTANT_CTX, _INSTANT_CTX_ERR
    with _CTX_LOCK:
        _INSTANT_CTX = None
        _INSTANT_CTX_ERR = None


# --- Profile / domain matching ----------------------------------------------

def _profile_matches_host(profile, host_lower):
    for d in profile.get("domains") or []:
        d = str(d).lower().strip(".")
        if not d:
            continue
        if host_lower == d or host_lower.endswith("." + d):
            return True
    return False


def _is_excluded_host(host_lower):
    for d in getattr(config, "MMDF_DOMAIN_EXCLUDES", None) or []:
        d = str(d).lower().strip(".")
        if not d:
            continue
        if host_lower == d or host_lower.endswith("." + d):
            return True
    return False


def match_fronting_profile(host: str):
    """Return the first profile whose domain list matches the host, or None.

    Hosts in ``MMDF_DOMAIN_EXCLUDES`` (e.g. gemini.google.com — they don't
    allow domain fronting and 403 the inner Host) skip MMDF entirely.
    """
    if not host:
        return None
    host_lower = host.lower().strip(".")
    if _is_excluded_host(host_lower):
        return None
    for profile in getattr(config, "MMDF_FRONTING_PROFILES", None) or []:
        if _profile_matches_host(profile, host_lower):
            return profile
    return None


def host_matches_mmdf(host: str) -> bool:
    return match_fronting_profile(host) is not None


# --- Outbound IP selection --------------------------------------------------

async def _resolve_host(hostname, target_port):
    from utils.route_service import ROUTE_SERVICE
    try:
        ip = await ROUTE_SERVICE.resolve_target(hostname, target_port)
        if ip and ip != hostname:
            return ip
    except Exception:
        pass
    return None


async def pick_outbound_ip(profile, target_port, prefer_front_ip=True,
                           front_sni_override=None, front_ip_override=None):
    """Resolve the outbound IP for the given fronting profile.

    ``prefer_front_ip=True`` (the default and the right choice for most
    networks): resolve the profile's front host directly. ``False``: try the
    white-IP pool first, fall back to the front host.
    """
    front_host = (
        str(front_sni_override).strip()
        if front_sni_override
        else (profile.get("front_ip_host") or profile.get("front_sni"))
    )

    if front_ip_override:
        return str(front_ip_override).strip(), target_port

    if not prefer_front_ip:
        from utils.route_service import ROUTE_SERVICE
        try:
            result = await ROUTE_SERVICE.get_routed_ip(front_host, target_port)
            if isinstance(result, tuple) and len(result) >= 2:
                return str(result[0]), int(result[1])
            if isinstance(result, str) and result and result != front_host:
                return result, target_port
        except Exception:
            pass

    ip = await _resolve_host(front_host, target_port)
    if ip:
        return ip, target_port
    return None, target_port


# --- TLS pumps via MemoryBIO ------------------------------------------------

class _BioStream:
    def __init__(self, reader, writer, sslobj, in_bio, out_bio):
        self.reader = reader
        self.writer = writer
        self.sslobj = sslobj
        self.in_bio = in_bio
        self.out_bio = out_bio
        self._closed = False

    async def _flush_outgoing(self):
        out = self.out_bio.read()
        if out:
            self.writer.write(out)
            try:
                await self.writer.drain()
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
                self._closed = True
                raise

    async def _pump_incoming(self):
        data = await self.reader.read(16384)
        if not data:
            self.in_bio.write_eof()
            return False
        self.in_bio.write(data)
        return True

    async def do_handshake(self):
        while True:
            try:
                self.sslobj.do_handshake()
                await self._flush_outgoing()
                return
            except ssl.SSLWantReadError:
                await self._flush_outgoing()
                ok = await self._pump_incoming()
                if not ok:
                    raise ssl.SSLError("Peer closed during TLS handshake")
            except ssl.SSLWantWriteError:
                await self._flush_outgoing()

    async def read(self, n):
        while True:
            try:
                data = self.sslobj.read(n)
                if data:
                    return data
                return b""
            except ssl.SSLWantReadError:
                await self._flush_outgoing()
                ok = await self._pump_incoming()
                if not ok:
                    return b""
            except ssl.SSLWantWriteError:
                await self._flush_outgoing()
            except ssl.SSLZeroReturnError:
                return b""
            except (ssl.SSLError, OSError):
                return b""

    async def write(self, data):
        if not data:
            return
        view = memoryview(data)
        while view:
            try:
                written = self.sslobj.write(view)
                view = view[written:]
                await self._flush_outgoing()
            except ssl.SSLWantReadError:
                await self._flush_outgoing()
                ok = await self._pump_incoming()
                if not ok:
                    raise ConnectionResetError("Peer closed during TLS write")
            except ssl.SSLWantWriteError:
                await self._flush_outgoing()

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            self.sslobj.unwrap()
        except Exception:
            pass
        try:
            self.writer.close()
        except Exception:
            pass


async def _run_tls_server(client_reader, client_writer, ssl_ctx, prebuffered=b""):
    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    sslobj = ssl_ctx.wrap_bio(in_bio, out_bio, server_side=True)
    if prebuffered:
        in_bio.write(prebuffered)
    bio = _BioStream(client_reader, client_writer, sslobj, in_bio, out_bio)
    await bio.do_handshake()
    return bio


async def _run_tls_client(out_reader, out_writer, ssl_ctx, server_hostname):
    in_bio = ssl.MemoryBIO()
    out_bio = ssl.MemoryBIO()
    sslobj = ssl_ctx.wrap_bio(in_bio, out_bio, server_side=False, server_hostname=server_hostname)
    bio = _BioStream(out_reader, out_writer, sslobj, in_bio, out_bio)
    await bio.do_handshake()
    return bio


async def _bridge(src: _BioStream, dst: _BioStream):
    try:
        while True:
            data = await src.read(65536)
            if not data:
                return
            await dst.write(data)
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError, ssl.SSLError):
        return
    except Exception:
        return


# --- ClientHello sniffer ----------------------------------------------------

async def _read_client_hello(reader, max_bytes=16384, timeout=4.0):
    head = bytearray()
    while len(head) < 5:
        chunk = await asyncio.wait_for(reader.read(5 - len(head)), timeout=timeout)
        if not chunk:
            return None
        head.extend(chunk)
    if head[0] != 0x16:
        return bytes(head)
    record_len = struct.unpack("!H", bytes(head[3:5]))[0]
    target_len = min(5 + record_len, max_bytes)
    while len(head) < target_len:
        chunk = await asyncio.wait_for(reader.read(target_len - len(head)), timeout=timeout)
        if not chunk:
            break
        head.extend(chunk)
    return bytes(head)


# --- Public entry point -----------------------------------------------------

async def handle_mmdf_connection(client_reader, client_writer, target_host, target_port,
                                 prefer_front_ip=True, prebuffered=b"",
                                 front_sni_override=None, front_ip_override=None):
    """MITM one client connection through MMDF.

    ``prebuffered`` is any TLS bytes already consumed by the upstream protocol
    handler (e.g. the transparent-TLS path peeked at the SNI). Pass b"" if no
    bytes have been read since the TCP socket was accepted (typical SOCKS5 /
    HTTP CONNECT path).
    """
    instant_ctx, err = _ensure_instant_ctx()
    if instant_ctx is None:
        print(f"[MMDF] disabled: {err}")
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    profile = match_fronting_profile(target_host)
    if not profile:
        # Caller already validated host_matches_mmdf, but defend defensively.
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    # 1. Make sure we have a complete ClientHello in `head`.
    try:
        head = bytes(prebuffered) if prebuffered else b""
        if not head:
            sniff = await _read_client_hello(client_reader, timeout=4.0)
            if not sniff:
                client_writer.close()
                return False
            head = sniff
        elif head[0] == 0x16 and len(head) >= 5:
            record_len = struct.unpack("!H", head[3:5])[0]
            need = 5 + record_len - len(head)
            if need > 0:
                rest = await asyncio.wait_for(client_reader.readexactly(need), timeout=4.0)
                head += rest
    except Exception as e:
        print(f"[MMDF] ClientHello read failed: {e!r}")
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    if not head or head[0] != 0x16:
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    sni = _parse_sni_from_client_hello(head) or target_host
    leaf_host = sni or target_host or "default.local"
    client_alpn = _parse_alpn_from_client_hello(head)

    front_sni = (
        str(front_sni_override).strip()
        if front_sni_override
        else (getattr(config, "MMDF_SNI", "") or profile["front_sni"])
    )

    # 2. Pick outbound IP from the selected front domain/IP.
    out_ip, out_port = await pick_outbound_ip(
        profile,
        target_port,
        prefer_front_ip=prefer_front_ip,
        front_sni_override=front_sni,
        front_ip_override=front_ip_override,
    )
    if not out_ip:
        print(f"[MMDF] no outbound IP for profile={profile['name']} front={front_sni}")
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    forced_alpn = profile.get("force_alpn")
    outbound_alpn = forced_alpn if forced_alpn else (client_alpn or None)

    # 3. Open outbound socket and start TLS with the front SNI.
    out_ctx = ssl.create_default_context()
    out_ctx.check_hostname = False
    out_ctx.verify_mode = ssl.CERT_NONE
    if outbound_alpn:
        try:
            out_ctx.set_alpn_protocols(list(outbound_alpn))
        except Exception:
            pass

    try:
        out_reader, out_writer = await asyncio.wait_for(
            asyncio.open_connection(out_ip, out_port),
            timeout=float(getattr(config, "PROXY_CONNECT_TIMEOUT", 6.0)),
        )
    except Exception as e:
        print(f"[MMDF] outbound connect to {out_ip}:{out_port} failed: {e!r}")
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    out_bio = None
    in_bio = None
    try:
        out_bio = await asyncio.wait_for(
            _run_tls_client(out_reader, out_writer, out_ctx, server_hostname=front_sni),
            timeout=12.0,
        )
    except Exception as e:
        print(f"[MMDF] outbound TLS handshake failed (host={leaf_host} front={front_sni} ip={out_ip}:{out_port}): {e!r}")
        try:
            out_writer.close()
        except Exception:
            pass
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    # 4. Determine the ALPN we'll negotiate with the *client*: whatever the
    # outbound actually picked. If outbound didn't negotiate ALPN, fall back
    # to the client's offer so we're transparent.
    try:
        negotiated_alpn = out_bio.sslobj.selected_alpn_protocol()
    except Exception:
        negotiated_alpn = None
    if negotiated_alpn:
        inbound_alpn = [negotiated_alpn]
    elif client_alpn:
        inbound_alpn = client_alpn
    else:
        inbound_alpn = None

    server_ctx = instant_ctx.get_context_for_sni(leaf_host, inbound_alpn)

    # 5. Wrap inbound with our instant cert (using the pre-buffered ClientHello).
    try:
        in_bio = await asyncio.wait_for(
            _run_tls_server(client_reader, client_writer, server_ctx, prebuffered=head),
            timeout=12.0,
        )
    except Exception as e:
        print(f"[MMDF] inbound TLS handshake failed (host={leaf_host} alpn={inbound_alpn}): {e!r}")
        try:
            out_bio.close()
        except Exception:
            pass
        try:
            client_writer.close()
        except Exception:
            pass
        return False

    print(
        f"[🌀 MMDF/{profile['name']}] {target_host or leaf_host}:{target_port} "
        f"-> {out_ip}:{out_port} (front={front_sni}, alpn={negotiated_alpn or 'unset'})"
    )

    # 6. Bidirectional cleartext bridge.
    t1 = asyncio.create_task(_bridge(in_bio, out_bio))
    t2 = asyncio.create_task(_bridge(out_bio, in_bio))
    try:
        await asyncio.gather(t1, t2, return_exceptions=True)
    finally:
        in_bio.close()
        out_bio.close()
    return True
