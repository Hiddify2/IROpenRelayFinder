import os
import sys
import socket
import re
from utils import config
from utils import storage

# ==========================================
# NETWORK & SOCKET UTILITIES
# ==========================================
def _default_port(default_port=None):
    if default_port is not None:
        return int(default_port)
    try:
        return config.primary_target_port()
    except Exception:
        return 443

def parse_ip_port(value, default_port=None):
    """
    Normalizes an IP/port representation into a tuple (ip, port).
    Accepts tuples, 'ip:port' strings, or bare IPs (defaulting to primary port).
    """
    if value is None:
        return None
    if isinstance(value, tuple) and len(value) == 2:
        ip, port = value
        try:
            return str(ip), int(port)
        except (TypeError, ValueError):
            return None

    raw = str(value).strip()
    if not raw:
        return None

    ip_part, port_part = raw, None
    if ':' in raw:
        maybe_ip, maybe_port = raw.rsplit(':', 1)
        if maybe_port.isdigit():
            ip_part, port_part = maybe_ip, int(maybe_port)
    if port_part is None:
        port_part = _default_port(default_port)
    return ip_part, port_part

def format_ip_port(ip, port):
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        port_int = _default_port()
    return f"{ip}:{port_int}"

def parse_port_list(raw_value, fallback_ports=None):
    """
    Parses a user-supplied port list (comma/space separated) into a normalized int list.
    Falls back to the provided list if nothing valid is found.
    """
    tokens = re.split(r"[,\s]+", raw_value.strip()) if raw_value else []
    parsed = []
    for token in tokens:
        if not token:
            continue
        try:
            parsed.append(int(token))
        except (TypeError, ValueError):
            continue
    normalized = config._normalize_ports(parsed or fallback_ports or config.TARGET_PORTS)
    return normalized

def add_ban_entry(domain, endpoint, persist=True):
    """
    Adds a {domain, ip, port} ban entry to memory and optionally to disk.
    Returns True if the ban was newly added.
    """
    parsed = parse_ip_port(endpoint)
    domain_key = (domain or "").strip().lower()
    if not parsed or not domain_key:
        return False
    ip, port = parsed

    domain_bans = config.BANNED_ROUTES.get(domain_key)
    if not isinstance(domain_bans, set):
        domain_bans = set()
        config.BANNED_ROUTES[domain_key] = domain_bans

    if (ip, port) in domain_bans:
        return False

    domain_bans.add((ip, port))
    if persist:
        try:
            storage.append_line(config.BANNED_ROUTES_FILE, f"{format_ip_port(ip, port)} {domain_key}", encoding="utf-8")
        except Exception:
            pass
    return True

def get_local_ip():
    """Attempts to find the local IP address of the host machine."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def tune_socket(sock):
    """Applies low-level TCP optimizations (NoDelay & KeepAlive) to a socket."""
    if not sock: return
    try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception: pass
    try: sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except Exception: pass

    # TCP_QUICKACK: Send ACKs immediately instead of waiting up to 40ms (Delayed ACK).
    # Critical for upload responsiveness — without this, every upload write waits an
    # extra RTT for the remote ACK, which compounds badly on Iran's high-latency links.
    # NOTE: Linux resets TCP_QUICKACK after each ACK so we set it once at connect time;
    # this gives immediate ACKs for the handshake and early data, which matters most.
    if hasattr(socket, 'TCP_QUICKACK'):
        try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
        except Exception: pass

    # ── Tuned buffer sizing for Iranian network conditions ──
    # 64KB send + recv — smaller than before to avoid accumulating large bursts.
    # Iranian DPI/shapers see huge socket buffers dumping data all at once and
    # rate-limit the flow. Smaller buffers mean steadier, more natural-looking traffic.
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
    except Exception: pass

    if sys.platform == 'win32' and hasattr(sock, 'ioctl'):
        try: sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 8000, 1500))
        except Exception: pass
    else:
        # Tighter keepalive values than default to fail fast on Iranian link drops.
        # KEEPIDLE=8s: start probing after 8s idle (was 11s)
        # KEEPINTVL=1.5s: re-probe every 1.5s (was 2s)
        # KEEPCNT=3: give up after 3 failed probes (~12.5s total to detect dead conn)
        if hasattr(socket, 'TCP_KEEPIDLE'):
            try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 8)
            except Exception: pass
        elif hasattr(socket, 'TCP_KEEPALIVE'):
            try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPALIVE, 8)
            except Exception: pass
        if hasattr(socket, 'TCP_KEEPINTVL'):
            try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            except Exception: pass
        if hasattr(socket, 'TCP_KEEPCNT'):
            try: sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except Exception: pass

def tcp_checksum(msg):
    """Calculates the TCP checksum used for raw packet injection."""
    s = 0
    if len(msg) % 2 == 1: msg += b'\0'
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

# ==========================================
# HTTP / DOMAIN PARSING UTILITIES
# ==========================================
def is_l7_geoblocked(domain, resp_bytes):
    """
    Intelligently analyzes an L7 HTTP response to determine if a CDN IP 
    is actively blocking access to the requested domain (e.g. CF 1034, Google 403).
    """
    resp_lower = resp_bytes.lower()
    status_line = resp_bytes.split(b'\r\n')[0] if b'\r\n' in resp_bytes else b''
    
    if b"location_unavailable" in resp_lower: return True
    if b"edge ip restricted" in resp_lower: return True
    if b"error code: 1020" in resp_lower: return True
    if b"error 1034" in resp_lower: return True
    if b"fastly error: unknown domain" in resp_lower: return True
    
    google_domains = ('google.com', 'youtube.com', 'googlevideo.com', 'gvt1.com', 'ytimg.com', 'ggpht.com', 'turns.goog')
    is_google = any(domain == d or domain.endswith('.' + d) for d in google_domains)
    if is_google and (b" 403 " in status_line or b" 451 " in status_line):
        return True
        
    return False

def get_base_domain(domain):
    """Extracts the base domain from a full hostname (e.g., www.example.com -> example.com)."""
    SENSITIVE_DOMAINS = {'google.com', 'googlevideo.com', 'youtube.com', 'gvt1.com', 'chatgpt.com', 'openai.com', 'turns.goog'}
    parts = domain.split('.')
    if len(parts) <= 2: base = domain
    elif parts[-2] in ['co', 'com', 'org', 'net', 'edu', 'gov'] and len(parts[-1]) == 2: base = '.'.join(parts[-3:])
    else: base = '.'.join(parts[-2:])
    if base in SENSITIVE_DOMAINS: return domain 
    return base

# ==========================================
# FILE & CACHE UTILITIES
# ==========================================
def cleanup_files(*files):
    """Silently removes temporary files if they exist."""
    for f in files:
        if os.path.exists(f):
            try: os.remove(f)
            except OSError: pass

def load_white_cache():
    """Loads the permanently saved White IPs from disk."""
    cache = set()
    for line in storage.read_text_lines(config.WHITE_IPS_CACHE_FILE, encoding='utf-8'):
        parsed = parse_ip_port(line.strip())
        if parsed:
            cache.add(parsed)
    return cache

def save_to_white_cache(new_ips):
    """Appends new IPs to the permanent cache file, avoiding duplicates."""
    cache = load_white_cache()
    before_len = len(cache)
    for item in new_ips:
        parsed = parse_ip_port(item)
        if parsed:
            cache.add(parsed)
    if len(cache) > before_len:
        def _sort_key(ep):
            ip, port = ep
            return (ip, int(port))

        sorted_cache = sorted(cache, key=_sort_key)
        body = "".join(f"{format_ip_port(ip, port)}\n" for ip, port in sorted_cache)
        storage.atomic_write_text(config.WHITE_IPS_CACHE_FILE, body, encoding='utf-8')
        return len(cache) - before_len
    return 0

def load_socks5_cache():
    """Loads the permanently saved working SOCKS5 proxies from disk."""
    cache = set()
    for line in storage.read_text_lines(config.SOCKS5_CACHE_FILE, encoding='utf-8'):
        parsed = parse_ip_port(line.strip())
        if parsed:
            cache.add(parsed)
    return cache

def save_to_socks5_cache(new_proxies):
    """Appends new working SOCKS5 proxies to the permanent cache, avoiding duplicates."""
    cache = load_socks5_cache()
    before_len = len(cache)
    for item in new_proxies:
        parsed = parse_ip_port(item)
        if parsed:
            cache.add(parsed)
    if len(cache) > before_len:
        def _sort_key(ep):
            ip, port = ep
            return (ip, int(port))

        sorted_cache = sorted(cache, key=_sort_key)
        body = "".join(f"{format_ip_port(ip, port)}\n" for ip, port in sorted_cache)
        storage.atomic_write_text(config.SOCKS5_CACHE_FILE, body, encoding='utf-8')
        return len(cache) - before_len
    return 0

# ==========================================
# CLI / UI UTILITIES
# ==========================================
def clear_screen():
    """Clears the terminal window."""
    os.system('cls' if os.name == 'nt' else 'clear')
