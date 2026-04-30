import os
import json
import socket
import asyncio
import ipaddress
import ssl
import re
import fnmatch
import time
from dataclasses import dataclass

from utils import config
from utils import paths
from utils import storage
from utils.runtime_state import STATE
from utils.helpers import get_base_domain, parse_ip_port, format_ip_port
from cores.scanner import classify_response

# ==========================================
# GLOBAL CACHES & TUPLES (PERFORMANCE)
# ==========================================
_TLS_CTX_STRICT = None

_CACHED_VIDEO_TUPLE = None
_HAS_TO_THREAD = hasattr(asyncio, "to_thread")  # Cached once – never changes at runtime
_LOCKS_INITIALIZED = False
_SENSITIVE_DOMAINS = ('google.com', 'youtube.com', 'googlevideo.com', 'gvt1.com', 'ytimg.com', 'ggpht.com', 'turns.goog', 'chatgpt.com', 'openai.com', 'claude.ai')
_SENSITIVE_TUPLE = tuple('.' + d for d in _SENSITIVE_DOMAINS)
_MEDIA_DOMAINS_TO_UNBAN = ('googlevideo.com', 'youtube.com', 'ytimg.com', 'gvt1.com', 'yt.be', 'ggpht.com', 'turns.goog')
_MEDIA_DOMAINS_TUPLE = tuple('.' + d for d in _MEDIA_DOMAINS_TO_UNBAN)
_PROBE_EXCLUDED_SUBDOMAINS = (
    'fonts.googleapis.com',
    'fonts.gstatic.com',
    'www.gstatic.com',
    'apis.google.com',
)
_ROUTE_POLICY_CACHE_VERSION = -1
_ROUTE_POLICY_CACHE = {
    'always': {'exact': set(), 'glob': [], 'regex': []},
    'do_not': {'exact': set(), 'glob': [], 'regex': []},
}
_MAX_PRIMARY_CANDIDATES_DEFAULT = 12
_MAX_PRIMARY_CANDIDATES_SENSITIVE = 15
_MAX_PRIMARY_CANDIDATES_VIDEO = 24
_MAX_FALLBACK_CANDIDATES = 6


@dataclass
class EndpointStats:
    ewma_latency_ms: float = 9999.0
    fail_count: int = 0
    last_ok_ts: float = 0.0
    success_count: int = 0

    def score(self, now=None):
        now_mono = now if now is not None else time.monotonic()
        recency_age = max(0.0, now_mono - self.last_ok_ts) if self.last_ok_ts else getattr(config, 'ROUTE_SCORE_RECENCY_CAP_SEC', 120.0)
        recency_penalty = min(recency_age, getattr(config, 'ROUTE_SCORE_RECENCY_CAP_SEC', 120.0)) * getattr(config, 'ROUTE_SCORE_RECENCY_WEIGHT', 3.0)
        return (
            (self.ewma_latency_ms * getattr(config, 'ROUTE_SCORE_LATENCY_WEIGHT', 1.0))
            + (self.fail_count * getattr(config, 'ROUTE_SCORE_FAIL_WEIGHT', 250.0))
            + recency_penalty
        )


# Unified endpoint registry and host L1 route cache
_EP_REGISTRY = {}
_ROUTE_L1_CACHE = {}

# Adaptive concurrency for the race semaphore. Lazily wired on first
# ensure_locks() call so the AdaptiveThrottler binds to the running loop.
_RACE_THROTTLER = None
_RACE_THROTTLER_TASK = None

# Legacy compatibility symbols used by smoke harness and older tooling.
# They are kept as thin aliases/wrappers over the new architecture.
_ROUTE_FAST_CACHE = _ROUTE_L1_CACHE
_IP_HEALTH_SCORES = {}
_POOL_CACHE = {
    'expiry': 0.0,
    'sig': None,
    'eps': [],
}

_GOOGLE_FAMILY_SUFFIXES = (
    'google.com',
    'gmail.com',
    'googlemail.com',
    'googleapis.com',
    'googleusercontent.com',
    'gstatic.com',
    'googlevideo.com',
    'gvt1.com',
    'ytimg.com',
    'ggpht.com',
    'turns.goog',
)

def get_tls_context(strict=True):
    """Lazily creates and caches the strict SSL context to avoid CA-loading overhead per IP.

    The ``strict`` parameter is kept for source compatibility; only the strict
    context is supported — accepting unverified certificates would let a
    hijacker win the route race with a self-signed cert.
    """
    global _TLS_CTX_STRICT
    if _TLS_CTX_STRICT is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        try: ctx.set_alpn_protocols(['http/1.1'])
        except Exception: pass
        _TLS_CTX_STRICT = ctx
    return _TLS_CTX_STRICT

def get_video_cdn_tuple():
    global _CACHED_VIDEO_TUPLE
    if _CACHED_VIDEO_TUPLE is None:
        _CACHED_VIDEO_TUPLE = tuple('.' + d for d in config.VIDEO_CDN_DOMAINS)
    return _CACHED_VIDEO_TUPLE


def _build_policy_compiled(patterns):
    compiled = {
        'exact': set(),
        'glob': [],
        'regex': [],
    }
    for raw in patterns or []:
        pattern = (raw or '').strip().lower()
        if not pattern:
            continue
        if pattern.startswith('re:'):
            expr = pattern[3:].strip()
            if not expr:
                continue
            try:
                compiled['regex'].append((pattern, re.compile(expr)))
            except re.error:
                continue
        elif '*' in pattern or '?' in pattern:
            compiled['glob'].append(pattern)
        else:
            compiled['exact'].add(pattern.lstrip('.'))
    return compiled


def _ensure_route_policy_cache():
    global _ROUTE_POLICY_CACHE_VERSION, _ROUTE_POLICY_CACHE
    version = getattr(config, 'ROUTE_POLICY_VERSION', 0)
    if _ROUTE_POLICY_CACHE_VERSION == version:
        return

    _ROUTE_POLICY_CACHE = {
        'always': _build_policy_compiled(getattr(config, 'ALWAYS_ROUTE_PATTERNS', [])),
        'do_not': _build_policy_compiled(getattr(config, 'DO_NOT_ROUTE_PATTERNS', [])),
    }
    _ROUTE_POLICY_CACHE_VERSION = version


def _matches_any_compiled(host, base_domain, compiled):
    for exact in compiled['exact']:
        if host == exact or host.endswith('.' + exact) or base_domain == exact or base_domain.endswith('.' + exact):
            return exact

    for pattern in compiled['glob']:
        if fnmatch.fnmatch(host, pattern):
            return pattern

    for source, regex in compiled['regex']:
        try:
            if regex.search(host):
                return source
        except Exception:
            continue
    return None


def _is_google_family(domain):
    for suffix in _GOOGLE_FAMILY_SUFFIXES:
        if domain == suffix or domain.endswith('.' + suffix):
            return True
    return False


def _should_probe_domain(domain):
    return domain in _SENSITIVE_DOMAINS or domain.endswith(_SENSITIVE_TUPLE) or _is_google_family(domain)


def _endpoint_key(endpoint):
    return str(endpoint[0]), int(endpoint[1])


def _get_endpoint_stats(endpoint):
    key = _endpoint_key(endpoint)
    stats = _EP_REGISTRY.get(key)
    if stats is None:
        stats = EndpointStats()
        _EP_REGISTRY[key] = stats
    return stats


def _record_endpoint_success(endpoint, latency_ms=None):
    stats = _get_endpoint_stats(endpoint)
    stats.success_count += 1
    stats.last_ok_ts = time.monotonic()
    stats.fail_count = max(0, stats.fail_count - 1)
    key = _endpoint_key(endpoint)
    _IP_HEALTH_SCORES[key] = max(-100, _IP_HEALTH_SCORES.get(key, 0) + 3)
    if latency_ms is not None:
        alpha = getattr(config, 'ROUTE_EWMA_ALPHA', 0.35)
        if stats.ewma_latency_ms >= 9999.0:
            stats.ewma_latency_ms = float(latency_ms)
        else:
            stats.ewma_latency_ms = (alpha * float(latency_ms)) + ((1.0 - alpha) * stats.ewma_latency_ms)


def _record_endpoint_failure(endpoint):
    stats = _get_endpoint_stats(endpoint)
    stats.fail_count = min(50, stats.fail_count + 1)
    key = _endpoint_key(endpoint)
    _IP_HEALTH_SCORES[key] = min(100, _IP_HEALTH_SCORES.get(key, 0) - 4)


def _collect_pool_endpoints():
    endpoints = []
    seen = set()

    def _push(endpoint):
        if not endpoint:
            return
        ep = (str(endpoint[0]), int(endpoint[1]))
        if ep in seen:
            return
        seen.add(ep)
        endpoints.append(ep)

    try:
        raw_pool = getattr(config, 'IP_POOL', [])
        for ep in raw_pool:
            if isinstance(ep, tuple) and len(ep) >= 2:
                try:
                    _push((str(ep[0]), int(ep[1])))
                except (TypeError, ValueError):
                    continue
            else:
                parsed = parse_ip_port(ep)
                if parsed:
                    _push(parsed)
    except Exception:
        pass

    try:
        for ep in STATE.ip_pool().keys():
            _push(ep)
    except Exception:
        pass
    return endpoints


def _collect_pool_endpoints_cached():
    now = time.monotonic()
    raw_pool = getattr(config, 'IP_POOL', [])
    try:
        state_pool_len = len(STATE.ip_pool())
    except Exception:
        state_pool_len = 0

    sig = (
        len(raw_pool) if hasattr(raw_pool, '__len__') else 0,
        state_pool_len,
    )

    if _POOL_CACHE['sig'] == sig and _POOL_CACHE['expiry'] > now:
        return _POOL_CACHE['eps']

    endpoints = _collect_pool_endpoints()
    _POOL_CACHE['eps'] = endpoints
    _POOL_CACHE['sig'] = sig
    _POOL_CACHE['expiry'] = now + 2.0
    return endpoints


def _is_endpoint_banned_for_target(endpoint, target_port, banned_set):
    if not endpoint:
        return False

    ep_ip, ep_port = endpoint
    ep_key = (str(ep_ip), int(ep_port))
    if ep_key in banned_set:
        return True

    if not config.is_tls_port(target_port):
        return False
    if not config.is_tls_port(ep_key[1]):
        return False

    for banned_ip, banned_port in banned_set:
        try:
            if str(banned_ip) == ep_key[0] and config.is_tls_port(int(banned_port)):
                return True
        except Exception:
            continue
    return False


def _l1_route_get(host, port, banned_set, force_white):
    key = (host, int(port))
    entry = _ROUTE_L1_CACHE.get(key)
    if not entry:
        return None

    if entry['exp'] <= time.monotonic():
        _ROUTE_L1_CACHE.pop(key, None)
        return None

    mode = entry.get('mode')
    if mode == 'native':
        if force_white:
            return None
        return host, int(port)

    ep = entry.get('ep')
    if not ep or _is_endpoint_banned_for_target(ep, port, banned_set):
        _ROUTE_L1_CACHE.pop(key, None)
        return None

    stats = _EP_REGISTRY.get(ep)
    if stats and stats.fail_count >= getattr(config, 'ROUTE_EVICT_FAIL_THRESHOLD', 6):
        _ROUTE_L1_CACHE.pop(key, None)
        return None

    if _IP_HEALTH_SCORES.get(ep, 0) < -6:
        _ROUTE_L1_CACHE.pop(key, None)
        return None
    return ep


def _l1_route_set(host, port, result):
    key = (host, int(port))
    if not result:
        _ROUTE_L1_CACHE.pop(key, None)
        return

    if isinstance(result, tuple) and len(result) >= 2:
        ip, p = str(result[0]), int(result[1])
        if ip == host and p == int(port):
            _ROUTE_L1_CACHE[key] = {'mode': 'native', 'exp': time.monotonic() + getattr(config, 'ROUTE_L1_NATIVE_TTL_SEC', 45.0)}
        else:
            _ROUTE_L1_CACHE[key] = {'mode': 'white', 'ep': (ip, p), 'exp': time.monotonic() + getattr(config, 'ROUTE_L1_TTL_SEC', 90.0)}


def _fast_route_get(host, port, banned_set, force_white):
    # Backward-compatible alias for older call sites/tests.
    return _l1_route_get(host, port, banned_set, force_white)


def _fast_route_set(host, port, result):
    # Backward-compatible alias for older call sites/tests.
    _l1_route_set(host, port, result)


def _prepare_candidates(target_port, banned_for_domain, is_sensitive_host=False, is_video_domain=False, seed_endpoint=None, forbidden_eps=None):
    primary = []
    fallback = []
    forbidden_eps = forbidden_eps or set()

    for ep in _collect_pool_endpoints_cached():
        if ep in forbidden_eps:
            continue
        if config.is_tls_port(target_port):
            if not config.is_tls_port(ep[1]):
                continue
        elif ep[1] != target_port:
            continue

        if _is_endpoint_banned_for_target(ep, target_port, banned_for_domain):
            fallback.append(ep)
        else:
            primary.append(ep)

    now = time.monotonic()
    primary.sort(key=lambda ep: (_EP_REGISTRY.get(ep).score(now) if _EP_REGISTRY.get(ep) else 99999.0, ep[0], ep[1]))
    fallback.sort(key=lambda ep: (_EP_REGISTRY.get(ep).score(now) if _EP_REGISTRY.get(ep) else 99999.0, ep[0], ep[1]))

    if seed_endpoint and seed_endpoint in primary:
        primary.remove(seed_endpoint)
        primary.insert(0, seed_endpoint)

    if is_video_domain:
        max_primary = _MAX_PRIMARY_CANDIDATES_VIDEO
    elif is_sensitive_host:
        max_primary = _MAX_PRIMARY_CANDIDATES_SENSITIVE
    else:
        max_primary = _MAX_PRIMARY_CANDIDATES_DEFAULT
    primary = primary[:max_primary]
    fallback = fallback[:_MAX_FALLBACK_CANDIDATES]
    return primary, fallback


def _effective_batch_size(default_size, total_candidates):
    if total_candidates <= 0:
        return 0
    batch_size = min(max(1, int(default_size)), total_candidates)
    try:
        if STATE.active_proxy_connections() >= getattr(config, 'BACKGROUND_SCAN_PAUSE_CONNECTIONS', 6):
            down = max(0, int(getattr(config, 'RACE_BATCH_LOAD_DOWNSTEP', 1)))
            batch_size = max(int(getattr(config, 'RACE_BATCH_MIN', 2)), batch_size - down)
    except Exception:
        pass
    return min(batch_size, total_candidates)


def _get_registrable_domain(domain):
    parts = domain.split('.')
    if len(parts) <= 2:
        return domain
    if parts[-2] in ['co', 'com', 'org', 'net', 'edu', 'gov'] and len(parts[-1]) == 2:
        return '.'.join(parts[-3:])
    return '.'.join(parts[-2:])

def _get_port_map(route_map, key):
    port_map = route_map.get(key)
    return port_map if isinstance(port_map, dict) else None

def _set_route(route_map, key, port, ip):
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return
    port_map = route_map.get(key)
    if not isinstance(port_map, dict):
        port_map = {}
        route_map[key] = port_map
    port_map[port_int] = ip

# ==========================================
# ASYNC PRIMITIVES LAZY INIT
# ==========================================
def _install_race_throttler():
    """
    Wire an AdaptiveThrottler in front of the routing race. The throttler
    measures gateway RTT and grows/shrinks the DynamicSemaphore (AIMD): it
    behaves like a normal asyncio.Semaphore for callers, but its limit
    moves with router health so we don't flood the link under sustained
    load. Returns the DynamicSemaphore (or None if init fails).
    """
    global _RACE_THROTTLER, _RACE_THROTTLER_TASK
    if _RACE_THROTTLER is not None:
        return _RACE_THROTTLER.semaphore
    try:
        from cores.adaptive_throttle import AdaptiveThrottler
    except Exception:
        return None
    initial = max(2, int(getattr(config, 'RACE_CONCURRENCY_INITIAL', 8)))
    max_limit = max(initial, int(getattr(config, 'RACE_CONCURRENCY_MAX', 24)))
    gateway = None
    try:
        from cores.scanner import _find_default_gateway
        gateway = _find_default_gateway()
    except Exception:
        pass
    _RACE_THROTTLER = AdaptiveThrottler(
        initial=initial,
        gateway=gateway,
        max_limit=max_limit,
        verbose=False,
    )
    try:
        asyncio.get_running_loop()
        _RACE_THROTTLER_TASK = asyncio.create_task(_RACE_THROTTLER.run())
    except RuntimeError:
        # No loop yet — the task will be started on the next ensure_locks()
        # call from inside an async context.
        _RACE_THROTTLER_TASK = None
    return _RACE_THROTTLER.semaphore


def ensure_locks():
    global _LOCKS_INITIALIZED, _RACE_THROTTLER_TASK
    if _LOCKS_INITIALIZED:
        # Late-start the throttler loop if ensure_locks() was first called
        # outside an event loop (e.g. from a sync test harness) and we're
        # now inside one.
        if _RACE_THROTTLER is not None and _RACE_THROTTLER_TASK is None:
            try:
                asyncio.get_running_loop()
                _RACE_THROTTLER_TASK = asyncio.create_task(_RACE_THROTTLER.run())
            except RuntimeError:
                pass
        return
    if config._FILE_WRITE_LOCK is None:
        config._FILE_WRITE_LOCK = asyncio.Lock()
    if config.RACE_SEMAPHORE is None:
        sem = _install_race_throttler()
        config.RACE_SEMAPHORE = sem if sem is not None else asyncio.Semaphore(10)
    _LOCKS_INITIALIZED = True


def _record_race_outcome(ok: bool, latency_ms: float, sni_timeout: float):
    """Feed per-IP race outcomes back to the AdaptiveThrottler so it can
    track health and adjust the race semaphore limit over time."""
    if _RACE_THROTTLER is None:
        return
    try:
        timed_out = (not ok) and latency_ms >= (sni_timeout * 1000.0 * 0.95)
        _RACE_THROTTLER.record_outcome(bool(ok), bool(timed_out), float(latency_ms))
    except Exception:
        pass

# ==========================================
# POOL & ROUTE LOADERS
# ==========================================
def load_routes():
    STATE.clear_routes()
    try:
        for line in storage.read_text_lines(config.HOSTS_FILE, encoding='utf-8'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue

            parsed = parse_ip_port(parts[0])
            if not parsed:
                continue
            ip, port = parsed
            domains = parts[1:]
            for domain in domains:
                domain = domain.lower()
                if domain.startswith('*.'):
                    clean_domain = domain[2:].lstrip('.')
                    if clean_domain:
                        _set_route(STATE.wildcard_routes(), f".{clean_domain}", port, ip)
                else:
                    clean_domain = domain.lstrip('.')
                    if clean_domain:
                        _set_route(STATE.exact_routes(), clean_domain, port, ip)
    except PermissionError:
        print(f"[-] Permission denied reading routes file: {config.HOSTS_FILE}")
        print("[-] Continue with empty route cache. Run once with elevated privileges to auto-fix file mode.")
    except Exception:
        pass

def load_banned_routes():
    STATE.clear_banned_routes()
    b_routes = STATE.banned_routes()
    rewritten_lines = []
    seen_entries = set()
    try:
        for line in storage.read_text_lines(config.BANNED_ROUTES_FILE, encoding='utf-8'):
            stripped = line.strip()
            parts = stripped.split()
            if len(parts) >= 2:
                parsed = parse_ip_port(parts[0])
                domain = parts[1].lower()
                if parsed:
                    ip, port = parsed
                    entry_key = (domain, ip, int(port))
                    if entry_key in seen_entries:
                        continue
                    seen_entries.add(entry_key)
                    if domain not in b_routes:
                        b_routes[domain] = set()
                    b_routes[domain].add((ip, int(port)))
                    rewritten_lines.append(f"{format_ip_port(ip, port)} {domain}")
    except PermissionError:
        pass
    except Exception:
        pass
    try:
        if rewritten_lines:
            storage.atomic_write_text(config.BANNED_ROUTES_FILE, "".join(f"{line}\n" for line in rewritten_lines), encoding='utf-8')
    except Exception:
        pass

def load_ip_pool():
    STATE.clear_dead_ip_pool()
    scan_files = paths.list_scan_files(include_cyclic=False)
    if not scan_files: return 0
    
    loaded_ips = {}
    for file_path in scan_files[:3]:
        try:
            results = storage.read_json(file_path, default=[])
            if not isinstance(results, list):
                continue
            for r in results:
                if len(loaded_ips) >= 100:
                    break
                ip = r.get('ip')
                port = int(r.get('port', 443))
                endpoint = (ip, port) if ip else None
                if not endpoint or endpoint in loaded_ips:
                    continue
                domains = r.get('domains') or []
                loaded_ips[endpoint] = domains[0] if domains else None
        except Exception:
            pass
        
    STATE.replace_ip_pool(loaded_ips)
    return len(STATE.ip_pool())

async def purge_media_wildcard_routes():
    changed = False
    w_routes = STATE.wildcard_routes()
    e_routes = STATE.exact_routes()
    b_routes = STATE.banned_routes()

    for base_domain in list(w_routes.keys()):
        clean = base_domain.lstrip('.')
        if clean in _MEDIA_DOMAINS_TO_UNBAN or clean.endswith(_MEDIA_DOMAINS_TUPLE):
            removed = w_routes.pop(base_domain, None)
            e_routes.pop(clean, None)
            print(f"[STARTUP PURGE] Removed wildcard route: {base_domain} -> {removed}")
            changed = True

    for domain in list(e_routes.keys()):
        clean = domain.lstrip('.')
        if clean in _MEDIA_DOMAINS_TO_UNBAN or clean.endswith(_MEDIA_DOMAINS_TUPLE):
            removed = e_routes.pop(domain, None)
            print(f"[STARTUP PURGE] Removed exact route: {domain} -> {removed}")
            changed = True

    for domain in list(b_routes.keys()):
        if domain in _MEDIA_DOMAINS_TO_UNBAN or domain.endswith(_MEDIA_DOMAINS_TUPLE):
            print(f"[STARTUP PURGE] Cleared ban list for: {domain}")
            del b_routes[domain]

    if os.path.exists(config.BANNED_ROUTES_FILE):
        lines = storage.read_text_lines(config.BANNED_ROUTES_FILE, encoding='utf-8')
        cleaned = [line for line in lines if not any(d in line for d in _MEDIA_DOMAINS_TO_UNBAN)]
        storage.atomic_write_text(config.BANNED_ROUTES_FILE, "".join(f"{line}\n" for line in cleaned), encoding='utf-8')

    if changed:
        await async_rewrite_routes(e_routes, w_routes)
        print("[STARTUP PURGE] white_routes.txt updated.")

# ==========================================
# FILE I/O WRAPPERS
# ==========================================
def _write_route_sync(winner_ip, winner_port, base_domain):
    route_token = format_ip_port(winner_ip, winner_port)
    storage.append_line(config.HOSTS_FILE, f"{route_token} *.{base_domain} {base_domain}", encoding='utf-8')

async def async_append_route(winner_ip, winner_port, base_domain):
    ensure_locks()
    async with config._FILE_WRITE_LOCK:
        if _HAS_TO_THREAD: await asyncio.to_thread(_write_route_sync, winner_ip, winner_port, base_domain)
        else: _write_route_sync(winner_ip, winner_port, base_domain)

def _rewrite_routes_sync(exact_routes, wildcard_routes):
    lines = set()
    for domain, port_map in (exact_routes or {}).items():
        clean = domain.lstrip('.')
        if not clean or not isinstance(port_map, dict):
            continue
        for port, ip in port_map.items():
            lines.add(f"{format_ip_port(ip, port)} {clean}\n")
    for base_domain, port_map in (wildcard_routes or {}).items():
        clean = base_domain.lstrip('.')
        if not clean or not isinstance(port_map, dict):
            continue
        for port, ip in port_map.items():
            lines.add(f"{format_ip_port(ip, port)} *.{clean} {clean}\n")
    ordered_lines = sorted(lines)
    storage.atomic_write_text(config.HOSTS_FILE, "".join(ordered_lines), encoding='utf-8')

async def async_rewrite_routes(exact_routes, wildcard_routes):
    ensure_locks()
    async with config._FILE_WRITE_LOCK:
        if _HAS_TO_THREAD: await asyncio.to_thread(_rewrite_routes_sync, exact_routes, wildcard_routes)
        else: _rewrite_routes_sync(exact_routes, wildcard_routes)

def _write_fail_log_sync(target_host_lower):
    storage.append_line(config.FAIL_LOG_FILE, target_host_lower, encoding='utf-8')

async def async_append_fail_log(target_host_lower):
    ensure_locks()
    async with config._FILE_WRITE_LOCK:
        if _HAS_TO_THREAD: await asyncio.to_thread(_write_fail_log_sync, target_host_lower)
        else: _write_fail_log_sync(target_host_lower)

# ==========================================
# CORE ROUTING & RACING LOGIC
# ==========================================
async def resolve_target(host, port):
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    try:
        info = await loop.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
        return info[0][4][0]
    except Exception: 
        return host

async def verify_sni(ip, domain, port=443, timeout=config.RACE_TIMEOUT, tls_only=False, http_verify=False):
    """
    Confirms the route by completing a strict TLS handshake against ``domain``.
    Any cert failure (untrusted CA, hostname mismatch, expired, self-signed)
    rejects the IP — we will not route through an endpoint we can't authenticate.

    When ``http_verify`` is set the verifier also issues a small HTTP GET on the
    open TLS connection and runs the response through the scanner's
    ``classify_response``. This catches edge IPs that present a valid cert but
    serve "Your client does not have permission" (403) or other CDN denials at
    HTTP level — TLS-only verification is blind to those.
    """
    writer = None
    try:
        ctx = get_tls_context(strict=True) if config.is_tls_port(port) else None
        srv_host = domain if config.is_tls_port(port) else None
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=srv_host),
            timeout=timeout
        )

        if http_verify and config.is_tls_port(port):
            probe = (
                b"GET / HTTP/1.1\r\nHost: " + domain.encode("ascii", "ignore") +
                b"\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                b"\r\nAccept: text/html,application/xhtml+xml"
                b"\r\nAccept-Encoding: identity"
                b"\r\nConnection: close\r\n\r\n"
            )
            try:
                writer.write(probe)
                await writer.drain()
                resp_buf = bytearray()
                # First-byte timeout is more generous than per-chunk reads —
                # CDN edge nodes often stall a beat before responding to a
                # cold connection.
                first_read_deadline = max(1.5, min(float(timeout), 4.0))
                next_read_deadline = max(0.5, min(float(timeout), 2.0))
                header_end = -1
                first_chunk = True
                while True:
                    deadline = first_read_deadline if first_chunk else next_read_deadline
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=deadline)
                    first_chunk = False
                    if not chunk:
                        break
                    resp_buf.extend(chunk)
                    if header_end == -1:
                        idx = resp_buf.find(b"\r\n\r\n")
                        if idx != -1:
                            header_end = idx + 4
                    # Scanner.classify_response wants enough body to find
                    # domain tokens; cap at 8 KiB to stay light.
                    if header_end != -1 and len(resp_buf) >= header_end + 4096:
                        break
                    if len(resp_buf) >= 8192:
                        break
                # Reject only on a *definitive* HTTP-layer denial (1034 / 403
                # permission / region block / "edge IP restricted"). If the
                # probe just times out or returns nothing parseable, trust
                # the TLS handshake we already completed — being too eager
                # to reject empties the candidate pool on slow links.
                if resp_buf:
                    verdict = classify_response(bytes(resp_buf), domain)
                    if verdict == 'reject':
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except Exception:
                            pass
                        return None
            except Exception:
                # Probe read timed out or the peer closed early. The TLS
                # handshake itself succeeded, so treat the IP as TLS-verified
                # rather than rejecting outright.
                pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if tls_only:
            return ip
        return ip, port
    except Exception:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        return None

async def verify_native_target(host, port=443, timeout=config.RACE_TIMEOUT):
    """
    Verifies native reachability. Uses strict TLS so that ISP DNS hijacks 
    and transparent filtering proxies are correctly identified as blocked.
    """
    tasks = []

    async def _cancel_and_drain(task_set):
        if not task_set: return
        for task in task_set: task.cancel()
        await asyncio.gather(*task_set, return_exceptions=True)
    
    async def _attempt(candidate, srv_host=None):
        try:
            # CRITICAL FIX: Use strict=True. If the ISP hijacks the connection and serves a fake cert,
            # this will throw an SSLError, correctly failing the native route and triggering the proxy.
            ctx = get_tls_context(strict=True) if config.is_tls_port(port) else None
            _, w = await asyncio.wait_for(
                asyncio.open_connection(host=candidate, port=port, ssl=ctx, server_hostname=srv_host),
                timeout=timeout
            )
            w.close()
            await w.wait_closed()
            return host 
        except Exception:
            return None

    try:
        ipaddress.ip_address(host)
    except ValueError:
        async def _resolve_and_attempt():
            try:
                resolved_ipv4 = await resolve_target(host, port)
                if resolved_ipv4 != host:
                    return await _attempt(resolved_ipv4, srv_host=host if config.is_tls_port(port) else None)
            except Exception: pass
            return None
        tasks.append(asyncio.create_task(_resolve_and_attempt()))

    tasks.append(asyncio.create_task(_attempt(host, srv_host=host if config.is_tls_port(port) else None)))

    winner = None
    pending = set(tasks)
    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            try:
                res = t.result()
                if res and not winner:
                    winner = res
            except Exception: pass
        if winner: break

    await _cancel_and_drain(pending)
    return winner

async def _timed_verify_sni(ep_ip: str, sni_host: str, ep_port: int, timeout: float, http_verify: bool = False):
    t0 = time.monotonic()
    result = await verify_sni(ep_ip, sni_host, ep_port, timeout=timeout, http_verify=http_verify)
    latency_ms = (time.monotonic() - t0) * 1000
    return result, latency_ms


def _normalize_endpoint(endpoint):
    if not endpoint:
        return None
    if isinstance(endpoint, tuple) and len(endpoint) >= 2:
        try:
            return (str(endpoint[0]), int(endpoint[1]))
        except (TypeError, ValueError):
            return None
    return None


def _purge_l2_route(host_lower, base, registrable, bad_endpoint):
    """Remove disk-backed exact/wildcard entries that point at ``bad_endpoint``."""
    bad_ip, bad_port = bad_endpoint
    exact = STATE.exact_routes()
    wild = STATE.wildcard_routes()
    purged = False

    for store, keys in (
        (exact, (host_lower, base, registrable)),
        (wild, (f".{base}", f".{registrable}")),
    ):
        for k in keys:
            if not k:
                continue
            pm = store.get(k)
            if isinstance(pm, dict) and pm.get(bad_port) == bad_ip:
                pm.pop(bad_port, None)
                if not pm:
                    store.pop(k, None)
                purged = True
    return purged


def mark_route_dead(host, port, bad_endpoint):
    """Use-time hard failure: the chosen IP failed to connect at all.

    Evicts the L1 cache, purges any matching exact/wildcard L2 entries that
    point at ``bad_endpoint``, and demotes the endpoint heavily so the next
    resolution races for a fresh IP. Persisted only in-memory; the routes
    file is rewritten the next time a winner is found.
    """
    ep = _normalize_endpoint(bad_endpoint)
    if not host or not ep:
        return
    host_lower = host.lower()
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return

    _ROUTE_L1_CACHE.pop((host_lower, port_int), None)

    stats = _get_endpoint_stats(ep)
    weight = max(1, int(getattr(config, 'ROUTE_CONNECT_FAIL_WEIGHT', 6)))
    stats.fail_count = min(50, stats.fail_count + weight)
    key = _endpoint_key(ep)
    _IP_HEALTH_SCORES[key] = max(-100, _IP_HEALTH_SCORES.get(key, 0) - 8)

    base = (get_base_domain(host_lower) or host_lower).strip('.').lower()
    registrable = _get_registrable_domain(host_lower)
    _purge_l2_route(host_lower, base, registrable, ep)


def mark_route_slow(host, port, bad_endpoint):
    """Use-time soft failure: the IP connected but the download stalled or
    delivered no bytes. Evict the L1 entry and demote the endpoint a little so
    the next request re-races, but leave the disk-backed maps alone — a single
    slow request shouldn't permanently retire an otherwise-healthy IP.
    """
    ep = _normalize_endpoint(bad_endpoint)
    if not host or not ep:
        return
    host_lower = host.lower()
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return

    _ROUTE_L1_CACHE.pop((host_lower, port_int), None)
    stats = _get_endpoint_stats(ep)
    weight = max(1, int(getattr(config, 'ROUTE_SLOW_FAIL_WEIGHT', 2)))
    stats.fail_count = min(50, stats.fail_count + weight)
    key = _endpoint_key(ep)
    _IP_HEALTH_SCORES[key] = max(-100, _IP_HEALTH_SCORES.get(key, 0) - 4)


async def get_routed_ip(target_host, target_port, forbidden_eps=None):
    ensure_locks()
    target_host_lower = target_host.lower()
    forbidden_eps = forbidden_eps or set()
    
    # 1. Localhost/IP bypass - Return fully qualified tuple natively
    if target_host_lower in ('localhost', '127.0.0.1'): return target_host_lower, target_port
    try: 
        ipaddress.ip_address(target_host_lower)
        return target_host_lower, target_port
    except ValueError: pass

    is_video_shard = target_host_lower.endswith(get_video_cdn_tuple()) and not target_host_lower.startswith('www.')

    base_domain = get_base_domain(target_host_lower)
    registrable_domain = _get_registrable_domain(target_host_lower)
    _ensure_route_policy_cache()

    # 2. Pattern-driven force routing rules
    matched_always = _matches_any_compiled(target_host_lower, registrable_domain, _ROUTE_POLICY_CACHE['always'])
    matched_native = _matches_any_compiled(target_host_lower, registrable_domain, _ROUTE_POLICY_CACHE['do_not'])

    force_white = bool(matched_always)
    force_native = bool(matched_native) and not force_white
    is_sensitive_host = target_host_lower in _SENSITIVE_DOMAINS or target_host_lower.endswith(_SENSITIVE_TUPLE)

    if force_white and matched_native:
        print(f"[RULE] {target_host_lower} matched both lists ({matched_always} / {matched_native}) -> ALWAYS_ROUTE wins.")

    if force_native:
        print(f"[RULE] {target_host_lower} matched DO_NOT_ROUTE ({matched_native}) -> native route.")
        return target_host_lower, target_port

    # Local dictionary mapping for tighter loops
    exact_routes = STATE.exact_routes()
    wildcard_routes = STATE.wildcard_routes()
    banned_for_domain = set()
    ban_lookup_keys = (registrable_domain, base_domain, target_host_lower)
    for dom_key in ban_lookup_keys:
        for entry in STATE.banned_routes().get(dom_key, set()):
            # Handle both raw strings from disk and tuples from memory
            ep = entry if isinstance(entry, tuple) else parse_ip_port(entry)
            if ep and ep[1] == target_port:
                banned_for_domain.add(ep)

    # 3. L1 in-memory route cache (TTL + health eviction).
    # If the caller passed forbidden_eps (a retry after a connect-time
    # failure), bypass L1 entirely and force a re-race — otherwise we'd
    # just hand back the same dead IP.
    if not forbidden_eps:
        fast_cached = _l1_route_get(target_host_lower, target_port, banned_for_domain, force_white)
        if fast_cached:
            return fast_cached

    # 4. L2 persistent route cache from disk-backed maps (exact + wildcard).
    # Skip the disk cache entirely on a retry — it can hold the same kind of
    # bad IP that just failed, and we want a fresh race instead of digging
    # through stale entries one at a time.
    seeded_cached_ep = None
    if not is_video_shard and not forbidden_eps:
        cached_ep = None
        cache_source = None

        # Check Exact Matches
        port_map = _get_port_map(exact_routes, target_host_lower)
        if port_map:
            if target_port in port_map:
                cached_ep = (port_map[target_port], target_port)
                cache_source = 'exact'
            elif config.is_tls_port(target_port):
                # Target is TLS, but requested port isn't cached. Find *any* mapped TLS endpoint
                for p, ip in port_map.items():
                    if config.is_tls_port(p):
                        cached_ep = (ip, p)
                        cache_source = 'exact'
                        break

        # Check Wildcard Matches
        if not cached_ep:
            parts = target_host_lower.split('.')
            for i in range(len(parts) - 1):
                port_map = _get_port_map(wildcard_routes, '.' + '.'.join(parts[i:]))
                if port_map:
                    if target_port in port_map:
                        cached_ep = (port_map[target_port], target_port)
                        cache_source = 'wildcard'
                        break
                    elif config.is_tls_port(target_port):
                        for p, ip in port_map.items():
                            if config.is_tls_port(p):
                                cached_ep = (ip, p)
                                cache_source = 'wildcard'
                                break
                if cached_ep:
                    break

        if cached_ep:
            ep_key = (cached_ep[0], cached_ep[1])
            ep_stats = _EP_REGISTRY.get(ep_key)
            fail_count = ep_stats.fail_count if ep_stats else 0
            if _is_endpoint_banned_for_target(ep_key, target_port, banned_for_domain):
                print(f"[*] Cached endpoint {format_ip_port(*cached_ep)} is BANNED for {registrable_domain}. Forcing new race...")
            elif fail_count < getattr(config, 'ROUTE_EVICT_FAIL_THRESHOLD', 6):
                # Trust the L2 entry on the cold path. A genuinely bad cached
                # IP is caught downstream: the proxy's connect-time failover
                # calls mark_route_dead (purges L1+L2 and re-races), and the
                # relay's TTFB/no-data watchdog calls mark_route_slow on the
                # download leg. Adding a synchronous TLS+HTTP probe here was
                # too costly on every cold cache hit.
                print(f"[⚡ CACHED] {target_host_lower} -> {format_ip_port(*cached_ep)}")
                _l1_route_set(target_host_lower, target_port, cached_ep)
                return cached_ep
            elif cache_source == 'wildcard' and is_sensitive_host and target_host_lower not in exact_routes:
                seeded_cached_ep = ep_key
            else:
                print(f"[*] Cached endpoint {format_ip_port(*cached_ep)} has poor health for {target_host_lower}. Re-racing...")

    # 5. Dedup lock + 6. resolve() staged race pipeline
    if config.is_tls_port(target_port):
        lock_key = f"{target_host_lower}:{target_port}"
        # Retry callers (those with forbidden_eps) must NOT join an in-flight
        # race — that race may resolve to the same forbidden IP. Skip dedup.
        if not forbidden_eps and lock_key in config._RACE_LOCKS:
            try:
                return await config._RACE_LOCKS[lock_key]
            except BaseException:
                return None

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        config._RACE_LOCKS[lock_key] = future

        try:
            is_video_domain = target_host_lower in config.VIDEO_CDN_DOMAINS or target_host_lower.endswith(get_video_cdn_tuple())
            race_timeout = config.VIDEO_RACE_TIMEOUT if is_video_domain else config.RACE_TIMEOUT
            winner_ep = None
            is_alias_fallback = False

            primary_eps = []
            fallback_eps = []
            if config.CONNECTION_MODE in ('white_ip', 'mixed'):
                primary_eps, fallback_eps = _prepare_candidates(
                    target_port,
                    banned_for_domain,
                    is_sensitive_host=is_sensitive_host,
                    is_video_domain=is_video_domain,
                    seed_endpoint=seeded_cached_ep,
                    forbidden_eps=forbidden_eps,
                )

            sni_timeout = min(race_timeout, getattr(config, 'RACE_PER_IP_TIMEOUT', 2.5))
            # An IP can pass TLS yet still serve 403 / Cloudflare 1034 / "edge
            # IP restricted" at the HTTP layer for the requested hostname. We
            # verify at HTTP level for every race candidate so those IPs lose
            # the race instead of becoming the cached winner.
            http_verify_enabled = bool(getattr(config, 'ROUTE_HTTP_VERIFY_RACE', True))

            async def _race_batch(eps, batch_size):
                if not eps:
                    return None

                local_batch_size = _effective_batch_size(batch_size, len(eps))
                if local_batch_size <= 0:
                    return None

                for i in range(0, len(eps), local_batch_size):
                    batch = eps[i:i + local_batch_size]
                    async with config.RACE_SEMAPHORE:
                        tasks = {
                            asyncio.create_task(_timed_verify_sni(ep[0], target_host_lower, ep[1], timeout=sni_timeout, http_verify=http_verify_enabled)): ep
                            for ep in batch
                        }
                        try:
                            pending = set(tasks.keys())
                            while pending:
                                done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
                                for t in done:
                                    ep = tasks[t]
                                    try:
                                        res, latency_ms = t.result()
                                    except Exception:
                                        _record_endpoint_failure(ep)
                                        _record_race_outcome(False, float(sni_timeout) * 1000.0, sni_timeout)
                                        continue
                                    _record_race_outcome(bool(res), float(latency_ms), sni_timeout)
                                    if res:
                                        _record_endpoint_success(ep, latency_ms=latency_ms)
                                        for p in pending:
                                            p.cancel()
                                        await asyncio.gather(*pending, return_exceptions=True)
                                        return res
                                    _record_endpoint_failure(ep)
                        finally:
                            for t in tasks:
                                if not t.done():
                                    t.cancel()
                            await asyncio.gather(*tasks.keys(), return_exceptions=True)
                return None

            if not force_white:
                native_task = asyncio.create_task(verify_native_target(target_host_lower, target_port, timeout=race_timeout))
                try:
                    done, pending = await asyncio.wait(
                        {native_task},
                        timeout=getattr(config, 'RACE_NATIVE_HEADSTART_SEC', 0.3),
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    for t in done:
                        try:
                            native_res = t.result()
                            if native_res:
                                winner_ep = native_res
                                print(f"[🌐 NORMAL] {target_host_lower} is accessible natively.")
                        except Exception:
                            pass
                    if pending:
                        for p in pending:
                            p.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
                except Exception:
                    try:
                        native_task.cancel()
                    except Exception:
                        pass

            if not winner_ep:
                winner_ep = await _race_batch(primary_eps, getattr(config, 'RACE_BATCH_PRIMARY', 6))
            if not winner_ep and fallback_eps:
                print(f"[*] Primary race failed. Attempting fallback race for {target_host_lower}...")
                winner_ep = await _race_batch(fallback_eps, getattr(config, 'RACE_BATCH_FALLBACK', 4))

            # Special Alias fallback for Google APIs
            is_turns_domain = target_host_lower == 'turns.goog' or target_host_lower.endswith('.turns.goog')
            if not winner_ep and is_turns_domain and primary_eps:
                print(f"[*] turns.goog direct race failed. Attempting Google SNI alias fallback for {target_host_lower}...")
                alias_coros = [
                    verify_sni(ep[0], 'www.google.com', ep[1], timeout=race_timeout)
                    for ep in primary_eps[:3]
                ]
                async with config.RACE_SEMAPHORE:
                    pending_alias = {asyncio.create_task(c) for c in alias_coros}
                    try:
                        while pending_alias and not winner_ep:
                            done, pending_alias = await asyncio.wait(pending_alias, return_when=asyncio.FIRST_COMPLETED)
                            for t in done:
                                try:
                                    res = t.result()
                                    if res and not winner_ep:
                                        winner_ep = res
                                        is_alias_fallback = True
                                except Exception:
                                    pass
                    finally:
                        if pending_alias:
                            for t in pending_alias:
                                t.cancel()
                            await asyncio.gather(*pending_alias, return_exceptions=True)
                    
            # Post-Race Routing
            if winner_ep:
                # Unpack tuple safely
                if isinstance(winner_ep, tuple):
                    winner_ip, winner_port = winner_ep
                else:
                    winner_ip, winner_port = winner_ep, target_port
                    
                winner_tuple = (winner_ip, winner_port)
                
                if winner_ip == target_host_lower:
                    result = target_host_lower, target_port
                elif is_alias_fallback:
                    print(f"[🔄 ALIAS] {target_host_lower} -> {winner_tuple} (google.com SNI alias — Chrome verifies turns.goog TLS)")
                    result = winner_tuple
                else:
                    _set_route(exact_routes, target_host_lower, winner_port, winner_ip)
                    _record_endpoint_success(winner_tuple)

                    if not is_video_shard:
                        wildcard_key = f".{registrable_domain}"
                        route_map = _get_port_map(wildcard_routes, wildcard_key)
                        if not route_map or winner_port not in route_map:
                            _set_route(wildcard_routes, wildcard_key, winner_port, winner_ip)
                            _set_route(exact_routes, registrable_domain, winner_port, winner_ip)
                            await async_rewrite_routes(exact_routes, wildcard_routes)
                    print(f"[🔥 ROUTE] {target_host_lower} -> {format_ip_port(winner_ip, winner_port)}")
                    result = winner_tuple
            else:
                if target_host_lower not in STATE.failed_domains():
                    STATE.add_failed_domain(target_host_lower)
                    await async_append_fail_log(target_host_lower)
                    print(f"[❌ FAILED] {target_host_lower} won't open directly nor with White CDN IPs.")
                if seeded_cached_ep:
                    _record_endpoint_failure(seeded_cached_ep)
                
                # ANTI-HIJACK PROTECTION
                if config.is_tls_port(target_port):
                    result = None
                else:
                    result = target_host_lower, target_port

            _l1_route_set(target_host_lower, target_port, result)
                
            if not future.done():
                future.set_result(result)
            return result
        except asyncio.CancelledError:
            if not future.done(): future.cancel()
            raise
        except BaseException:
            if not future.done(): future.set_result(None)
            raise
        finally: 
            config._RACE_LOCKS.pop(lock_key, None)
            
    return target_host_lower, target_port

# ==========================================
# === END OF FILE ===
# ==========================================
