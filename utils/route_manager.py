import os
import json
import socket
import asyncio
import ipaddress
import ssl
import re
import fnmatch
import time
from dataclasses import dataclass, field

from utils import config
from utils import paths
from utils import storage
from utils import data_store
from utils.runtime_state import STATE
from utils.helpers import get_base_domain, parse_ip_port, format_ip_port, add_ban_entry
from cores.scanner import probe_route_endpoint

# ==========================================
# GLOBAL CACHES & TUPLES (PERFORMANCE)
# ==========================================
_TLS_CTX_STRICT = None

_HAS_TO_THREAD = hasattr(asyncio, "to_thread")  # Cached once – never changes at runtime
_LOCKS_INITIALIZED = False
_SENSITIVE_DOMAINS = ('google.com', 'chatgpt.com', 'openai.com', 'claude.ai', 'notebooklm.google.com')
_SENSITIVE_TUPLE = tuple('.' + d for d in _SENSITIVE_DOMAINS)
_PROBE_EXCLUDED_SUBDOMAINS = (
    'fonts.googleapis.com',
    'apis.google.com',
)
_ROUTE_POLICY_CACHE_VERSION = -1
_ROUTE_POLICY_CACHE = {
    'always': {'exact': set(), 'glob': [], 'regex': []},
    'do_not': {'exact': set(), 'glob': [], 'regex': []},
}
_MAX_PRIMARY_CANDIDATES_DEFAULT = 12
_MAX_PRIMARY_CANDIDATES_SENSITIVE = 15
_MAX_FALLBACK_CANDIDATES = 6
_HOST_HTTP_REVERIFY = (
    "gemini.google.com",
    "bard.google.com",
    "aistudio.google.com",
    "ai.google.dev",
    "notebooklm.google.com",
)
_HOST_VERIFY_CACHE = {}
_HOST_VERIFY_PASS_TTL_SEC = 75.0
_HOST_VERIFY_FAIL_TTL_SEC = 20.0

# Router debug session state (lightweight counters + per-domain stats)
_ROUTER_SESSION = {
    'start_ts': time.time(),
    'requests': 0,
    'hot_starts': 0,
    'cold_starts': 0,
    'l1_hits': 0,
    'l2_hits': 0,
    'native_wins': 0,
    'white_wins': 0,
    'race_started': 0,
    'race_wins': 0,
    'race_failures': 0,
    'reroutes': 0,
    'mark_dead': 0,
    'mark_slow': 0,
    'reverify_failures': 0,
    'race_time_ms': [],
    'reroute_time_ms': [],
    'selected_latency_ms': [],
    'domains': {},
    'logs': [],
}


def _normalize_route_domain(domain):
    return (domain or "").strip().lower().strip(".")


def _validate_server_hostname(server_hostname):
    host = _normalize_route_domain(server_hostname)
    if not host or len(host) > 253:
        return None
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    try:
        host.encode("idna")
    except UnicodeError:
        return None
    for label in host.split("."):
        if not label or len(label) > 63:
            return None
        if label.startswith("-") or label.endswith("-"):
            return None
    return host


def _default_domain_state():
    return {
        'ewma_latency_ms': 9999.0,
        'fail_count': 0,
        'last_ok_ts': 0.0,
        'success_count': 0,
        'consecutive_failures': 0,
        'last_fail_ts': 0.0,
        'last_fail_reason': "",
        'quarantine_ts': 0.0,
        'quarantine_reason': "",
        'quarantine_until': 0.0,
        'quarantine_count': 0,
        'last_quarantine_duration_sec': 0.0,
        'last_quarantine_ts': 0.0,
    }


def _route_probe_timeout_cap_sec():
    max_race_ms = getattr(config, "ROUTE_MAX_RACE_MS", None)
    if max_race_ms is None:
        max_race_ms = int(float(getattr(config, "RACE_TIMEOUT", 8.0)) * 1000.0)
    try:
        max_race_ms = float(max_race_ms)
    except (TypeError, ValueError):
        max_race_ms = float(getattr(config, "RACE_TIMEOUT", 8.0)) * 1000.0
    return max(0.1, max_race_ms / 1000.0)


def _bounded_route_probe_timeout(timeout):
    cap = _route_probe_timeout_cap_sec()
    if timeout is None:
        return cap
    try:
        requested = float(timeout)
    except (TypeError, ValueError):
        return cap
    return max(0.1, min(requested, cap))


async def _close_stream_writer(writer, timeout=None):
    if writer is None:
        return
    try:
        writer.close()
    except Exception:
        pass
    wait_closed = getattr(writer, "wait_closed", None)
    if wait_closed is None:
        return
    try:
        await asyncio.wait_for(wait_closed(), timeout=_bounded_route_probe_timeout(timeout))
    except Exception:
        pass


def _quarantine_reason_kind(reason: str):
    rl = _normalize_failure_reason(reason)
    if "connect-error" in rl or "connect-failed" in rl or "connection error" in rl:
        return "connect-error"
    if "timeout" in rl:
        return "timeout"
    if "tls-error" in rl or "ssl error" in rl:
        return "tls-error"
    if "http-reject" in rl or "reject" in rl:
        return "http-reject"
    return "generic"


def _compute_quarantine_ttl(reason, state=None, requested_ttl=None):
    rl = _normalize_failure_reason(reason)
    if _is_soft_perf_failure_reason(rl):
        return 0.0
    if "http-reject" in rl or "reject" in rl:
        return 0.0

    kind = _quarantine_reason_kind(rl)
    if kind == "connect-error":
        base_ttl = float(getattr(config, "ROUTE_QUARANTINE_CONNECT_BASE_SEC", 600.0))
    elif kind == "tls-error":
        base_ttl = float(getattr(config, "ROUTE_QUARANTINE_TLS_BASE_SEC", 900.0))
    elif kind == "timeout":
        base_ttl = float(getattr(config, "ROUTE_QUARANTINE_TIMEOUT_BASE_SEC", 600.0))
    else:
        base_ttl = float(getattr(config, "ROUTE_QUARANTINE_SEVERE_BASE_SEC", 300.0))

    state = state or {}
    quarantine_count = int(state.get("quarantine_count", 0))
    exp_cap = int(getattr(config, "ROUTE_QUARANTINE_BACKOFF_CAP", 8))
    backoff_exp = max(0, min(quarantine_count, exp_cap))
    ttl_s = base_ttl * (2.0 ** backoff_exp)
    ttl_s = min(ttl_s, float(getattr(config, "ROUTE_QUARANTINE_BACKOFF_MAX_SEC", 86400.0)))
    if requested_ttl is not None:
        try:
            ttl_s = max(ttl_s, float(requested_ttl))
        except (TypeError, ValueError):
            pass
    return max(0.0, ttl_s)


def _apply_quarantine_state(state, reason, now_mono, ttl_s):
    state["quarantine_ts"] = now_mono
    state["quarantine_until"] = now_mono + ttl_s if ttl_s > 0 else 0.0
    state["quarantine_reason"] = (reason or "").strip().lower()
    state["last_quarantine_ts"] = now_mono
    state["last_quarantine_duration_sec"] = float(ttl_s)
    state["quarantine_count"] = max(0, int(state.get("quarantine_count", 0))) + 1
    return state


@dataclass
class EndpointStats:
    domain_state: dict = field(default_factory=dict)

    def _domain_key(self, domain):
        return _normalize_route_domain(domain)

    def _state(self, domain, create=True):
        key = self._domain_key(domain)
        if not key:
            return None
        state = self.domain_state.get(key)
        if state is None and create:
            state = _default_domain_state()
            self.domain_state[key] = state
        return state

    def is_quarantined(self, now=None, domain=None):
        now_mono = now if now is not None else time.monotonic()
        state = self._state(domain, create=False)
        if not state:
            return False
        quarantine_until = float(state.get("quarantine_until", 0.0) or 0.0)
        if quarantine_until > 0.0:
            if now_mono <= quarantine_until:
                return True
            state["quarantine_ts"] = 0.0
            state["quarantine_until"] = 0.0
            state["quarantine_reason"] = ""
            state["consecutive_failures"] = 0
            return False

        if not state.get("quarantine_ts"):
            return False

        ttl_s = _compute_quarantine_ttl(state.get("quarantine_reason", ""), state=state)
        if ttl_s <= 0:
            state["quarantine_ts"] = 0.0
            state["quarantine_until"] = 0.0
            state["quarantine_reason"] = ""
            state["consecutive_failures"] = 0
            return False

        if now_mono > (state["quarantine_ts"] + ttl_s):
            state["quarantine_ts"] = 0.0
            state["quarantine_until"] = 0.0
            state["quarantine_reason"] = ""
            state["consecutive_failures"] = 0
            return False
        return True

    def quarantine(self, domain, reason: str, ttl: float | None = None, now=None):
        now_mono = now if now is not None else time.monotonic()
        state = self._state(domain, create=True)
        if state is None:
            return None
        ttl_s = _compute_quarantine_ttl(reason, state=state, requested_ttl=ttl)
        if ttl_s <= 0:
            return state
        _apply_quarantine_state(state, reason, now_mono, ttl_s)
        return state

    def clear_quarantine(self, domain):
        state = self._state(domain, create=False)
        if not state:
            return
        state["quarantine_ts"] = 0.0
        state["quarantine_until"] = 0.0
        state["quarantine_reason"] = ""

    def score(self, now=None, domain=None, endpoint=None):
        now_mono = now if now is not None else time.monotonic()
        state = self._state(domain, create=False)
        if self.is_quarantined(now_mono, domain=domain):
            return float("inf")

        if not state:
            if endpoint is not None:
                known_latency = _endpoint_known_latency_ms(endpoint)
                latency_penalty = known_latency if known_latency is not None else getattr(config, "ROUTE_SCORE_NEUTRAL_LATENCY_MS", 700.0)
            else:
                latency_penalty = getattr(config, "ROUTE_SCORE_NEUTRAL_LATENCY_MS", 700.0)
        else:
            latency_penalty = state.get("ewma_latency_ms", 9999.0)
            if latency_penalty >= 9999.0:
                if endpoint is not None:
                    known_latency = _endpoint_known_latency_ms(endpoint)
                    latency_penalty = known_latency if known_latency is not None else getattr(config, "ROUTE_SCORE_NEUTRAL_LATENCY_MS", 700.0)
                else:
                    latency_penalty = getattr(config, "ROUTE_SCORE_NEUTRAL_LATENCY_MS", 700.0)

        fail_penalty = min(
            max(0, state.get("fail_count", 0) if state else 0),
            getattr(config, "ROUTE_SCORE_FAIL_CAP", 8),
        ) * getattr(config, 'ROUTE_SCORE_FAIL_WEIGHT', 250.0)

        recency_penalty = 0.0
        if state and state.get("success_count", 0) > 0 and state.get("last_ok_ts", 0.0) > 0:
            recency_age = max(0.0, now_mono - state["last_ok_ts"])
            recency_penalty = min(
                recency_age,
                getattr(config, 'ROUTE_SCORE_RECENCY_CAP_SEC', 120.0),
            ) * getattr(config, 'ROUTE_SCORE_RECENCY_WEIGHT', 3.0)
        return (
            (latency_penalty * getattr(config, 'ROUTE_SCORE_LATENCY_WEIGHT', 1.0))
            + fail_penalty
            + recency_penalty
        )


def _router_debug_enabled():
    return bool(getattr(config, 'ROUTER_DEBUG', False))


def router_debug_log(host, message, include_ts=False):
    if not _router_debug_enabled():
        return
    host_label = (host or '?').strip()
    ts_unix = time.time()
    ts = time.strftime('%Y-%m-%d %H:%M:%S') if include_ts else None
    _ROUTER_SESSION['logs'].append({
        'ts': ts_unix,
        'host': host_label,
        'message': message,
    })
    if ts:
        print(f"[ROUTER-DEBUG] {host_label} | {ts} | {message}")
    else:
        print(f"[ROUTER-DEBUG] {host_label} | {message}")


def _session_domain_stats(host):
    host_key = (host or '').strip().lower() or '?'
    stats = _ROUTER_SESSION['domains'].get(host_key)
    if stats is None:
        stats = {
            'requests': 0,
            'hot_starts': 0,
            'cold_starts': 0,
            'l1_hits': 0,
            'l2_hits': 0,
            'race_wins': 0,
            'failures': 0,
            'last_choice': None,
        }
        _ROUTER_SESSION['domains'][host_key] = stats
    return stats


def _session_record_request(host, hot_start):
    _ROUTER_SESSION['requests'] += 1
    if hot_start:
        _ROUTER_SESSION['hot_starts'] += 1
    else:
        _ROUTER_SESSION['cold_starts'] += 1
    dom = _session_domain_stats(host)
    dom['requests'] += 1
    if hot_start:
        dom['hot_starts'] += 1
    else:
        dom['cold_starts'] += 1


def _session_record_cache_hit(host, cache_kind):
    if cache_kind == 'l1':
        _ROUTER_SESSION['l1_hits'] += 1
    elif cache_kind == 'l2':
        _ROUTER_SESSION['l2_hits'] += 1
    dom = _session_domain_stats(host)
    if cache_kind == 'l1':
        dom['l1_hits'] += 1
    elif cache_kind == 'l2':
        dom['l2_hits'] += 1


def _session_record_race(host, duration_ms=None, winner=None):
    _ROUTER_SESSION['race_started'] += 1
    if duration_ms is not None:
        _ROUTER_SESSION['race_time_ms'].append(float(duration_ms))
    if winner:
        _ROUTER_SESSION['race_wins'] += 1
        dom = _session_domain_stats(host)
        dom['race_wins'] += 1
        dom['last_choice'] = winner
    else:
        _ROUTER_SESSION['race_failures'] += 1


def _session_record_selection(host, winner, latency_ms=None):
    if winner:
        dom = _session_domain_stats(host)
        dom['last_choice'] = winner
    if latency_ms is not None:
        _ROUTER_SESSION['selected_latency_ms'].append(float(latency_ms))


def _session_record_failure(host):
    dom = _session_domain_stats(host)
    dom['failures'] += 1


def _session_record_reroute(duration_ms=None):
    _ROUTER_SESSION['reroutes'] += 1
    if duration_ms is not None:
        _ROUTER_SESSION['reroute_time_ms'].append(float(duration_ms))


def record_reroute(duration_ms=None):
    _session_record_reroute(duration_ms=duration_ms)


def _session_record_mark(kind):
    if kind == 'dead':
        _ROUTER_SESSION['mark_dead'] += 1
    elif kind == 'slow':
        _ROUTER_SESSION['mark_slow'] += 1


def _session_record_native_win():
    _ROUTER_SESSION['native_wins'] += 1


def _session_record_white_win():
    _ROUTER_SESSION['white_wins'] += 1


def _session_record_reverify_failure():
    _ROUTER_SESSION['reverify_failures'] += 1


def _fmt_ms(values):
    if not values:
        return "n/a"
    avg = sum(values) / max(1, len(values))
    return f"{avg:.1f}ms"


def _fmt_ms_value(values):
    if not values:
        return None
    return float(sum(values) / max(1, len(values)))


def _serialize_choice(choice):
    if isinstance(choice, tuple) and len(choice) >= 2:
        return format_ip_port(choice[0], choice[1])
    return choice


def get_router_session_report():
    now = time.time()
    uptime = max(0.0, now - _ROUTER_SESSION['start_ts'])
    requests = _ROUTER_SESSION['requests']
    hot = _ROUTER_SESSION['hot_starts']
    cold = _ROUTER_SESSION['cold_starts']
    l1 = _ROUTER_SESSION['l1_hits']
    l2 = _ROUTER_SESSION['l2_hits']
    races = _ROUTER_SESSION['race_started']
    race_wins = _ROUTER_SESSION['race_wins']
    race_fail = _ROUTER_SESSION['race_failures']
    native = _ROUTER_SESSION['native_wins']
    white = _ROUTER_SESSION['white_wins']
    reroutes = _ROUTER_SESSION['reroutes']
    mark_dead = _ROUTER_SESSION['mark_dead']
    mark_slow = _ROUTER_SESSION['mark_slow']
    reverify_fail = _ROUTER_SESSION['reverify_failures']

    lines = [
        "[ROUTER-REPORT] Routing session summary",
        f"Uptime: {uptime:.1f}s",
        f"Requests: {requests} (hot {hot}, cold {cold})",
        f"Cache hits: L1 {l1}, L2 {l2}",
        f"Races: {races} (wins {race_wins}, fails {race_fail}, avg { _fmt_ms(_ROUTER_SESSION['race_time_ms']) })",
        f"Selections: native {native}, white {white}, avg selected latency { _fmt_ms(_ROUTER_SESSION['selected_latency_ms']) }",
        f"Reroutes: {reroutes}, avg swap { _fmt_ms(_ROUTER_SESSION['reroute_time_ms']) }",
        f"Health marks: dead {mark_dead}, slow {mark_slow}, reverify failures {reverify_fail}",
    ]

    if _ROUTER_SESSION['domains']:
        top = sorted(
            _ROUTER_SESSION['domains'].items(),
            key=lambda item: (item[1].get('requests', 0), item[0]),
            reverse=True,
        )[:5]
        lines.append("Top domains (by requests):")
        for dom, stats in top:
            last_choice = stats.get('last_choice')
            last_label = format_ip_port(*last_choice) if isinstance(last_choice, tuple) else (last_choice or "-")
            lines.append(
                f"- {dom}: req {stats.get('requests', 0)}, hot {stats.get('hot_starts', 0)}, "
                f"L1 {stats.get('l1_hits', 0)}, L2 {stats.get('l2_hits', 0)}, "
                f"race wins {stats.get('race_wins', 0)}, fails {stats.get('failures', 0)}, last {last_label}"
            )

    return "\n".join(lines)


def get_router_session_report_data():
    now = time.time()
    uptime = max(0.0, now - _ROUTER_SESSION['start_ts'])
    report = {
        'generated_ts': now,
        'uptime_sec': uptime,
        'requests': {
            'total': _ROUTER_SESSION['requests'],
            'hot': _ROUTER_SESSION['hot_starts'],
            'cold': _ROUTER_SESSION['cold_starts'],
        },
        'cache_hits': {
            'l1': _ROUTER_SESSION['l1_hits'],
            'l2': _ROUTER_SESSION['l2_hits'],
        },
        'races': {
            'started': _ROUTER_SESSION['race_started'],
            'wins': _ROUTER_SESSION['race_wins'],
            'fails': _ROUTER_SESSION['race_failures'],
            'avg_ms': _fmt_ms_value(_ROUTER_SESSION['race_time_ms']),
        },
        'selections': {
            'native': _ROUTER_SESSION['native_wins'],
            'white': _ROUTER_SESSION['white_wins'],
            'avg_selected_latency_ms': _fmt_ms_value(_ROUTER_SESSION['selected_latency_ms']),
        },
        'reroutes': {
            'count': _ROUTER_SESSION['reroutes'],
            'avg_swap_ms': _fmt_ms_value(_ROUTER_SESSION['reroute_time_ms']),
        },
        'health_marks': {
            'dead': _ROUTER_SESSION['mark_dead'],
            'slow': _ROUTER_SESSION['mark_slow'],
            'reverify_failures': _ROUTER_SESSION['reverify_failures'],
        },
        'domains': {},
        'top_domains': [],
    }

    if _ROUTER_SESSION['domains']:
        ordered = sorted(
            _ROUTER_SESSION['domains'].items(),
            key=lambda item: (item[1].get('requests', 0), item[0]),
            reverse=True,
        )
        for dom, stats in ordered:
            report['domains'][dom] = {
                'requests': stats.get('requests', 0),
                'hot_starts': stats.get('hot_starts', 0),
                'cold_starts': stats.get('cold_starts', 0),
                'l1_hits': stats.get('l1_hits', 0),
                'l2_hits': stats.get('l2_hits', 0),
                'race_wins': stats.get('race_wins', 0),
                'failures': stats.get('failures', 0),
                'last_choice': _serialize_choice(stats.get('last_choice')),
            }
        for dom, stats in ordered[:5]:
            report['top_domains'].append({
                'domain': dom,
                'requests': stats.get('requests', 0),
                'hot_starts': stats.get('hot_starts', 0),
                'l1_hits': stats.get('l1_hits', 0),
                'l2_hits': stats.get('l2_hits', 0),
                'race_wins': stats.get('race_wins', 0),
                'failures': stats.get('failures', 0),
                'last_choice': _serialize_choice(stats.get('last_choice')),
            })

    return report


def write_router_session_files(report_name="report.json", logs_name="logs.json"):
    try:
        report_payload = get_router_session_report_data()
        data_store.write_json(report_name, report_payload, indent=2)
    except Exception:
        pass
    try:
        logs_payload = {
            'generated_ts': time.time(),
            'logs': list(_ROUTER_SESSION.get('logs', [])),
        }
        data_store.write_json(logs_name, logs_payload, indent=2)
    except Exception:
        pass


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


def _normalize_pool_endpoint(endpoint):
    if not endpoint:
        return None
    if isinstance(endpoint, tuple) and len(endpoint) >= 2:
        try:
            return str(endpoint[0]), int(endpoint[1])
        except (TypeError, ValueError):
            return None
    parsed = parse_ip_port(endpoint)
    if parsed:
        return str(parsed[0]), int(parsed[1])
    return None


def _normalize_pool_domains(domains):
    clean = []
    seen = set()
    for dom in domains or []:
        d = (dom or "").strip().lower().strip(".")
        if not d or d in seen:
            continue
        seen.add(d)
        clean.append(d)
    return tuple(clean)


def _coerce_pool_latency_ms(value):
    if value is None:
        return None
    try:
        latency = float(value)
    except (TypeError, ValueError):
        return None
    if latency <= 0:
        return None
    return latency


def _build_pool_endpoint_meta(domains=None, latency_ms=None):
    clean_domains = _normalize_pool_domains(domains)
    google_verified = any(_is_google_family(dom) for dom in clean_domains)
    google_only = bool(clean_domains) and all(_is_google_family(dom) for dom in clean_domains)
    universal = any(not _is_google_family(dom) for dom in clean_domains)
    return {
        'domains': clean_domains,
        'latency_ms': _coerce_pool_latency_ms(latency_ms),
        'google_verified': google_verified,
        'google_only': google_only,
        'universal': universal,
    }


def _merge_pool_endpoint_meta(existing=None, domains=None, latency_ms=None):
    existing = existing or {}
    merged_domains = list(existing.get('domains') or [])
    for dom in _normalize_pool_domains(domains):
        if dom not in merged_domains:
            merged_domains.append(dom)
    merged_latency = _coerce_pool_latency_ms(latency_ms)
    if merged_latency is None:
        merged_latency = _coerce_pool_latency_ms(existing.get('latency_ms'))
    return _build_pool_endpoint_meta(merged_domains, merged_latency)


def _set_pool_endpoint_meta(endpoint, domains=None, latency_ms=None):
    ep = _normalize_pool_endpoint(endpoint)
    if not ep:
        return None
    meta_store = getattr(config, 'IP_POOL_METADATA', None)
    if not isinstance(meta_store, dict):
        meta_store = {}
        config.IP_POOL_METADATA = meta_store
    meta_store[ep] = _merge_pool_endpoint_meta(meta_store.get(ep), domains=domains, latency_ms=latency_ms)
    return meta_store[ep]


def _get_pool_endpoint_meta(endpoint):
    ep = _normalize_pool_endpoint(endpoint)
    if not ep:
        return _build_pool_endpoint_meta()

    meta_store = getattr(config, 'IP_POOL_METADATA', None)
    if not isinstance(meta_store, dict):
        meta_store = {}
        config.IP_POOL_METADATA = meta_store

    meta = meta_store.get(ep)
    if meta is not None:
        return meta

    pool_hint = None
    try:
        pool_hint = getattr(config, 'IP_POOL', {}).get(ep)
    except Exception:
        pool_hint = None
    if pool_hint is None:
        try:
            pool_hint = STATE.ip_pool().get(ep)
        except Exception:
            pool_hint = None

    if isinstance(pool_hint, dict):
        domains = pool_hint.get('domains')
        latency_ms = pool_hint.get('latency_ms')
    elif isinstance(pool_hint, (list, tuple)) and pool_hint and not isinstance(pool_hint[0], (int, float)):
        domains = pool_hint[0]
        latency_ms = pool_hint[1] if len(pool_hint) > 1 else None
    elif isinstance(pool_hint, str):
        domains = [pool_hint]
        latency_ms = None
    else:
        domains = []
        latency_ms = None

    meta = _build_pool_endpoint_meta(domains=domains, latency_ms=latency_ms)
    meta_store[ep] = meta
    return meta


def _endpoint_known_latency_ms(endpoint):
    ep = _normalize_pool_endpoint(endpoint)
    if not ep:
        return None
    meta = _get_pool_endpoint_meta(ep)
    meta_latency = _coerce_pool_latency_ms(meta.get('latency_ms'))
    return meta_latency


def _target_candidate_priority(endpoint, target_host=None):
    ep = _normalize_pool_endpoint(endpoint)
    if not ep:
        return None
    meta = _get_pool_endpoint_meta(ep)
    target_l = (target_host or "").strip().lower().strip(".")
    known_latency = _endpoint_known_latency_ms(ep)
    ultra_low = known_latency is not None and known_latency <= 800.0
    if _is_google_family(target_l):
        if meta.get('google_verified') and ultra_low:
            return 0
        if meta.get('google_verified'):
            return 1
        if ultra_low:
            return 2
        if meta.get('universal'):
            return 3
        return 4
    if meta.get('universal') and ultra_low:
        return 0
    if meta.get('universal'):
        return 1
    if meta.get('google_verified'):
        return 2
    if ultra_low:
        return 3
    return 4


def _endpoint_allowed_for_target(endpoint, target_host=None):
    ep = _normalize_pool_endpoint(endpoint)
    if not ep:
        return False, 'invalid-endpoint'
    meta = _get_pool_endpoint_meta(ep)
    target_l = (target_host or "").strip().lower().strip(".")
    if _is_google_family(target_l):
        if meta.get('google_verified'):
            return True, 'google-verified'
        if meta.get('universal'):
            return True, 'universal'
    return True, 'eligible'


def _endpoint_probe_timeout_sec(endpoint, target_host=None):
    known_latency_ms = _endpoint_known_latency_ms(endpoint)
    if known_latency_ms is not None:
        headroom_ms = float(getattr(config, 'ROUTE_KNOWN_LATENCY_HEADROOM_MS', 1500.0))
        return max(0.5, (known_latency_ms + headroom_ms) / 1000.0)
    return float(getattr(config, 'RACE_PER_IP_TIMEOUT', 2.5))


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


def _get_endpoint_domain_state(endpoint, domain, create=True):
    return _get_endpoint_stats(endpoint)._state(domain, create=create)


def _endpoint_score(endpoint, now=None, domain=None, allow_quarantined=False):
    ep = _normalize_pool_endpoint(endpoint)
    stats = _EP_REGISTRY.get(ep) if ep else None
    if not stats:
        known_latency = _endpoint_known_latency_ms(ep) if ep else None
        if known_latency is not None:
            return float(known_latency)
        return float(getattr(config, "ROUTE_SCORE_NEUTRAL_LATENCY_MS", 700.0))
    if not allow_quarantined and stats.is_quarantined(now, domain=domain):
        return float("inf")
    return stats.score(now, domain=domain, endpoint=ep)


def _normalize_failure_reason(reason):
    return (reason or "").strip().lower()


def _is_soft_perf_failure_reason(reason):
    rl = _normalize_failure_reason(reason)
    return (
        "no-data" in rl
        or rl.startswith("ttfb")
        or rl == "slow"
        or (" slow" in rl)
    )


def _failure_weight_for_reason(reason):
    rl = _normalize_failure_reason(reason)
    if "no-data" in rl:
        return getattr(config, "ROUTE_NO_DATA_FAIL_WEIGHT", 4.0)
    if "ttfb" in rl or "slow" in rl:
        return getattr(config, "ROUTE_SLOW_FAIL_WEIGHT", 2.0)
    if "connect-error" in rl or "connect-failed" in rl or "connection error" in rl:
        return getattr(config, "ROUTE_CONNECT_FAIL_WEIGHT", 6.0)
    if "timeout" in rl:
        return getattr(config, "ROUTE_FAIL_WEIGHT_TIMEOUT", 8.0)
    if "tls-error" in rl or "ssl error" in rl:
        return getattr(config, "ROUTE_FAIL_WEIGHT_TLS_ERROR", 5.0)
    if "http-reject" in rl or "rejected" in rl or "reject" in rl:
        return getattr(config, "ROUTE_FAIL_WEIGHT_HTTP_REJECT", 4.0)
    return getattr(config, "ROUTE_FAIL_WEIGHT_GENERIC", 3.0)


def _is_severe_failure_reason(reason):
    rl = _normalize_failure_reason(reason)
    return (
        "connect-error" in rl
        or "connect-failed" in rl
        or "timeout" in rl
        or "tls-error" in rl
        or "ssl error" in rl
        or "http-reject" in rl
        or "reject" in rl
    )


def _should_quarantine_endpoint(stats, reason, domain):
    rl = _normalize_failure_reason(reason)
    state = stats._state(domain, create=True)
    if state is None:
        return False
    if _is_soft_perf_failure_reason(rl):
        return False
    if "http-reject" in rl or "reject" in rl:
        return False
    if _is_severe_failure_reason(rl):
        threshold = getattr(config, "ROUTE_QUARANTINE_SEVERE_THRESHOLD", 1)
        return state.get("consecutive_failures", 0) >= threshold
    if "connect-error" in rl or "connect-failed" in rl or "connection error" in rl:
        return state.get("consecutive_failures", 0) >= getattr(config, "ROUTE_QUARANTINE_CONNECT_THRESHOLD", 4)
    if "timeout" in rl:
        return state.get("consecutive_failures", 0) >= getattr(
            config,
            "ROUTE_QUARANTINE_TIMEOUT_THRESHOLD",
            getattr(config, "ROUTE_QUARANTINE_REPEAT_TIMEOUT_THRESHOLD", 3),
        )
    if "tls-error" in rl or "ssl error" in rl:
        return state.get("consecutive_failures", 0) >= getattr(config, "ROUTE_QUARANTINE_TLS_THRESHOLD", 4)
    return state.get("fail_count", 0) >= getattr(config, "ROUTE_QUARANTINE_REPEAT_FAIL_THRESHOLD", 8)


def _quarantine_endpoint(endpoint, domain, reason, ttl=None):
    stats = _get_endpoint_stats(endpoint)
    stats.quarantine(domain, reason, ttl=ttl)
    return stats


def _record_endpoint_success(endpoint, domain, latency_ms=None):
    stats = _get_endpoint_stats(endpoint)
    state = stats._state(domain, create=True)
    if state is None:
        return
    state['success_count'] += 1
    state['last_ok_ts'] = time.monotonic()
    state['fail_count'] = max(0, state['fail_count'] - 1)
    state['consecutive_failures'] = 0
    state['last_fail_reason'] = ""
    state['last_fail_ts'] = 0.0
    state['quarantine_count'] = max(0, int(state.get('quarantine_count', 0)) - 1)
    stats.clear_quarantine(domain)
    key = _endpoint_key(endpoint)
    _IP_HEALTH_SCORES[key] = max(-100, _IP_HEALTH_SCORES.get(key, 0) + 3)
    if latency_ms is not None:
        alpha = getattr(config, 'ROUTE_EWMA_ALPHA', 0.35)
        if state['ewma_latency_ms'] >= 9999.0:
            state['ewma_latency_ms'] = float(latency_ms)
        else:
            state['ewma_latency_ms'] = (alpha * float(latency_ms)) + ((1.0 - alpha) * state['ewma_latency_ms'])


def _record_endpoint_failure(endpoint, domain, reason=None, latency_ms=None):
    stats = _get_endpoint_stats(endpoint)
    state = stats._state(domain, create=True)
    if state is None:
        return
    rl = _normalize_failure_reason(reason)
    weight = _failure_weight_for_reason(rl)
    state['fail_count'] = min(50, state['fail_count'] + max(1, int(round(weight))))
    if _is_soft_perf_failure_reason(rl):
        state['consecutive_failures'] = 0
    else:
        state['consecutive_failures'] += 1
    state['last_fail_reason'] = rl
    state['last_fail_ts'] = time.monotonic()
    key = _endpoint_key(endpoint)
    _IP_HEALTH_SCORES[key] = min(100, _IP_HEALTH_SCORES.get(key, 0) - max(1, int(round(weight * 1.5))))

    if _should_quarantine_endpoint(stats, rl, domain):
        _quarantine_endpoint(endpoint, domain, rl)
        router_debug_log(str(endpoint[0]), f"quarantine {format_ip_port(*endpoint)} ({rl or 'fail'})")
    elif latency_ms is not None and state['ewma_latency_ms'] >= 9999.0:
        state['ewma_latency_ms'] = float(latency_ms)


def _purge_routes_for_endpoint(host, endpoint):
    host_l = (host or "").strip().lower().strip(".")
    ep = _normalize_endpoint(endpoint)
    if not host_l or not ep:
        return False
    base = (get_base_domain(host_l) or host_l).strip(".").lower()
    registrable = _get_registrable_domain(host_l)
    return _purge_l2_route(host_l, base, registrable, ep)


def _needs_host_http_reverify(host):
    host_l = (host or "").strip().lower().strip(".")
    return host_l in _HOST_HTTP_REVERIFY


def _host_verify_cache_get(host, endpoint):
    if not host or not endpoint:
        return None
    key = ((host or "").strip().lower(), str(endpoint[0]), int(endpoint[1]))
    cached = _HOST_VERIFY_CACHE.get(key)
    if not cached:
        return None
    ok, reason, exp = cached
    if exp <= time.monotonic():
        _HOST_VERIFY_CACHE.pop(key, None)
        return None
    return bool(ok), reason


def _host_verify_cache_set(host, endpoint, ok, reason=None):
    if not host or not endpoint:
        return
    ttl = _HOST_VERIFY_PASS_TTL_SEC if ok else _HOST_VERIFY_FAIL_TTL_SEC
    key = ((host or "").strip().lower(), str(endpoint[0]), int(endpoint[1]))
    if len(_HOST_VERIFY_CACHE) > 4096:
        now = time.monotonic()
        stale_keys = [k for k, (_, _, exp) in _HOST_VERIFY_CACHE.items() if exp <= now]
        for stale_key in stale_keys[:1024]:
            _HOST_VERIFY_CACHE.pop(stale_key, None)
        if len(_HOST_VERIFY_CACHE) > 4096:
            for oldest_key in list(_HOST_VERIFY_CACHE.keys())[:512]:
                _HOST_VERIFY_CACHE.pop(oldest_key, None)
    _HOST_VERIFY_CACHE[key] = (bool(ok), _normalize_failure_reason(reason), time.monotonic() + float(ttl))


async def _reverify_cached_endpoint_for_host(host, endpoint, timeout):
    cached_ok = _host_verify_cache_get(host, endpoint)
    if cached_ok is not None:
        ok, cached_reason = cached_ok
        return ok, 0.0, (cached_reason or "cached")
    host_l = _validate_server_hostname(host)
    if not host_l:
        return False, 0.0, "invalid-server-hostname"
    bounded_timeout = _bounded_route_probe_timeout(timeout)
    try:
        result, latency_ms, reason = await asyncio.wait_for(
            probe_route_endpoint(
                endpoint[0],
                host_l,
                port=endpoint[1],
                timeout=bounded_timeout,
                http_verify=True,
                return_reason=True,
            ),
            timeout=bounded_timeout,
        )
    except asyncio.TimeoutError:
        result, latency_ms, reason = None, float(bounded_timeout) * 1000.0, "timeout"
    except Exception:
        result, latency_ms, reason = None, 0.0, "error"
    probe_ok = bool(result)
    _host_verify_cache_set(host_l, endpoint, probe_ok, reason=reason)
    return probe_ok, latency_ms, reason


def _ban_endpoint_for_host(host, endpoint):
    host_l = (host or "").strip().lower().strip(".")
    ep = _normalize_endpoint(endpoint)
    if not host_l or not ep:
        return
    try:
        add_ban_entry(host_l, ep, persist=True)
    except Exception:
        pass


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
        if isinstance(raw_pool, dict):
            raw_iter = raw_pool.items()
        else:
            raw_iter = ((ep, None) for ep in raw_pool)
        for ep, value in raw_iter:
            parsed = _normalize_pool_endpoint(ep)
            if not parsed:
                continue
            if isinstance(value, dict):
                _set_pool_endpoint_meta(parsed, domains=value.get('domains') or value.get('domain') or [], latency_ms=value.get('latency_ms'))
            elif isinstance(value, (list, tuple)) and value and not isinstance(value[0], (int, float)):
                _set_pool_endpoint_meta(parsed, domains=value[0], latency_ms=value[1] if len(value) > 1 else None)
            elif isinstance(value, str):
                _set_pool_endpoint_meta(parsed, domains=[value], latency_ms=None)
            elif value is not None:
                _set_pool_endpoint_meta(parsed, domains=[], latency_ms=value)
            _push(parsed)
    except Exception:
        pass

    try:
        for ep, value in STATE.ip_pool().items():
            parsed = _normalize_pool_endpoint(ep)
            if not parsed:
                continue
            if isinstance(value, dict):
                _set_pool_endpoint_meta(parsed, domains=value.get('domains') or value.get('domain') or [], latency_ms=value.get('latency_ms'))
            elif isinstance(value, (list, tuple)) and value and not isinstance(value[0], (int, float)):
                _set_pool_endpoint_meta(parsed, domains=value[0], latency_ms=value[1] if len(value) > 1 else None)
            elif isinstance(value, str):
                _set_pool_endpoint_meta(parsed, domains=[value], latency_ms=None)
            elif value is not None:
                _set_pool_endpoint_meta(parsed, domains=[], latency_ms=value)
            _push(parsed)
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


def _l1_route_peek(host, port):
    key = (host, int(port))
    entry = _ROUTE_L1_CACHE.get(key)
    if not entry:
        return None
    if entry.get('exp', 0) <= time.monotonic():
        return None
    return entry


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
    domain_key = _normalize_route_domain(host)
    if stats and stats.is_quarantined(domain=domain_key):
        _ROUTE_L1_CACHE.pop(key, None)
        return None

    state = _get_endpoint_domain_state(ep, domain_key, create=False) or {}
    if state and (
        state.get('fail_count', 0) >= getattr(config, 'ROUTE_EVICT_FAIL_THRESHOLD', 6)
        or (
            state.get('consecutive_failures', 0) > 0
            and _is_severe_failure_reason(state.get('last_fail_reason'))
        )
    ):
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


def _prepare_candidates(
    target_port,
    banned_for_domain,
    is_sensitive_host=False,
    seed_endpoint=None,
    forbidden_eps=None,
    target_host=None,
    debug_ctx=None,
):
    primary = []
    fallback = []
    forbidden_eps = forbidden_eps or set()
    target_l = (target_host or "").strip().lower().strip(".")

    for ep in _collect_pool_endpoints_cached():
        parsed_ep = _normalize_pool_endpoint(ep)
        if not parsed_ep:
            continue
        if parsed_ep in forbidden_eps:
            if debug_ctx is not None:
                debug_ctx.setdefault('excluded', []).append((parsed_ep, 'forbidden-by-retry'))
            continue
        if config.is_tls_port(target_port):
            if not config.is_tls_port(parsed_ep[1]):
                if debug_ctx is not None:
                    debug_ctx.setdefault('excluded', []).append((parsed_ep, 'port-mismatch-non-tls'))
                continue
        elif parsed_ep[1] != target_port:
            if debug_ctx is not None:
                debug_ctx.setdefault('excluded', []).append((parsed_ep, 'port-mismatch'))
            continue

        stats = _EP_REGISTRY.get(parsed_ep)
        if stats and stats.is_quarantined(domain=target_l):
            if debug_ctx is not None:
                debug_ctx.setdefault('excluded', []).append((parsed_ep, 'quarantined'))
            continue

        if _is_endpoint_banned_for_target(parsed_ep, target_port, banned_for_domain):
            fallback.append(parsed_ep)
            if debug_ctx is not None:
                debug_ctx.setdefault('banned', []).append((parsed_ep, 'banned-for-domain'))
        else:
            primary.append(parsed_ep)

    now = time.monotonic()

    def _sort_key(ep, allow_quarantine=False):
        priority = _target_candidate_priority(ep, target_l)
        if priority is None:
            priority = 999
        return (
            priority,
            _endpoint_score(ep, now, domain=target_l, allow_quarantined=allow_quarantine),
            ep[0],
            ep[1],
        )

    primary.sort(key=_sort_key)
    fallback.sort(key=_sort_key)

    if seed_endpoint and seed_endpoint in primary:
        primary.remove(seed_endpoint)
        primary.insert(0, seed_endpoint)

    max_primary = _MAX_PRIMARY_CANDIDATES_SENSITIVE if is_sensitive_host else _MAX_PRIMARY_CANDIDATES_DEFAULT
    primary = primary[:max_primary]
    fallback = fallback[:_MAX_FALLBACK_CANDIDATES]
    if debug_ctx is not None:
        debug_ctx['primary'] = list(primary)
        debug_ctx['fallback'] = list(fallback)
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


# Per-registrable-domain semaphore: gates *cold race execution* so a burst of
# subdomain requests (e.g. scontent-*.cdninstagram.com) can't fan out N races
# in parallel against the same candidate pool and exhaust local sockets. Each
# (host, port) still gets its own coalescing entry in config._RACE_LOCKS, so
# winners are never shared across subdomains — only race concurrency is bounded.
_REGISTRABLE_RACE_SEMAPHORES = {}

def _get_registrable_race_semaphore(registrable):
    key = (registrable or '').lower() or '_default'
    sem = _REGISTRABLE_RACE_SEMAPHORES.get(key)
    if sem is None:
        limit = max(1, int(getattr(config, 'ROUTE_RACE_PER_REGISTRABLE_LIMIT', 2)))
        sem = asyncio.Semaphore(limit)
        _REGISTRABLE_RACE_SEMAPHORES[key] = sem
    return sem

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
    try:
        config.IP_POOL_METADATA = {}
    except Exception:
        pass
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
                latency_ms = r.get('latency_ms')
                clean_domains = _normalize_pool_domains(domains)
                loaded_ips[endpoint] = clean_domains[0] if clean_domains else None
                _set_pool_endpoint_meta(endpoint, domains=clean_domains, latency_ms=latency_ms)
        except Exception:
            pass
        
    STATE.replace_ip_pool(loaded_ips)
    return len(STATE.ip_pool())

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

async def verify_sni(ip, domain, port=443, timeout=config.RACE_TIMEOUT, tls_only=False, http_verify=False, return_reason=False):
    domain_l = _validate_server_hostname(domain)
    if not domain_l:
        if return_reason:
            return None, 0.0, "invalid-server-hostname"
        return False
    bounded_timeout = _bounded_route_probe_timeout(timeout)
    try:
        return await asyncio.wait_for(
            probe_route_endpoint(
                ip,
                domain_l,
                port=port,
                timeout=bounded_timeout,
                http_verify=http_verify,
                tls_only=tls_only,
                return_reason=return_reason,
            ),
            timeout=bounded_timeout,
        )
    except asyncio.TimeoutError:
        if return_reason:
            return None, float(bounded_timeout) * 1000.0, "timeout"
        return False
    except Exception:
        if return_reason:
            return None, 0.0, "error"
        return False

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
        writer = None
        try:
            cap_timeout = _bounded_route_probe_timeout(timeout)
            srv_host = _validate_server_hostname(srv_host) if config.is_tls_port(port) else None
            if config.is_tls_port(port) and not srv_host:
                return None
            # CRITICAL FIX: Use strict=True. If the ISP hijacks the connection and serves a fake cert,
            # this will throw an SSLError, correctly failing the native route and triggering the proxy.
            ctx = get_tls_context(strict=True) if config.is_tls_port(port) else None
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host=candidate, port=port, ssl=ctx, server_hostname=srv_host),
                timeout=cap_timeout
            )
            return host
        except asyncio.TimeoutError:
            return None
        except Exception:
            return None
        finally:
            await _close_stream_writer(writer, timeout=timeout)

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
    sni_l = _validate_server_hostname(sni_host)
    if not sni_l:
        return None, 0.0, "invalid-server-hostname"
    bounded_timeout = _bounded_route_probe_timeout(timeout)
    try:
        result, latency_ms, reason = await asyncio.wait_for(
            probe_route_endpoint(
                ep_ip,
                sni_l,
                port=ep_port,
                timeout=bounded_timeout,
                http_verify=http_verify,
                return_reason=True,
            ),
            timeout=bounded_timeout,
        )
    except asyncio.TimeoutError:
        result, latency_ms, reason = None, float(bounded_timeout) * 1000.0, "timeout"
    except Exception:
        result, latency_ms, reason = None, 0.0, "error"
    return result, latency_ms, reason


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


def mark_route_dead(host, port, bad_endpoint, reason=None, latency_ms=None):
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
    norm_reason = _normalize_failure_reason(reason or 'connect-error')
    # Domain-specific bans (e.g. 403 forbidden, geoblock) must not poison the
    # endpoint universally, otherwise viable nodes get killed for all targets.
    if 'banned-for-domain' not in norm_reason and 'http-reject' not in norm_reason and 'reject' not in norm_reason:
        # Use-time "dead" should immediately remove the endpoint from the healthy
        # candidate pool to avoid repeated failures during bursts.
        _quarantine_endpoint(ep, host_lower, norm_reason)
    _record_endpoint_failure(ep, host_lower, reason=norm_reason, latency_ms=latency_ms)

    base = (get_base_domain(host_lower) or host_lower).strip('.').lower()
    registrable = _get_registrable_domain(host_lower)
    _purge_l2_route(host_lower, base, registrable, ep)
    _session_record_mark('dead')
    reason_label = f"reason={reason}" if reason else "reason=connect-failed"
    latency_label = f", latency={float(latency_ms):.0f}ms" if latency_ms is not None else ""
    router_debug_log(host_lower, f"mark dead {format_ip_port(*ep)} ({reason_label}{latency_label})")


def mark_route_slow(host, port, bad_endpoint, reason=None, ttfb_ms=None, elapsed_ms=None):
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
    _record_endpoint_failure(ep, host_lower, reason=reason or 'slow', latency_ms=ttfb_ms or elapsed_ms)
    _session_record_mark('slow')
    details = []
    details.append(f"reason={reason or 'slow'}")
    if ttfb_ms is not None:
        details.append(f"ttfb={float(ttfb_ms):.0f}ms")
    if elapsed_ms is not None:
        details.append(f"elapsed={float(elapsed_ms):.0f}ms")
    router_debug_log(host_lower, f"mark slow {format_ip_port(*ep)} ({', '.join(details)})")


async def get_routed_ip(target_host, target_port, forbidden_eps=None):
    ensure_locks()
    target_host_lower = target_host.lower()
    forbidden_eps = forbidden_eps or set()
    debug_on = _router_debug_enabled()
    debug_ctx = {} if debug_on else None
    fast_fallback_mode = bool(forbidden_eps)

    l1_entry = _l1_route_peek(target_host_lower, target_port)
    exact_routes = STATE.exact_routes()
    wildcard_routes = STATE.wildcard_routes()
    l2_hot = False
    if exact_routes.get(target_host_lower):
        l2_hot = True
    else:
        parts = target_host_lower.split('.')
        for i in range(len(parts) - 1):
            if wildcard_routes.get('.' + '.'.join(parts[i:])):
                l2_hot = True
                break
    hot_start = bool(l1_entry or l2_hot)
    _session_record_request(target_host_lower, hot_start)
    router_debug_log(
        target_host_lower,
        f"route request port={target_port} start={'hot' if hot_start else 'cold'}",
        include_ts=True,
    )
    
    # 1. Localhost/IP bypass - Return fully qualified tuple natively
    if target_host_lower in ('localhost', '127.0.0.1'): return target_host_lower, target_port
    try: 
        ipaddress.ip_address(target_host_lower)
        return target_host_lower, target_port
    except ValueError: pass

    base_domain = get_base_domain(target_host_lower)
    registrable_domain = _get_registrable_domain(target_host_lower)
    _ensure_route_policy_cache()

    # 2. Pattern-driven force routing rules
    matched_always = _matches_any_compiled(target_host_lower, registrable_domain, _ROUTE_POLICY_CACHE['always'])
    matched_native = _matches_any_compiled(target_host_lower, registrable_domain, _ROUTE_POLICY_CACHE['do_not'])

    force_white = bool(matched_always)
    force_native = bool(matched_native) and not force_white
    is_sensitive_host = target_host_lower in _SENSITIVE_DOMAINS or target_host_lower.endswith(_SENSITIVE_TUPLE)
    requires_host_reverify = bool(config.is_tls_port(target_port) and _needs_host_http_reverify(target_host_lower))

    if force_white and matched_native:
        print(f"[RULE] {target_host_lower} matched both lists ({matched_always} / {matched_native}) -> ALWAYS_ROUTE wins.")

    if force_native:
        print(f"[RULE] {target_host_lower} matched DO_NOT_ROUTE ({matched_native}) -> native route.")
        router_debug_log(target_host_lower, f"forced native route (matched {matched_native})")
        _session_record_native_win()
        return target_host_lower, target_port

    # Local dictionary mapping for tighter loops
    banned_for_domain = set()
    ban_lookup_keys = (registrable_domain, base_domain, target_host_lower)
    for dom_key in ban_lookup_keys:
        for entry in STATE.banned_routes().get(dom_key, set()):
            # Handle both raw strings from disk and tuples from memory
            ep = entry if isinstance(entry, tuple) else parse_ip_port(entry)
            if ep and ep[1] == target_port:
                banned_for_domain.add(ep)

    if not forbidden_eps and l1_entry and l1_entry.get('mode') == 'white':
        l1_ep = _normalize_endpoint(l1_entry.get('ep'))
        l1_stats = _EP_REGISTRY.get(l1_ep) if l1_ep else None
        if l1_ep and l1_stats and l1_stats.is_quarantined(domain=target_host_lower):
            _purge_routes_for_endpoint(target_host_lower, l1_ep)
            _ROUTE_L1_CACHE.pop((target_host_lower, int(target_port)), None)
            fast_fallback_mode = True

    # 3. L1 in-memory route cache (TTL + health eviction).
    # If the caller passed forbidden_eps (a retry after a connect-time
    # failure), bypass L1 entirely and force a re-race — otherwise we'd
    # just hand back the same dead IP.
    if not forbidden_eps:
        fast_cached = _l1_route_get(target_host_lower, target_port, banned_for_domain, force_white)
        if fast_cached:
            if (
                requires_host_reverify
                and isinstance(fast_cached, tuple)
                and len(fast_cached) >= 2
                and not (fast_cached[0] == target_host_lower and int(fast_cached[1]) == int(target_port))
            ):
                verify_timeout = _endpoint_probe_timeout_sec(fast_cached, target_host_lower)
                reverify_ok, reverify_ms, reverify_reason = await _reverify_cached_endpoint_for_host(target_host_lower, fast_cached, verify_timeout)
                if reverify_ok:
                    _session_record_cache_hit(target_host_lower, 'l1')
                    _session_record_white_win()
                    router_debug_log(target_host_lower, f"L1 cache hit -> {format_ip_port(*fast_cached)} (reverify ok)")
                    return fast_cached
                print(f"[*] L1 cached endpoint {format_ip_port(*fast_cached)} is geoblocked for {target_host_lower}.")
                _record_endpoint_failure(fast_cached, target_host_lower, reason=reverify_reason, latency_ms=reverify_ms)
                fast_fallback_mode = True
                if "http-reject" in _normalize_failure_reason(reverify_reason):
                    _ban_endpoint_for_host(target_host_lower, fast_cached)
                _purge_routes_for_endpoint(target_host_lower, fast_cached)
                banned_for_domain.add((fast_cached[0], int(fast_cached[1])))
                _session_record_reverify_failure()
            elif fast_cached is not None:
                _session_record_cache_hit(target_host_lower, 'l1')
                if isinstance(fast_cached, tuple) and len(fast_cached) >= 2:
                    if fast_cached[0] == target_host_lower and int(fast_cached[1]) == int(target_port):
                        _session_record_native_win()
                        router_debug_log(target_host_lower, f"L1 cache hit -> native {target_host_lower}:{target_port}")
                    else:
                        _session_record_white_win()
                        router_debug_log(target_host_lower, f"L1 cache hit -> {format_ip_port(*fast_cached)}")
                return fast_cached

    # 4. L2 persistent route cache from disk-backed maps (exact + wildcard).
    # Skip the disk cache entirely on a retry — it can hold the same kind of
    # bad IP that just failed, and we want a fresh race instead of digging
    # through stale entries one at a time.
    seeded_cached_ep = None
    if not forbidden_eps:
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
            domain_state = _get_endpoint_domain_state(ep_key, target_host_lower, create=False) or {}
            fail_count = domain_state.get('fail_count', 0)
            if ep_stats and ep_stats.is_quarantined(domain=target_host_lower):
                print(f"[*] Cached endpoint {format_ip_port(*cached_ep)} is QUARANTINED for {target_host_lower}. Forcing new race...")
                _purge_routes_for_endpoint(target_host_lower, ep_key)
                _ROUTE_L1_CACHE.pop((target_host_lower, int(target_port)), None)
                router_debug_log(target_host_lower, f"L2 cached endpoint {format_ip_port(*cached_ep)} rejected (quarantined)")
                fast_fallback_mode = True
            elif _is_endpoint_banned_for_target(ep_key, target_port, banned_for_domain):
                print(f"[*] Cached endpoint {format_ip_port(*cached_ep)} is BANNED for {registrable_domain}. Forcing new race...")
                router_debug_log(target_host_lower, f"L2 cached endpoint {format_ip_port(*cached_ep)} rejected (banned)")
                fast_fallback_mode = True
            else:
                if requires_host_reverify:
                    verify_timeout = _endpoint_probe_timeout_sec(ep_key, target_host_lower)
                    reverify_ok, reverify_ms, reverify_reason = await _reverify_cached_endpoint_for_host(
                        target_host_lower,
                        ep_key,
                        verify_timeout,
                    )
                    if reverify_ok:
                        print(f"[⚡ CACHED] {target_host_lower} -> {format_ip_port(*cached_ep)}")
                        _record_endpoint_success(ep_key, target_host_lower)
                        _l1_route_set(target_host_lower, target_port, cached_ep)
                        _session_record_cache_hit(target_host_lower, 'l2')
                        _session_record_white_win()
                        router_debug_log(target_host_lower, f"L2 cache hit -> {format_ip_port(*cached_ep)} (reverify ok)")
                        return cached_ep
                    print(f"[*] Cached endpoint {format_ip_port(*cached_ep)} is geoblocked for {target_host_lower}. Forcing new race...")
                    _record_endpoint_failure(ep_key, target_host_lower, reason=reverify_reason, latency_ms=reverify_ms)
                    fast_fallback_mode = True
                    if "http-reject" in _normalize_failure_reason(reverify_reason):
                        _ban_endpoint_for_host(target_host_lower, ep_key)
                    _purge_routes_for_endpoint(target_host_lower, ep_key)
                    banned_for_domain.add((ep_key[0], int(ep_key[1])))
                    _session_record_reverify_failure()
                    router_debug_log(target_host_lower, f"L2 cached endpoint {format_ip_port(*cached_ep)} rejected (reverify failed)")
                elif fail_count < getattr(config, 'ROUTE_EVICT_FAIL_THRESHOLD', 6) and not (
                    domain_state.get('consecutive_failures', 0) > 0 and _is_severe_failure_reason(domain_state.get('last_fail_reason'))
                ):
                    # Trust the L2 entry on the cold path. A genuinely bad cached
                    # IP is caught downstream: the proxy's connect-time failover
                    # calls mark_route_dead (purges L1+L2 and re-races), and the
                    # relay's TTFB/no-data watchdog calls mark_route_slow on the
                    # download leg. Adding a synchronous TLS+HTTP probe here was
                    # too costly on every cold cache hit.
                    print(f"[⚡ CACHED] {target_host_lower} -> {format_ip_port(*cached_ep)}")
                    _l1_route_set(target_host_lower, target_port, cached_ep)
                    _session_record_cache_hit(target_host_lower, 'l2')
                    _session_record_white_win()
                    router_debug_log(target_host_lower, f"L2 cache hit -> {format_ip_port(*cached_ep)}")
                    return cached_ep
                elif cache_source == 'wildcard' and is_sensitive_host and target_host_lower not in exact_routes:
                    seeded_cached_ep = ep_key
                else:
                    print(f"[*] Cached endpoint {format_ip_port(*cached_ep)} has poor health for {target_host_lower}. Re-racing...")
                    router_debug_log(target_host_lower, f"L2 cached endpoint {format_ip_port(*cached_ep)} rejected (fail_count={fail_count})")
                    fast_fallback_mode = True

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

        race_semaphore = _get_registrable_race_semaphore(registrable_domain)
        try:
            async with race_semaphore:
                race_timeout = config.RACE_TIMEOUT
                if fast_fallback_mode:
                    race_timeout = min(race_timeout, float(getattr(config, 'ROUTE_FAST_FALLBACK_TIMEOUT_SEC', 2.25)))
                winner_ep = None
    
                primary_eps = []
                fallback_eps = []
                if config.CONNECTION_MODE in ('white_ip', 'mixed'):
                    if debug_on:
                        score_lat = getattr(config, 'ROUTE_SCORE_LATENCY_WEIGHT', 1.0)
                        score_fail = getattr(config, 'ROUTE_SCORE_FAIL_WEIGHT', 250.0)
                        score_rec = getattr(config, 'ROUTE_SCORE_RECENCY_WEIGHT', 3.0)
                        rec_cap = getattr(config, 'ROUTE_SCORE_RECENCY_CAP_SEC', 120.0)
                        router_debug_log(
                            target_host_lower,
                            "candidate filters: tls-port match, banned-for-domain, forbidden-by-retry; "
                            f"sort: target-aware priority + score=(known-latency or ewma)*{score_lat}+fail_cap*{score_fail}+recent-success*{score_rec} (cap {rec_cap}s); "
                            "google targets prefer google-verified endpoints and low-latency candidates; "
                            "non-google targets keep all endpoints eligible",
                        )
                    primary_eps, fallback_eps = _prepare_candidates(
                        target_port,
                        banned_for_domain,
                        is_sensitive_host=is_sensitive_host,
                        seed_endpoint=seeded_cached_ep,
                        forbidden_eps=forbidden_eps,
                        target_host=target_host_lower,
                        debug_ctx=debug_ctx,
                    )
                    if debug_on:
                        def _fmt_candidates(eps):
                            out = []
                            now = time.monotonic()
                            for ep in eps:
                                stats = _EP_REGISTRY.get(ep)
                                state = _get_endpoint_domain_state(ep, target_host_lower, create=False) or {}
                                score = _endpoint_score(ep, now, domain=target_host_lower)
                                latency = state.get('ewma_latency_ms') if state else None
                                fail_count = state.get('fail_count', 0)
                                latency_label = f"{latency:.0f}ms" if latency is not None else "n/a"
                                out.append(f"{format_ip_port(*ep)}(score={score:.0f},lat={latency_label},fail={fail_count})")
                            return ", ".join(out) if out else "(none)"
    
                        router_debug_log(target_host_lower, f"primary candidates: {_fmt_candidates(primary_eps)}")
                        router_debug_log(target_host_lower, f"fallback candidates: {_fmt_candidates(fallback_eps)}")
                        if not primary_eps and not fallback_eps:
                            router_debug_log(target_host_lower, "no candidates available from pool")
                            if debug_ctx is not None and debug_ctx.get('banned'):
                                router_debug_log(target_host_lower, "all usable candidates were banned or quarantined")
                            router_debug_log(
                                target_host_lower,
                                "scanner trigger not available in routing path; pool must be refilled externally",
                            )
                    if fast_fallback_mode and fallback_eps:
                        merged_eps = list(primary_eps)
                        seen_eps = set(merged_eps)
                        for ep in fallback_eps:
                            if ep not in seen_eps:
                                merged_eps.append(ep)
                                seen_eps.add(ep)
                        primary_eps = merged_eps
                        fallback_eps = []
                        router_debug_log(target_host_lower, "fast fallback enabled; using a single merged race list")
    
                # An IP can pass TLS yet still serve 403 / Cloudflare 1034 / "edge
                # IP restricted" at the HTTP layer for the requested hostname. We
                # verify at HTTP level for every race candidate so those IPs lose
                # the race instead of becoming the cached winner.
                http_verify_enabled = bool(getattr(config, 'ROUTE_HTTP_VERIFY_RACE', True))
    
                async def _race_batch(eps, batch_size, deadline=None):
                    if not eps:
                        return None
    
                    local_batch_size = _effective_batch_size(batch_size, len(eps))
                    if local_batch_size <= 0:
                        return None
    
                    loop = asyncio.get_running_loop()
                    if deadline is None:
                        deadline = loop.time() + float(race_timeout)
                    per_ip_cap = None
                    if fast_fallback_mode:
                        per_ip_cap = float(getattr(config, 'ROUTE_FAST_FALLBACK_PER_IP_TIMEOUT_SEC', 1.75))
    
                    async def _probe_candidate(ep, probe_timeout_sec):
                        async with config.RACE_SEMAPHORE:
                            return await _timed_verify_sni(
                                ep[0],
                                target_host_lower,
                                ep[1],
                                timeout=probe_timeout_sec,
                                http_verify=http_verify_enabled,
                            )
    
                    inflight = {}
                    iterator = iter(eps)
    
                    async def _fill_window():
                        while len(inflight) < local_batch_size:
                            ep = next(iterator, None)
                            if ep is None:
                                return
                            probe_timeout_sec = _endpoint_probe_timeout_sec(ep, target_host_lower)
                            if per_ip_cap is not None:
                                probe_timeout_sec = min(probe_timeout_sec, per_ip_cap)
                            remaining = deadline - loop.time()
                            if remaining <= 0:
                                return
                            probe_timeout_sec = max(0.1, min(probe_timeout_sec, remaining))
                            task = asyncio.create_task(_probe_candidate(ep, probe_timeout_sec))
                            inflight[task] = (ep, probe_timeout_sec)
    
                    await _fill_window()
                    try:
                        while inflight:
                            remaining = max(0.01, deadline - loop.time())
                            if remaining <= 0:
                                break
                            done, _ = await asyncio.wait(set(inflight.keys()), timeout=remaining, return_when=asyncio.FIRST_COMPLETED)
                            if not done:
                                break
                            for t in done:
                                ep, probe_timeout_sec = inflight.pop(t, (None, None))
                                if ep is None:
                                    continue
                                try:
                                    res, latency_ms, reason = t.result()
                                except Exception:
                                    _record_endpoint_failure(ep, target_host_lower, reason='error')
                                    _record_race_outcome(False, float(probe_timeout_sec) * 1000.0, probe_timeout_sec)
                                    if debug_ctx is not None:
                                        debug_ctx.setdefault('failures', []).append((ep, 'exception', float(probe_timeout_sec) * 1000.0))
                                    continue
                                _record_race_outcome(bool(res), float(latency_ms), probe_timeout_sec)
                                if res:
                                    _record_endpoint_success(ep, target_host_lower, latency_ms=latency_ms)
                                    if debug_ctx is not None:
                                        debug_ctx['winner'] = ep
                                        debug_ctx['winner_latency_ms'] = float(latency_ms)
                                        debug_ctx['winner_reason'] = reason
                                    for pending_task in list(inflight.keys()):
                                        pending_task.cancel()
                                    await asyncio.gather(*inflight.keys(), return_exceptions=True)
                                    return res
                                _record_endpoint_failure(ep, target_host_lower, reason=reason, latency_ms=latency_ms)
                                if debug_ctx is not None:
                                    debug_ctx.setdefault('failures', []).append((ep, reason or 'reject', float(latency_ms)))
                            await _fill_window()
                    finally:
                        for t in list(inflight.keys()):
                            if not t.done():
                                t.cancel()
                        await asyncio.gather(*inflight.keys(), return_exceptions=True)
                    return None
    
                if not force_white:
                    native_task = asyncio.create_task(verify_native_target(target_host_lower, target_port, timeout=race_timeout))
                    try:
                        native_headstart_sec = float(getattr(config, 'RACE_NATIVE_HEADSTART_SEC', 0.3))
                        if fast_fallback_mode:
                            native_headstart_sec = min(native_headstart_sec, 0.15)
                        done, pending = await asyncio.wait(
                            {native_task},
                            timeout=native_headstart_sec,
                            return_when=asyncio.FIRST_COMPLETED,
                        )
                        for t in done:
                            try:
                                native_res = t.result()
                                if native_res:
                                    winner_ep = native_res
                                    print(f"[🌐 NORMAL] {target_host_lower} is accessible natively.")
                                    router_debug_log(target_host_lower, "native route verified; skipping race")
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
    
                race_started = False
                race_start = None
                if not winner_ep:
                    race_started = True
                    race_start = time.monotonic()
                    winner_ep = await _race_batch(primary_eps, getattr(config, 'RACE_BATCH_PRIMARY', 6))
                if not winner_ep and fallback_eps:
                    print(f"[*] Primary race failed. Attempting fallback race for {target_host_lower}...")
                    winner_ep = await _race_batch(fallback_eps, getattr(config, 'RACE_BATCH_FALLBACK', 4))
                if race_started:
                    duration_ms = (time.monotonic() - race_start) * 1000.0 if race_start else None
                    _session_record_race(target_host_lower, duration_ms=duration_ms, winner=winner_ep)
                    if winner_ep:
                        router_debug_log(target_host_lower, f"race completed in {duration_ms:.0f}ms")
                    else:
                        router_debug_log(target_host_lower, f"race failed after {duration_ms:.0f}ms")
    
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
                        _session_record_native_win()
                        router_debug_log(target_host_lower, f"selected native {target_host_lower}:{target_port}")
                    else:
                        _set_route(exact_routes, target_host_lower, winner_port, winner_ip)
                        _record_endpoint_success(winner_tuple, target_host_lower)
                        _session_record_white_win()
                        chosen_latency = None
                        if debug_ctx and debug_ctx.get('winner_latency_ms') is not None:
                            chosen_latency = float(debug_ctx.get('winner_latency_ms'))
                        else:
                            state = _get_endpoint_domain_state(winner_tuple, target_host_lower, create=False) or {}
                            if state.get('ewma_latency_ms', 9999.0) < 9999.0:
                                chosen_latency = float(state['ewma_latency_ms'])
                        _session_record_selection(target_host_lower, winner_tuple, latency_ms=chosen_latency)
                        latency_label = f"{chosen_latency:.0f}ms" if chosen_latency is not None else "n/a"
                        router_debug_log(
                            target_host_lower,
                            f"selected {format_ip_port(winner_ip, winner_port)} (expected latency {latency_label})",
                        )
    
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
                        _session_record_failure(target_host_lower)
                        router_debug_log(target_host_lower, "no viable endpoint found; routing failed")
                    if seeded_cached_ep:
                        _record_endpoint_failure(seeded_cached_ep, target_host_lower)
                    if debug_on:
                        failures = debug_ctx.get('failures', []) if debug_ctx else []
                        excluded = debug_ctx.get('excluded', []) if debug_ctx else []
                        banned = debug_ctx.get('banned', []) if debug_ctx else []
                        if excluded or banned or failures:
                            router_debug_log(target_host_lower, "candidate rejection summary:")
                            for ep, reason in excluded:
                                router_debug_log(target_host_lower, f"reject {format_ip_port(*ep)}: {reason}")
                            for ep, reason in banned:
                                router_debug_log(target_host_lower, f"reject {format_ip_port(*ep)}: {reason}")
                            for ep, reason, latency_ms in failures:
                                router_debug_log(target_host_lower, f"reject {format_ip_port(*ep)}: {reason} ({latency_ms:.0f}ms)")
                    
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
