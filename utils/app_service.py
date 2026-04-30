import os
import re

from utils import config
from utils import helpers
from utils.route_service import ROUTE_SERVICE


class AppService:
    def _normalize_route_pattern(self, pattern):
        pattern = (pattern or "").strip().lower()
        if not pattern:
            return None
        return pattern

    def _validate_route_pattern(self, pattern):
        if not pattern.startswith("re:"):
            return True
        expr = pattern[3:].strip()
        if not expr:
            return False
        try:
            re.compile(expr)
            return True
        except re.error:
            return False

    def add_always_route_pattern(self, pattern):
        pattern = self._normalize_route_pattern(pattern)
        if not pattern:
            return {"status": "empty"}
        if not self._validate_route_pattern(pattern):
            return {"status": "invalid", "pattern": pattern}
        if pattern in config.DO_NOT_ROUTE_PATTERNS:
            return {"status": "conflict", "pattern": pattern, "conflicts_with": "do_not_route"}
        if pattern in config.ALWAYS_ROUTE_PATTERNS:
            return {"status": "exists", "pattern": pattern}
        config.ALWAYS_ROUTE_PATTERNS.append(pattern)
        config.touch_route_policy()
        config.save_config()
        return {"status": "added", "pattern": pattern}

    def add_do_not_route_pattern(self, pattern):
        pattern = self._normalize_route_pattern(pattern)
        if not pattern:
            return {"status": "empty"}
        if not self._validate_route_pattern(pattern):
            return {"status": "invalid", "pattern": pattern}
        if pattern in config.ALWAYS_ROUTE_PATTERNS:
            return {"status": "conflict", "pattern": pattern, "conflicts_with": "always_route"}
        if pattern in config.DO_NOT_ROUTE_PATTERNS:
            return {"status": "exists", "pattern": pattern}
        config.DO_NOT_ROUTE_PATTERNS.append(pattern)
        config.touch_route_policy()
        config.save_config()
        return {"status": "added", "pattern": pattern}

    def remove_always_route_pattern(self, pattern):
        pattern = self._normalize_route_pattern(pattern)
        if not pattern:
            return {"status": "empty"}
        if pattern not in config.ALWAYS_ROUTE_PATTERNS:
            return {"status": "missing", "pattern": pattern}
        config.ALWAYS_ROUTE_PATTERNS = [p for p in config.ALWAYS_ROUTE_PATTERNS if p != pattern]
        config.touch_route_policy()
        config.save_config()
        return {"status": "removed", "pattern": pattern}

    def remove_do_not_route_pattern(self, pattern):
        pattern = self._normalize_route_pattern(pattern)
        if not pattern:
            return {"status": "empty"}
        if pattern not in config.DO_NOT_ROUTE_PATTERNS:
            return {"status": "missing", "pattern": pattern}
        config.DO_NOT_ROUTE_PATTERNS = [p for p in config.DO_NOT_ROUTE_PATTERNS if p != pattern]
        config.touch_route_policy()
        config.save_config()
        return {"status": "removed", "pattern": pattern}

    def get_route_policy_lists(self):
        return {
            "always": list(config.ALWAYS_ROUTE_PATTERNS),
            "do_not": list(config.DO_NOT_ROUTE_PATTERNS),
        }

    def set_proxy_port(self, port):
        config.PROXY_PORT = int(port)

    def clear_route_cache(self):
        if not os.path.exists(config.HOSTS_FILE):
            return False
        os.remove(config.HOSTS_FILE)
        ROUTE_SERVICE.load_routes()
        return True

    def set_connection_mode(self, mode, persist=True):
        config.CONNECTION_MODE = mode
        if persist:
            config.save_config()

    def set_ip_pool(self, ip_map):
        normalized = {}
        for key, value in ip_map.items():
            parsed = helpers.parse_ip_port(key)
            if parsed:
                normalized[parsed] = value
        config.IP_POOL = normalized
        return len(config.IP_POOL)

    def set_dpi_target(self, sni=None, ip=None):
        if sni is not None:
            config.DPI_SNI = sni
        if ip is not None:
            config.DPI_IP = ip

    def toggle_dpi_fragmentation(self):
        config.DPI_FRAGMENTATION = not getattr(config, 'DPI_FRAGMENTATION', False)
        config.save_config()
        return config.DPI_FRAGMENTATION

    def toggle_dpi_logs(self):
        config.ALWAYS_SHOW_DPI_LOGS = not getattr(config, 'ALWAYS_SHOW_DPI_LOGS', False)
        config.save_config()
        return config.ALWAYS_SHOW_DPI_LOGS

    def set_dpi_strategies(self, strategies):
        config.DPI_STRATEGIES = list(strategies)
        config.ACTIVE_DPI_STRATEGY = config.DPI_STRATEGIES[0]
        config.save_config()

    def set_max_concurrent_scans(self, value):
        config.MAX_CONCURRENT_SCANS = int(value)

    def set_tuned_masscan_rate(self, value):
        config.TUNED_MASSCAN_RATE = int(value)

    def set_tuned_nmap_rates(self, max_rate):
        max_rate = int(max_rate)
        config.TUNED_NMAP_MAX_RATE = max_rate
        config.TUNED_NMAP_MIN_RATE = max(5, max_rate // 2)

    def save_runtime_config(self):
        config.save_config()

    def record_dpi_failure_and_maybe_rotate(self):
        config.DPI_FAILURES += 1
        if config.DPI_FAILURES < 2 or len(config.DPI_STRATEGIES) <= 1:
            return None

        old_strat = config.ACTIVE_DPI_STRATEGY
        idx = config.DPI_STRATEGIES.index(old_strat) if old_strat in config.DPI_STRATEGIES else 0

        if config.DPI_FAILURES >= 4 and "classic" in config.DPI_STRATEGIES and old_strat != "classic":
            new_strat = "classic"
        else:
            new_strat = config.DPI_STRATEGIES[(idx + 1) % len(config.DPI_STRATEGIES)]

        config.ACTIVE_DPI_STRATEGY = new_strat
        config.DPI_FAILURES = 0
        config.save_config()
        return (old_strat, new_strat)

    def clear_dpi_failures(self):
        config.DPI_FAILURES = 0

    def force_reroute_domain(self, domain):
        domain = domain.strip().lower()
        if not domain:
            return {"status": "empty"}

        def _registrable(host):
            parts = host.split('.')
            if len(parts) <= 2:
                return host
            if parts[-2] in ['co', 'com', 'org', 'net', 'edu', 'gov'] and len(parts[-1]) == 2:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])

        base_domain = helpers.get_base_domain(domain)
        bad_endpoints = []

        def _collect_from_exact(key):
            port_map = config.EXACT_ROUTES.pop(key, None)
            if isinstance(port_map, dict):
                for port, ip in port_map.items():
                    bad_endpoints.append((ip, int(port)))

        def _collect_from_wildcard(key):
            port_map = config.WILDCARD_ROUTES.pop(key, None)
            if isinstance(port_map, dict):
                for port, ip in port_map.items():
                    bad_endpoints.append((ip, int(port)))

        # Remove exact domain entries first (full host and base)
        _collect_from_exact(domain)
        if base_domain != domain:
            _collect_from_exact(base_domain)

        # Remove broader exact routes that still cover this domain
        wildcard_suffix = f".{base_domain}"
        for key in list(config.EXACT_ROUTES.keys()):
            if key == domain or key == base_domain:
                continue
            if domain.endswith(f".{key}") or key.endswith(wildcard_suffix):
                _collect_from_exact(key)

        # Remove any wildcard entries that cover this domain (e.g. .google.com for gemini.google.com)
        for key in list(config.WILDCARD_ROUTES.keys()):
            clean = key.lstrip('.')
            if not clean:
                continue
            if domain == clean or domain.endswith(f".{clean}") or base_domain.endswith(f".{clean}"):
                _collect_from_wildcard(key)

        if bad_endpoints:
            unique_endpoints = []
            seen_eps = set()
            for ep in bad_endpoints:
                if ep in seen_eps:
                    continue
                seen_eps.add(ep)
                unique_endpoints.append(ep)
            bad_endpoints = unique_endpoints

            ROUTE_SERVICE.rewrite_routes_sync(config.EXACT_ROUTES, config.WILDCARD_ROUTES)

            for ip, port in bad_endpoints:
                helpers.add_ban_entry(base_domain, (ip, port), persist=True)
                registrable = _registrable(base_domain)
                if registrable != base_domain:
                    helpers.add_ban_entry(registrable, (ip, port), persist=True)

            config.FAILED_DOMAINS.discard(domain)
            config.FAILED_DOMAINS.discard(base_domain)
            return {
                "status": "rerouted",
                "domain": domain,
                "base_domain": base_domain,
                "bad_ip": helpers.format_ip_port(*bad_endpoints[0]),
            }

        removed_failed = domain in config.FAILED_DOMAINS
        config.FAILED_DOMAINS.discard(domain)
        return {
            "status": "not_found",
            "domain": domain,
            "base_domain": base_domain,
            "removed_failed": removed_failed,
        }


APP_SERVICE = AppService()
