from utils import route_manager


class RouteService:
    def ensure_locks(self):
        route_manager.ensure_locks()

    def load_routes(self):
        route_manager.load_routes()

    def load_banned_routes(self):
        route_manager.load_banned_routes()

    def load_ip_pool(self):
        return route_manager.load_ip_pool()

    async def resolve_target(self, host, port):
        return await route_manager.resolve_target(host, port)

    async def verify_sni(self, ip, domain, port=443, timeout=None, tls_only=False, return_reason=False):
        if timeout is None:
            return await route_manager.verify_sni(ip, domain, port=port, tls_only=tls_only, return_reason=return_reason)
        return await route_manager.verify_sni(ip, domain, port=port, timeout=timeout, tls_only=tls_only, return_reason=return_reason)

    async def get_routed_ip(self, target_host, target_port, forbidden_eps=None):
        return await route_manager.get_routed_ip(target_host, target_port, forbidden_eps=forbidden_eps)

    def mark_route_dead(self, host, port, bad_endpoint, reason=None, latency_ms=None):
        route_manager.mark_route_dead(host, port, bad_endpoint, reason=reason, latency_ms=latency_ms)

    def mark_route_slow(self, host, port, bad_endpoint, reason=None, ttfb_ms=None, elapsed_ms=None):
        route_manager.mark_route_slow(host, port, bad_endpoint, reason=reason, ttfb_ms=ttfb_ms, elapsed_ms=elapsed_ms)

    def mark_route_slow_reason(self, host, port, bad_endpoint, reason, ttfb_ms=None, elapsed_ms=None):
        return route_manager.mark_route_slow(
            host,
            port,
            bad_endpoint,
            reason=reason,
            ttfb_ms=ttfb_ms,
            elapsed_ms=elapsed_ms,
        )

    def log_debug(self, host, message, include_ts=False):
        route_manager.router_debug_log(host, message, include_ts=include_ts)

    def get_debug_report(self):
        return route_manager.get_router_session_report()

    def record_reroute(self, duration_ms=None):
        route_manager.record_reroute(duration_ms=duration_ms)

    def write_debug_reports(self, report_name="report.json", logs_name="logs.json"):
        route_manager.write_router_session_files(report_name=report_name, logs_name=logs_name)

    async def async_rewrite_routes(self, exact_routes, wildcard_routes):
        await route_manager.async_rewrite_routes(exact_routes, wildcard_routes)

    def rewrite_routes_sync(self, exact_routes, wildcard_routes):
        route_manager._rewrite_routes_sync(exact_routes, wildcard_routes)


ROUTE_SERVICE = RouteService()
