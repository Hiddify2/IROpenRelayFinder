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

    async def purge_media_wildcard_routes(self):
        await route_manager.purge_media_wildcard_routes()

    async def resolve_target(self, host, port):
        return await route_manager.resolve_target(host, port)

    async def verify_sni(self, ip, domain, port=443, timeout=None, tls_only=False):
        if timeout is None:
            return await route_manager.verify_sni(ip, domain, port=port, tls_only=tls_only)
        return await route_manager.verify_sni(ip, domain, port=port, timeout=timeout, tls_only=tls_only)

    async def get_routed_ip(self, target_host, target_port, forbidden_eps=None):
        return await route_manager.get_routed_ip(target_host, target_port, forbidden_eps=forbidden_eps)

    def mark_route_dead(self, host, port, bad_endpoint):
        route_manager.mark_route_dead(host, port, bad_endpoint)

    def mark_route_slow(self, host, port, bad_endpoint):
        route_manager.mark_route_slow(host, port, bad_endpoint)

    async def async_rewrite_routes(self, exact_routes, wildcard_routes):
        await route_manager.async_rewrite_routes(exact_routes, wildcard_routes)

    def rewrite_routes_sync(self, exact_routes, wildcard_routes):
        route_manager._rewrite_routes_sync(exact_routes, wildcard_routes)


ROUTE_SERVICE = RouteService()
