from utils import config


class RuntimeStateService:
    def active_proxy_connections(self):
        return getattr(config, 'ACTIVE_PROXY_CONNECTIONS', 0)

    def add_active_proxy_connections(self, delta):
        current = self.active_proxy_connections()
        updated = current + delta
        config.ACTIVE_PROXY_CONNECTIONS = updated if updated > 0 else 0
        return config.ACTIVE_PROXY_CONNECTIONS

    def should_pause_background_scan(self):
        threshold = getattr(config, 'BACKGROUND_SCAN_PAUSE_CONNECTIONS', 6)
        return self.active_proxy_connections() >= threshold

    def ip_pool(self):
        return config.IP_POOL

    def dead_ip_pool(self):
        return config.DEAD_IP_POOL

    def replace_ip_pool(self, new_pool):
        config.IP_POOL = dict(new_pool)

    def clear_dead_ip_pool(self):
        config.DEAD_IP_POOL.clear()

    def exact_routes(self):
        return config.EXACT_ROUTES

    def wildcard_routes(self):
        return config.WILDCARD_ROUTES

    def clear_routes(self):
        config.EXACT_ROUTES.clear()
        config.WILDCARD_ROUTES.clear()

    def banned_routes(self):
        return config.BANNED_ROUTES

    def clear_banned_routes(self):
        config.BANNED_ROUTES.clear()

    def add_ban(self, domain, endpoint):
        from utils import helpers
        helpers.add_ban_entry(domain, endpoint, persist=True)

    def failed_domains(self):
        return config.FAILED_DOMAINS

    def add_failed_domain(self, domain):
        config.FAILED_DOMAINS.add(domain)

    def clear_failed_domain(self, domain):
        if domain in config.FAILED_DOMAINS:
            config.FAILED_DOMAINS.remove(domain)


STATE = RuntimeStateService()
