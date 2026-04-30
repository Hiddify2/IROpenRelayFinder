from cores import scanner as scanner_core


class ScanService:
    def run_masscan_preflight(self, ips, use_cached=False):
        return scanner_core.run_masscan_preflight(ips, use_cached=use_cached)

    def run_nmap_preflight(self, ips, use_cached=False):
        return scanner_core.run_nmap_preflight(ips, use_cached=use_cached)

    async def run_mass_scan(self, targets, domains, results_list, skip_tcp=False, deep_scan=False):
        return await scanner_core.run_mass_scan(targets, domains, results_list, skip_tcp=skip_tcp, deep_scan=deep_scan)


SCAN_SERVICE = ScanService()
