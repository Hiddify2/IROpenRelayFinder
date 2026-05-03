from cores import scanner as scanner_core
from utils.pause_controller import PauseController


class ScanService:
    def __init__(self):
        self.pause_controller = PauseController()

    def new_pause_controller(self):
        self.pause_controller = PauseController()
        return self.pause_controller

    def run_masscan_preflight(self, ips, use_cached=False):
        return scanner_core.run_masscan_preflight(ips, use_cached=use_cached)

    def run_nmap_preflight(self, ips, use_cached=False):
        return scanner_core.run_nmap_preflight(ips, use_cached=use_cached)

    async def run_mass_scan(self, targets, domains, results_list, skip_tcp=False, deep_scan=False, pause_controller=None):
        controller = pause_controller or self.pause_controller
        return await scanner_core.run_mass_scan(
            targets,
            domains,
            results_list,
            skip_tcp=skip_tcp,
            deep_scan=deep_scan,
            pause_controller=controller,
        )


SCAN_SERVICE = ScanService()
