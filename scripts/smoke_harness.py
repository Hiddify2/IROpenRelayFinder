#!/usr/bin/env python3
"""Offline smoke harness for core service flows (stdlib-only)."""

import os
import sys
import stat
import tempfile
import unittest
from unittest.mock import patch

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from utils import paths
from utils import config
from utils import route_manager
from utils import storage
from utils.app_service import APP_SERVICE
from utils import app_service as app_service_module
from utils import scan_service as scan_service_module
from utils.scan_service import SCAN_SERVICE
from cores.ui import _choice_from_line_click


class PathsSmokeTests(unittest.TestCase):
    def test_list_scan_files_prefers_timestamped_names(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filenames = [
                "scan_legacy.json",
                "scan_20260417_235959.json",
                "scan_20260418_000001.json",
                "scan_cyclic_continuous.json",
            ]
            for name in filenames:
                with open(os.path.join(tmpdir, name), "w", encoding="utf-8"):
                    pass

            with patch("utils.paths.project_root", return_value=tmpdir):
                listed = paths.list_scan_files(include_cyclic=False)

            names = [os.path.basename(item) for item in listed]
            self.assertEqual(names[0], "scan_20260418_000001.json")
            self.assertIn("scan_legacy.json", names)
            self.assertNotIn("scan_cyclic_continuous.json", names)


class AppServiceSmokeTests(unittest.TestCase):
    def test_set_connection_mode_persists_when_enabled(self):
        saved = {"count": 0}

        def fake_save_config():
            saved["count"] += 1

        with patch.object(config, "save_config", side_effect=fake_save_config):
            APP_SERVICE.set_connection_mode("dpi_desync", persist=False)
            self.assertEqual(config.CONNECTION_MODE, "dpi_desync")
            self.assertEqual(saved["count"], 0)

            APP_SERVICE.set_connection_mode("white_ip", persist=True)
            self.assertEqual(config.CONNECTION_MODE, "white_ip")
            self.assertEqual(saved["count"], 1)

    def test_clear_route_cache_removes_hosts_and_reloads(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_file = os.path.join(tmpdir, "white_routes.txt")
            with open(hosts_file, "w", encoding="utf-8") as f:
                f.write("1.1.1.1 example.com\n")

            called = {"reloads": 0}

            def fake_load_routes():
                called["reloads"] += 1

            with patch.object(config, "HOSTS_FILE", hosts_file), patch.object(
                app_service_module.ROUTE_SERVICE, "load_routes", side_effect=fake_load_routes
            ):
                result = APP_SERVICE.clear_route_cache()

            self.assertTrue(result)
            self.assertFalse(os.path.exists(hosts_file))
            self.assertEqual(called["reloads"], 1)

    def test_force_reroute_domain_bans_and_rewrites(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            banned_file = os.path.join(tmpdir, "banned_routes.txt")
            rewritten = {"calls": 0}

            def fake_rewrite_routes_sync(exact_routes, wildcard_routes):
                rewritten["calls"] += 1

            exact_routes = {
                "chatgpt.com": {443: "1.1.1.1"},
                "api.chatgpt.com": {443: "1.1.1.1"},
                "example.com": {443: "8.8.8.8"},
            }
            wildcard_routes = {".chatgpt.com": {443: "1.1.1.1"}}
            banned_routes = {}
            failed_domains = {"chatgpt.com"}

            with patch.object(config, "EXACT_ROUTES", exact_routes), patch.object(
                config, "WILDCARD_ROUTES", wildcard_routes
            ), patch.object(config, "BANNED_ROUTES", banned_routes), patch.object(
                config, "FAILED_DOMAINS", failed_domains
            ), patch.object(config, "BANNED_ROUTES_FILE", banned_file), patch.object(
                app_service_module.ROUTE_SERVICE,
                "rewrite_routes_sync",
                side_effect=fake_rewrite_routes_sync,
            ):
                result = APP_SERVICE.force_reroute_domain("chatgpt.com")

            self.assertEqual(result["status"], "rerouted")
            self.assertEqual(rewritten["calls"], 1)
            self.assertNotIn(".chatgpt.com", wildcard_routes)
            self.assertNotIn("chatgpt.com", exact_routes)
            self.assertIn("chatgpt.com", banned_routes)
            self.assertIn(("1.1.1.1", 443), banned_routes["chatgpt.com"])
            self.assertNotIn("chatgpt.com", failed_domains)

            with open(banned_file, "r", encoding="utf-8") as f:
                line = f.read().strip()
            self.assertEqual(line, "1.1.1.1:443 chatgpt.com")


class ScanServiceSmokeTests(unittest.TestCase):
    def test_scan_service_delegates_calls(self):
        called = {"masscan": 0, "nmap": 0, "mass": 0}

        async def fake_mass_scan(ips, domains, results_list, skip_tcp=False, deep_scan=False):
            called["mass"] += 1
            first = ips[0] if ips else ("1.1.1.1", config.primary_target_port())
            ip, port = first if isinstance(first, tuple) else (first, config.primary_target_port())
            results_list.append({"ip": ip, "port": port, "domains": domains})
            return 1

        with patch.object(
            scan_service_module.scanner_core,
            "run_masscan_preflight",
            side_effect=lambda ips, use_cached=False: called.__setitem__("masscan", called["masscan"] + 1) or ["ok"],
        ), patch.object(
            scan_service_module.scanner_core,
            "run_nmap_preflight",
            side_effect=lambda ips, use_cached=False: called.__setitem__("nmap", called["nmap"] + 1) or ["ok"],
        ), patch.object(scan_service_module.scanner_core, "run_mass_scan", side_effect=fake_mass_scan):
            pre1 = SCAN_SERVICE.run_masscan_preflight(["1.1.1.1"])
            pre2 = SCAN_SERVICE.run_nmap_preflight(["1.1.1.1"])

            import asyncio

            results = []
            count = asyncio.run(
                SCAN_SERVICE.run_mass_scan(["1.1.1.1"], ["example.com"], results, skip_tcp=True)
            )

        self.assertEqual(pre1, ["ok"])
        self.assertEqual(pre2, ["ok"])
        self.assertEqual(count, 1)
        self.assertEqual(called, {"masscan": 1, "nmap": 1, "mass": 1})
        self.assertEqual(results[0]["ip"], "1.1.1.1")


class CursesMenuSmokeTests(unittest.TestCase):
    def test_click_parser_handles_multidigit_bracket_choices(self):
        line = " [10] example.com (15 IPs)"
        self.assertEqual(_choice_from_line_click(line, 2), "10")
        self.assertEqual(_choice_from_line_click(line, 12), "10")

    def test_click_parser_handles_numbered_checklist_rows(self):
        line = "   12. [X] AS58224 - Iran Telecommunication"
        self.assertEqual(_choice_from_line_click(line, 30), "12")

    def test_click_parser_handles_inline_command_tokens(self):
        line = " Commands: [n] Next  [p] Previous  [0] Back"
        self.assertEqual(_choice_from_line_click(line, line.index("[n]") + 1), "n")
        self.assertEqual(_choice_from_line_click(line, line.index("[p]") + 1), "p")
        self.assertEqual(_choice_from_line_click(line, line.index("[0]") + 1), "0")

    def test_click_parser_handles_asn_command_tokens(self):
        self.assertEqual(_choice_from_line_click(" [1,2,5-8] Toggle ASN selection", 2), "1,2,5-8")
        self.assertEqual(_choice_from_line_click(" [/*pat*]   Wildcard search", 2), "/*pat*")
        self.assertEqual(_choice_from_line_click(" [/regex:]  Regex search", 2), "/regex:")


class RouteManagerSmokeTests(unittest.TestCase):
    def setUp(self):
        route_manager._ROUTE_FAST_CACHE.clear()
        route_manager._IP_HEALTH_SCORES.clear()
        route_manager._POOL_CACHE["expiry"] = 0.0
        route_manager._POOL_CACHE["sig"] = None
        route_manager._POOL_CACHE["eps"] = []

    def test_verify_native_target_uses_strict_tls(self):
        seen_calls = []

        class FakeWriter:
            def close(self):
                return None

            async def wait_closed(self):
                return None

        async def fake_resolve_target(host, port):
            self.assertEqual(host, "example.com")
            self.assertEqual(port, 443)
            return "93.184.216.34"

        async def fake_open_connection(host, port, ssl=None, server_hostname=None):
            seen_calls.append((host, port, ssl, server_hostname))
            return object(), FakeWriter()

        with patch.object(route_manager, "resolve_target", side_effect=fake_resolve_target), patch.object(
            route_manager.asyncio, "open_connection", side_effect=fake_open_connection
        ):
            import asyncio

            result = asyncio.run(route_manager.verify_native_target("example.com", 443, timeout=0.5))

        self.assertEqual(result, "example.com")
        self.assertTrue(seen_calls)
        host, port, ssl_ctx, sni = seen_calls[0]
        self.assertEqual(host, "93.184.216.34")
        self.assertEqual(port, 443)
        self.assertEqual(sni, "example.com")
        self.assertEqual(getattr(ssl_ctx, "verify_mode", None), route_manager.ssl.CERT_REQUIRED)
        self.assertTrue(getattr(ssl_ctx, "check_hostname", False))

    def test_verify_native_target_returns_none_on_tls_failure(self):
        async def fake_open_connection(_host, _port, ssl=None, server_hostname=None):
            raise route_manager.ssl.SSLError("handshake failed")

        async def fake_resolve_target(host, port):
            self.assertEqual(host, "example.com")
            self.assertEqual(port, 443)
            return "93.184.216.34"

        with patch.object(route_manager, "resolve_target", side_effect=fake_resolve_target), patch.object(
            route_manager.asyncio, "open_connection", side_effect=fake_open_connection
        ):
            import asyncio

            result = asyncio.run(route_manager.verify_native_target("example.com", 443, timeout=0.5))

        self.assertIsNone(result)

    def test_verify_sni_rejects_on_cert_verify_failure(self):
        calls = []

        async def fake_open_connection(host, port, ssl=None, server_hostname=None):
            calls.append((host, port, ssl, server_hostname))
            raise route_manager.ssl.SSLCertVerificationError("certificate verify failed")

        with patch.object(route_manager.asyncio, "open_connection", side_effect=fake_open_connection):
            import asyncio

            result = asyncio.run(route_manager.verify_sni("1.1.1.1", "example.com", port=443, timeout=0.5, tls_only=True))

        self.assertIsNone(result)
        self.assertEqual(len(calls), 1)
        strict_ctx = calls[0][2]
        self.assertEqual(getattr(strict_ctx, "verify_mode", None), route_manager.ssl.CERT_REQUIRED)
        self.assertTrue(getattr(strict_ctx, "check_hostname", False))

    def test_fast_route_cache_returns_healthy_unbanned_endpoint(self):
        host = "api.chatgpt.com"
        port = 443
        endpoint = ("1.1.1.1", 443)

        route_manager._ROUTE_FAST_CACHE[(host, port)] = {
            "mode": "white",
            "ep": endpoint,
            "exp": route_manager.time.monotonic() + 30.0,
        }
        route_manager._IP_HEALTH_SCORES[endpoint] = 0

        result = route_manager._fast_route_get(host, port, banned_set=set(), force_white=False)
        self.assertEqual(result, endpoint)

    def test_fast_route_cache_ignores_banned_or_unhealthy_endpoint(self):
        host = "api.chatgpt.com"
        port = 443
        endpoint = ("1.1.1.1", 443)

        route_manager._ROUTE_FAST_CACHE[(host, port)] = {
            "mode": "white",
            "ep": endpoint,
            "exp": route_manager.time.monotonic() + 30.0,
        }

        result_banned = route_manager._fast_route_get(host, port, banned_set={endpoint}, force_white=False)
        self.assertIsNone(result_banned)

        route_manager._IP_HEALTH_SCORES[endpoint] = -10
        result_unhealthy = route_manager._fast_route_get(host, port, banned_set=set(), force_white=False)
        self.assertIsNone(result_unhealthy)

    def test_tls_endpoint_ban_applies_across_tls_target_ports(self):
        host = "api.chatgpt.com"
        target_port = 443
        cached_endpoint = ("1.1.1.1", 2053)

        route_manager._ROUTE_FAST_CACHE[(host, target_port)] = {
            "mode": "white",
            "ep": cached_endpoint,
            "exp": route_manager.time.monotonic() + 30.0,
        }

        result = route_manager._fast_route_get(
            host,
            target_port,
            banned_set={("1.1.1.1", 8443)},
            force_white=False,
        )
        self.assertIsNone(result)

    def test_non_tls_endpoint_ban_remains_exact_port_only(self):
        host = "api.chatgpt.com"
        target_port = 80
        cached_endpoint = ("1.1.1.1", 80)

        route_manager._ROUTE_FAST_CACHE[(host, target_port)] = {
            "mode": "white",
            "ep": cached_endpoint,
            "exp": route_manager.time.monotonic() + 30.0,
        }

        result = route_manager._fast_route_get(
            host,
            target_port,
            banned_set={("1.1.1.1", 443)},
            force_white=False,
        )
        self.assertEqual(result, cached_endpoint)

    def test_collect_pool_endpoints_cached_deduplicates_sources(self):
        with patch.object(config, "IP_POOL", ["1.1.1.1:443", "1.1.1.1:443", "2.2.2.2:443"]), patch.object(
            route_manager.STATE,
            "ip_pool",
            return_value={("3.3.3.3", 443): "example.com", ("2.2.2.2", 443): "example.com"},
        ):
            eps_first = route_manager._collect_pool_endpoints_cached()
            eps_second = route_manager._collect_pool_endpoints_cached()

        self.assertEqual(eps_first, eps_second)
        self.assertIn(("1.1.1.1", 443), eps_first)
        self.assertIn(("2.2.2.2", 443), eps_first)
        self.assertIn(("3.3.3.3", 443), eps_first)
        self.assertEqual(len(eps_first), 3)


class StorageSmokeTests(unittest.TestCase):
    def test_route_files_are_world_writable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            hosts_path = os.path.join(tmpdir, "white_routes.txt")
            banned_path = os.path.join(tmpdir, "banned_routes.txt")

            storage.atomic_write_text(hosts_path, "1.1.1.1 example.com\n")
            storage.append_line(banned_path, "1.1.1.1 example.com")

            hosts_mode = stat.S_IMODE(os.stat(hosts_path).st_mode)
            banned_mode = stat.S_IMODE(os.stat(banned_path).st_mode)

            self.assertEqual(hosts_mode, 0o666)
            self.assertEqual(banned_mode, 0o666)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
