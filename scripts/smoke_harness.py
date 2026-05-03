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
from cores import mmdf_engine
from cores import white_core


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

        async def fake_mass_scan(ips, domains, results_list, skip_tcp=False, deep_scan=False, pause_controller=None):
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


class RouteManagerSmokeTests(unittest.TestCase):
    def setUp(self):
        route_manager._ROUTE_FAST_CACHE.clear()
        route_manager._ROUTE_L1_CACHE.clear()
        route_manager._IP_HEALTH_SCORES.clear()
        route_manager._EP_REGISTRY.clear()
        route_manager._HOST_VERIFY_CACHE.clear()
        config.IP_POOL_METADATA.clear()
        route_manager._POOL_CACHE["expiry"] = 0.0
        route_manager._POOL_CACHE["sig"] = None
        route_manager._POOL_CACHE["eps"] = []
        route_manager.STATE.clear_routes()
        route_manager.STATE.clear_banned_routes()
        route_manager.STATE.clear_dead_ip_pool()
        config.FAILED_DOMAINS.clear()

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

    def test_verify_sni_delegates_to_shared_probe_helper(self):
        async def fake_probe(ip, domain, port=443, timeout=4.0, http_verify=True, tls_only=False, return_reason=False):
            self.assertEqual((ip, domain, port, timeout, http_verify, tls_only, return_reason), (
                "1.1.1.1",
                "example.com",
                443,
                0.5,
                True,
                True,
                True,
            ))
            return "1.1.1.1", 12.5, "ok"

        with patch.object(route_manager, "probe_route_endpoint", side_effect=fake_probe):
            import asyncio

            result = asyncio.run(
                route_manager.verify_sni(
                    "1.1.1.1",
                    "example.com",
                    port=443,
                    timeout=0.5,
                    http_verify=True,
                    tls_only=True,
                    return_reason=True,
                )
            )

        self.assertEqual(result, ("1.1.1.1", 12.5, "ok"))

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

    def test_health_score_prefers_fresh_neutral_over_stale_failures(self):
        fresh = route_manager.EndpointStats()
        stale = route_manager.EndpointStats()
        stale_state = stale._state("example.com", create=True)
        stale_state.update(
            {
                "ewma_latency_ms": 460.0,
                "fail_count": 8,
                "last_ok_ts": route_manager.time.monotonic() - 600.0,
                "success_count": 3,
            }
        )
        fresh_score = fresh.score(route_manager.time.monotonic(), domain="example.com")
        stale_score = stale.score(route_manager.time.monotonic(), domain="example.com")

        self.assertLess(fresh_score, stale_score)

    def test_quarantined_endpoint_is_filtered_from_candidates(self):
        endpoint = ("1.1.1.1", 443)
        stats = route_manager._get_endpoint_stats(endpoint)
        stats.quarantine("x.com", "connect-error")

        with patch.object(config, "IP_POOL", [endpoint]), patch.object(
            route_manager.STATE,
            "ip_pool",
            return_value={endpoint: "example.com"},
        ):
            route_manager._POOL_CACHE["expiry"] = 0.0
            route_manager._POOL_CACHE["sig"] = None
            route_manager._POOL_CACHE["eps"] = []
            primary_x, fallback_x = route_manager._prepare_candidates(443, banned_for_domain=set(), target_host="x.com")
            primary_g, fallback_g = route_manager._prepare_candidates(443, banned_for_domain=set(), target_host="google.com")

        self.assertNotIn(endpoint, primary_x)
        self.assertNotIn(endpoint, fallback_x)
        self.assertIn(endpoint, primary_g)
        self.assertNotIn(endpoint, fallback_g)

    def test_quarantine_ttl_clears_reason_and_consecutive_failures(self):
        stats = route_manager.EndpointStats()
        state = stats._state("x.com", create=True)
        state["consecutive_failures"] = 5
        state["quarantine_reason"] = "timeout"
        # Use the timeout-specific base TTL (600s) plus a buffer instead of generic TTL
        timeout_ttl = float(getattr(config, "ROUTE_QUARANTINE_TIMEOUT_BASE_SEC", 600.0))
        state["quarantine_ts"] = route_manager.time.monotonic() - timeout_ttl - 1.0

        self.assertFalse(stats.is_quarantined(route_manager.time.monotonic(), domain="x.com"))
        self.assertEqual(state["quarantine_reason"], "")
        self.assertEqual(state["consecutive_failures"], 0)

    def test_google_only_endpoints_remain_candidates_for_non_google_targets(self):
        google_ep = ("1.1.1.1", 443)
        universal_ep = ("2.2.2.2", 443)
        with patch.object(config, "IP_POOL", {
            google_ep: "mail.google.com",
            universal_ep: "x.com",
        }), patch.object(
            route_manager.STATE,
            "ip_pool",
            return_value={
                google_ep: "mail.google.com",
                universal_ep: "x.com",
            },
        ):
            config.IP_POOL_METADATA[google_ep] = {
                "domains": ("mail.google.com",),
                "latency_ms": 450.0,
                "google_verified": True,
                "google_only": True,
                "universal": False,
            }
            config.IP_POOL_METADATA[universal_ep] = {
                "domains": ("x.com",),
                "latency_ms": 4200.0,
                "google_verified": False,
                "google_only": False,
                "universal": True,
            }
            route_manager._POOL_CACHE["expiry"] = 0.0
            route_manager._POOL_CACHE["sig"] = None
            route_manager._POOL_CACHE["eps"] = []
            primary, fallback = route_manager._prepare_candidates(
                443,
                banned_for_domain=set(),
                target_host="x.com",
            )

        self.assertIn(google_ep, primary)
        self.assertNotIn(google_ep, fallback)
        self.assertIn(universal_ep, primary)

    def test_google_targets_prefer_google_verified_endpoints(self):
        google_ep = ("4.4.4.4", 443)
        universal_ep = ("5.5.5.5", 443)
        with patch.object(config, "IP_POOL", {
            google_ep: "mail.google.com",
            universal_ep: "x.com",
        }), patch.object(
            route_manager.STATE,
            "ip_pool",
            return_value={
                google_ep: "mail.google.com",
                universal_ep: "x.com",
            },
        ):
            config.IP_POOL_METADATA[google_ep] = {
                "domains": ("mail.google.com",),
                "latency_ms": 450.0,
                "google_verified": True,
                "google_only": True,
                "universal": False,
            }
            config.IP_POOL_METADATA[universal_ep] = {
                "domains": ("x.com",),
                "latency_ms": 4200.0,
                "google_verified": False,
                "google_only": False,
                "universal": True,
            }
            route_manager._POOL_CACHE["expiry"] = 0.0
            route_manager._POOL_CACHE["sig"] = None
            route_manager._POOL_CACHE["eps"] = []
            primary, fallback = route_manager._prepare_candidates(
                443,
                banned_for_domain=set(),
                target_host="mail.google.com",
            )

        self.assertIn(google_ep, primary)
        self.assertLess(
            route_manager._target_candidate_priority(google_ep, "mail.google.com"),
            route_manager._target_candidate_priority(universal_ep, "mail.google.com"),
        )

    def test_known_latency_endpoint_gets_extended_probe_timeout(self):
        endpoint = ("3.3.3.3", 443)
        config.IP_POOL_METADATA[endpoint] = {
            "domains": ("chatgpt.com",),
            "latency_ms": 3118.0,
            "google_verified": False,
            "google_only": False,
            "universal": True,
        }

        timeout_sec = route_manager._endpoint_probe_timeout_sec(endpoint, "chatgpt.com")

        self.assertGreater(timeout_sec, 3.118)
        self.assertGreater(timeout_sec, config.RACE_PER_IP_TIMEOUT)
        self.assertAlmostEqual(timeout_sec, (3118.0 + config.ROUTE_KNOWN_LATENCY_HEADROOM_MS) / 1000.0, places=3)

    def test_verify_sni_rejects_invalid_hostname_before_probe(self):
        called = {"probe": 0}

        async def fake_probe(*args, **kwargs):
            called["probe"] += 1
            return True

        with patch.object(route_manager, "probe_route_endpoint", side_effect=fake_probe):
            import asyncio

            result = asyncio.run(
                route_manager.verify_sni(
                    "1.1.1.1",
                    "bad-.example.com",
                    port=443,
                    timeout=0.5,
                    http_verify=True,
                    tls_only=False,
                    return_reason=True,
                )
            )

        self.assertEqual(result, (None, 0.0, "invalid-server-hostname"))
        self.assertEqual(called["probe"], 0)

    def test_mark_route_dead_purges_l2_and_quarantines_endpoint(self):
        host = "example.com"
        endpoint = ("1.1.1.1", 443)
        route_manager.STATE.exact_routes()[host] = {443: endpoint[0]}
        route_manager.STATE.wildcard_routes()[".example.com"] = {443: endpoint[0]}

        route_manager.mark_route_dead(host, 443, endpoint, reason="connect-error", latency_ms=42.0)

        self.assertNotIn(host, route_manager.STATE.exact_routes())
        self.assertNotIn(".example.com", route_manager.STATE.wildcard_routes())
        self.assertTrue(route_manager._get_endpoint_stats(endpoint).is_quarantined(domain=host))
        self.assertFalse(route_manager._get_endpoint_stats(endpoint).is_quarantined(domain="other.com"))

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


class MmdfSmokeTests(unittest.TestCase):
    def test_profile_matching_routes_reddit_through_fastly_profile(self):
        profile = mmdf_engine.match_fronting_profile("reddit.com")

        self.assertIsNotNone(profile)
        self.assertEqual(profile["name"], "fastly")
        self.assertEqual(profile["front_sni"], "www.python.org")

    def test_pick_outbound_ip_uses_profile_front_without_global_override(self):
        async def fake_resolve_host(hostname, target_port):
            self.assertEqual(hostname, "www.python.org")
            self.assertEqual(target_port, 443)
            return "151.101.0.223"

        profile = mmdf_engine.match_fronting_profile("reddit.com")
        with patch.object(mmdf_engine, "_resolve_host", side_effect=fake_resolve_host):
            import asyncio

            result = asyncio.run(
                mmdf_engine.pick_outbound_ip(
                    profile,
                    443,
                    prefer_front_ip=True,
                    front_sni_override=None,
                    front_ip_override=None,
                )
            )

        self.assertEqual(result, ("151.101.0.223", 443))

    def test_mmdf_disabled_prompt_does_not_ask_for_front_sni_or_ip(self):
        prompts = []

        def fake_input(prompt):
            prompts.append(prompt)
            return "n"

        with patch("builtins.input", side_effect=fake_input):
            white_core._resolve_mmdf_runtime()

        self.assertEqual(len(prompts), 1)
        self.assertIn("Enable MMDF", prompts[0])
        self.assertFalse(white_core._MMDF_READY)
        self.assertEqual(config.MMDF_SNI, "")
        self.assertEqual(config.MMDF_IP, "")

    def test_mmdf_default_startup_uses_per_domain_profiles(self):
        prompts = []

        def fake_input(prompt):
            prompts.append(prompt)
            return ""

        config.MMDF_SNI = "google.com"
        config.MMDF_IP = "8.8.8.8"

        with patch("builtins.input", side_effect=fake_input), patch.object(
            white_core.mmdf_ca, "any_backend_available", return_value=True
        ), patch.object(white_core.mmdf_ca, "ca_files_exist", return_value=True), patch.object(
            white_core.mmdf_ca, "is_ca_installed", return_value=True
        ):
            white_core._resolve_mmdf_runtime()

        self.assertTrue(white_core._MMDF_READY)
        self.assertEqual(white_core._MMDF_FRONT_SNI, "")
        self.assertEqual(white_core._MMDF_FRONT_IP, "")
        self.assertEqual(config.MMDF_SNI, "")
        self.assertEqual(config.MMDF_IP, "")
        self.assertTrue(any("per-domain profiles" in prompt for prompt in prompts))


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
