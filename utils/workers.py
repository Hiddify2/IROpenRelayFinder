import asyncio
import random
import sys
import os

from utils import config
from utils import helpers
from utils import asn_engine
from utils import route_manager
from utils import data_store
from utils.runtime_state import STATE
from utils.route_service import ROUTE_SERVICE

# ==========================================
# PASSIVE BACKGROUND SCANNER
# ==========================================
async def passive_scanner():
    """
    Runs continuously in the background. It randomly selects ISPs based on the 
    current White IPs cache and scans their entire subnets for new working IPs 
    to continuously feed the dynamic IP_POOL.
    """
    print("\n[+] Passive scanner started in background...")
    total_scanned = 0
    
    if not asn_engine.ASN_LOADED: 
        asn_engine.load_asn_data()
    
    # Lazy import to avoid circular dependency with the scanner core
    from cores.scanner import check_ip_tls
    
    while True:
        try:
            if STATE.should_pause_background_scan():
                await asyncio.sleep(15)
                continue

            target_as_names = set()
            cached_eps = helpers.load_white_cache()
            
            for ip, _port in cached_eps:
                asn, name, as_type = asn_engine.get_asn_info(ip)
                if name and name != "Unknown ASN": 
                    target_as_names.add(name)
                    
            mode_used = "Cached ISP"
            if not target_as_names:
                mode_used = "Random ISP"
                all_names = set()
                for octet_list in asn_engine.ASN_DATA_V4.values():
                    for net, asn, name, as_type in octet_list: 
                        all_names.add(name)
                if all_names: 
                    target_as_names.add(random.choice(list(all_names)))
            
            if not target_as_names:
                await asyncio.sleep(60)
                continue
                
            current_company = random.choice(list(target_as_names))
            company_subnets = []
            associated_asns = set()
            
            for octet_list in asn_engine.ASN_DATA_V4.values():
                for net, asn, name, as_type in octet_list:
                    if name == current_company:
                        company_subnets.append(net.exploded)
                        associated_asns.add(asn)
                        
            target_ips = set()
            for subnet in company_subnets: 
                target_ips.update(asn_engine.expand_target(subnet, silent=True))
                
            target_ips = list(target_ips)
            random.shuffle(target_ips)
            target_endpoints = [(ip, port) for ip in target_ips for port in config.TARGET_PORTS]
            
            if not target_endpoints:
                await asyncio.sleep(60)
                continue
                
            clean_company_name = current_company[:35] + "..." if len(current_company) > 35 else current_company
            asn_list_str = ",".join(list(associated_asns)[:3]) + ("..." if len(associated_asns) > 3 else "")
            print(f"\n[PASSIVE] Mode: {mode_used} | Target: {clean_company_name} ({asn_list_str}) | Queued {len(target_ips)} IPs.")
            
            semaphore = asyncio.Semaphore(20) 
            
            for chunk_start in range(0, len(target_endpoints), 100):
                chunk = target_endpoints[chunk_start:chunk_start + 100]
                tasks = [asyncio.create_task(check_ip_tls(ep, config.DEFAULT_DOMAINS, semaphore)) for ep in chunk]
                
                try:
                    for future in asyncio.as_completed(tasks):
                        try:
                            # Safely unpack the updated 4-value tuple
                            res = await future
                            ip, port, passed, latency = res[0], res[1], res[2], res[3]
                            soft_domains = res[4] if len(res) > 4 else []
                            endpoint = (ip, port)
                            
                            if passed or soft_domains:
                                if soft_domains:
                                    # Securely isolate worker IPs and ban them from AI routing paths
                                    try:
                                        data_store.append_line("cloudflare_workers_ips.txt", helpers.format_ip_port(ip, port), encoding="utf-8")
                                        for s_dom in soft_domains:
                                            bd = helpers.get_base_domain(s_dom)
                                            STATE.add_ban(bd, endpoint)
                                    except Exception:
                                        pass
                                
                                # Add the IP to the active pool (it's safe now because failing domains are banned!)
                                if endpoint not in STATE.ip_pool():
                                    STATE.ip_pool()[endpoint] = passed[0] if passed else None
                                    
                                    # Evict oldest IP if pool is full
                                    if len(STATE.ip_pool()) > 150:
                                        oldest_ip = next(iter(STATE.ip_pool()))
                                        STATE.dead_ip_pool()[oldest_ip] = STATE.ip_pool().pop(oldest_ip) 
                                        
                                    is_new = endpoint not in cached_eps
                                    status_tag = "[NEW]" if is_new else "[CACHED]"
                                    helpers.save_to_white_cache([endpoint])
                                    
                                    found_asn, found_name, _ = asn_engine.get_asn_info(ip)
                                    clean_found_name = found_name[:20] + "..." if len(found_name) > 20 else found_name
                                    asn_display = f"({found_asn} - {clean_found_name})" if found_asn else "(Unknown ASN)"
                                    
                                    if passed:
                                        total_tested = len(set(config.DEFAULT_DOMAINS).union(passed))
                                        print(f"[PASSIVE] Found & added {status_tag} White endpoint: {helpers.format_ip_port(ip, port)} [{len(passed)}/{total_tested}] {asn_display}")
                                    else:
                                        print(f"[PASSIVE] Found & added {status_tag} Worker endpoint: {helpers.format_ip_port(ip, port)} (Auto-Banned AI targets) {asn_display}")
                        except Exception: 
                            pass
                finally:
                    for t in tasks:
                        if not t.done(): 
                            t.cancel()
                
                previous_milestone = total_scanned // 1000
                total_scanned += len(chunk)
                current_milestone = total_scanned // 1000
                if current_milestone > previous_milestone: 
                    print(f"[PASSIVE] Progress: {total_scanned} IPs checked in the background so far...")
                    
                await asyncio.sleep(2) 

            print("\n[PASSIVE] Sweep finished. Resting before next cycle...")
            await asyncio.sleep(300) 
            
        except asyncio.CancelledError:
            if 'tasks' in locals():
                for t in tasks:
                    if not t.done(): 
                        t.cancel()
            break
        except Exception: 
            await asyncio.sleep(60)

# ==========================================
# ACTIVE POOL HEALTH CHECKER
# ==========================================
async def health_checker():
    """
    Continuously iterates over the active IP_POOL and dead IP_POOL.
    Removes broken IPs, revives working ones, and prunes dead cache routes.
    Uses concurrent batching to verify hundreds of IPs in seconds.
    """
    print("[+] Active Health-Checker started in background...")
    await asyncio.sleep(30) 
    
    async def _verify_batch(items):
        """Verify a list of (ip, domain) tuples concurrently, return [(ip, domain, alive_bool)]"""
        sem = asyncio.Semaphore(30)
        async def _check(endpoint, domain):
            async with sem:
                parsed = helpers.parse_ip_port(endpoint)
                if not parsed:
                    return endpoint, domain, False
                ip, port = parsed
                if domain:
                    alive = bool(await ROUTE_SERVICE.verify_sni(ip, domain, port, timeout=config.RACE_TIMEOUT))
                    return (ip, port), domain, alive
                else:
                    for d in config.DEFAULT_DOMAINS:
                        if await ROUTE_SERVICE.verify_sni(ip, d, port, timeout=config.RACE_TIMEOUT):
                            return (ip, port), d, True
                    return (ip, port), None, False
                    
        tasks = [asyncio.create_task(_check(ep, d)) for ep, d in items]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        valid_results = []
        for r in results:
            if isinstance(r, tuple) and len(r) == 3:
                valid_results.append(r)
        return valid_results

    while True:
        try:
            if STATE.should_pause_background_scan():
                await asyncio.sleep(20)
                continue

            # 1. Verify Active Pool
            if STATE.ip_pool():
                pool_copy = list(STATE.ip_pool().items())
                results = await _verify_batch(pool_copy)
                for ip, test_domain, is_alive in results:
                    if is_alive:
                        STATE.ip_pool()[ip] = test_domain
                    elif ip in STATE.ip_pool():
                        STATE.dead_ip_pool()[ip] = STATE.ip_pool().pop(ip)
                        print(f"[HEALTH] Removed dead IP from pool: {ip}")

            # 2. Attempt to Revive Dead Pool
            if STATE.dead_ip_pool():
                dead_copy = list(STATE.dead_ip_pool().items())
                results = await _verify_batch(dead_copy)
                for ip, test_domain, is_alive in results:
                    if is_alive and ip in STATE.dead_ip_pool():
                        STATE.ip_pool()[ip] = test_domain
                        del STATE.dead_ip_pool()[ip]
                        print(f"[HEALTH] 🌟 Revived IP back into active pool: {ip}")
                        
                        # Evict oldest if pool is full
                        if len(STATE.ip_pool()) > 150:
                            oldest_ip = next(iter(STATE.ip_pool()))
                            STATE.dead_ip_pool()[oldest_ip] = STATE.ip_pool().pop(oldest_ip)

                # Prevent dead pool from growing infinitely
                while len(STATE.dead_ip_pool()) > 300: 
                    STATE.dead_ip_pool().pop(next(iter(STATE.dead_ip_pool())))

            # 3. Prune Dead Routes from Cache
            routes_changed = False
            
            # Check Wildcard Routes
            if STATE.wildcard_routes():
                wildcard_copy = list(STATE.wildcard_routes().items())
                w_items = []
                for base_domain, port_map in wildcard_copy:
                    if isinstance(port_map, dict):
                        for port, ip in port_map.items():
                            w_items.append(((ip, port), base_domain.lstrip('.')))
                results = await _verify_batch(w_items)
                for endpoint, test_domain, is_alive in results:
                    if not is_alive:
                        ep_ip, ep_port = endpoint
                        base_domain = f".{test_domain}"
                        port_map = STATE.wildcard_routes().get(base_domain)
                        if isinstance(port_map, dict):
                            port_map.pop(ep_port, None)
                            if not port_map:
                                STATE.wildcard_routes().pop(base_domain, None)
                        exact_map = STATE.exact_routes().get(test_domain)
                        if isinstance(exact_map, dict):
                            exact_map.pop(ep_port, None)
                            if not exact_map:
                                STATE.exact_routes().pop(test_domain, None)
                        routes_changed = True
                        print(f"[HEALTH] Removed dead route: {base_domain} -> {helpers.format_ip_port(ep_ip, ep_port)}")

            # Check Exact Routes
            if STATE.exact_routes():
                exact_copy = list(STATE.exact_routes().items())
                e_items = []
                for domain, port_map in exact_copy:
                    clean_domain = domain.lstrip('.')
                    wildcard_key = f".{clean_domain}"
                    if wildcard_key in STATE.wildcard_routes():
                        continue
                    if isinstance(port_map, dict):
                        for port, ip in port_map.items():
                            e_items.append(((ip, port), clean_domain))
                        
                if e_items:
                    results = await _verify_batch(e_items)
                    for endpoint, clean_domain, is_alive in results:
                        if not is_alive:
                            ep_ip, ep_port = endpoint
                            port_map = STATE.exact_routes().get(clean_domain)
                            if isinstance(port_map, dict):
                                port_map.pop(ep_port, None)
                                if not port_map:
                                    STATE.exact_routes().pop(clean_domain, None)
                            routes_changed = True
                            print(f"[HEALTH] Removed dead route: {clean_domain} -> {helpers.format_ip_port(ep_ip, ep_port)}")

            if routes_changed:
                await ROUTE_SERVICE.async_rewrite_routes(STATE.exact_routes(), STATE.wildcard_routes())
                print("[HEALTH] Routing cache file updated.")
                
        except asyncio.CancelledError: 
            break
        except Exception: 
            pass
            
        await asyncio.sleep(120) 

# ==========================================
# LATENCY ROUTE PRE-WARMER
# ==========================================
async def prewarm_routes():
    """Forces initial races for essential domains immediately on startup."""
    PREWARM_DOMAINS = ['meet.google.com', 'www.youtube.com', 'meet.turns.goog']
    target_port = config.primary_target_port()
    print("[PREWARM] Pre-warming routes for latency-sensitive domains...")
    
    for domain in PREWARM_DOMAINS:
        if domain not in STATE.exact_routes():
            ip = await ROUTE_SERVICE.get_routed_ip(domain, target_port)
            print(f"[PREWARM] {domain} -> {helpers.format_ip_port(ip, target_port) if ip else 'unresolved'}")
        await asyncio.sleep(0.5)

# ==========================================
# === END OF FILE ===
# ==========================================
