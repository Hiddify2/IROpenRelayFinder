import os
import sys
import json
import time
import socket
import asyncio
import random

from utils import config
from utils import data_store
from utils.helpers import load_white_cache, clear_screen
from utils.asn_engine import expand_target
from utils.route_manager import verify_sni

def draw_header():
    clear_screen()
    print("==================================================")
    print(f"   IROPENRELAYFINDER SUITE - DESYNC SCANNER v{config.VERSION}")
    print("==================================================")

async def run():
    """
    Entry point for the Desync Scanner module.
    Mines and verifies specific SNI/IP combinations to bypass DPI firewalls.
    """
    draw_header()
    print("[*] DPI Desync SNI/IP Miner")
    print("[*] Create and verify specific SNI/IP combinations to bypass DPI firewalls.")
    
    print("\n[?] Select Target SNIs:")
    print("    [1] Default Safe SNIs (config.DESYNC_SNI_LIST) [Recommended]")
    print("    [2] clean_snis.txt (Output from SNI Scanner)")
    print("    [3] Load Custom SNIs from File")
    print("    [4] Paste Custom SNIs Manually")
    choice_sni = input("    Choice [Default 1]: ").strip() or "1"
    
    target_snis = []
    
    if choice_sni == "1":
        target_snis.extend(config.DESYNC_SNI_LIST)
    elif choice_sni == "2":
        clean_lines = data_store.read_lines("clean_snis.txt", encoding="utf-8")
        if clean_lines:
            target_snis = [line.strip() for line in clean_lines if line.strip() and not line.startswith("#")]
        else:
            print("[-] 'clean_snis.txt' not found! Falling back to default list.")
            target_snis.extend(config.DESYNC_SNI_LIST)
    elif choice_sni == "3":
        fp = input("    Enter path to file: ").strip()
        if os.path.exists(fp):
            with open(fp, "r", encoding="utf-8") as f:
                target_snis = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        else:
            print("[-] File not found! Returning...")
            time.sleep(2)
            return
    elif choice_sni == "4":
        print("    Paste SNIs (Press Enter on an empty line to finish):")
        while True:
            line = input().strip()
            if not line: break
            target_snis.append(line)
            
    target_snis = list(set(target_snis))
    if not target_snis:
        print("[-] No SNIs selected.")
        time.sleep(2)
        return

    print(f"\n[*] Loaded {len(target_snis)} target SNIs.")
    print("\n[?] Select IP Source:")
    print("    [1] DNS Probing (Resolve SNIs to find local edge IPs) [Default]")
    print("    [2] DNS Probing + Custom IPs (Test both)")
    print("    [3] Custom IPs Only (No DNS Probing)")
    choice_ip = input("    Choice [Default 1]: ").strip() or "1"
    
    custom_ips = []
    if choice_ip in ["2", "3"]:
        print("\n    [1] Load from File\n    [2] Paste Manually\n    [3] Load from White IPs Cache")
        c = input("    Choice: ").strip()
        raw_ips = []
        if c == "1":
            fp = input("    Enter path to file: ").strip()
            if os.path.exists(fp):
                with open(fp, "r") as f:
                    raw_ips = [line.strip() for line in f if line.strip()]
        elif c == "2":
            print("    Paste IPs/CIDRs/ASNs (Press Enter on an empty line to finish):")
            while True:
                line = input().strip()
                if not line: break
                raw_ips.append(line)
        elif c == "3":
            raw_ips = [ip for ip, _ in load_white_cache()]
            if not raw_ips:
                print("    [-] White IPs Cache is empty.")
                
        if raw_ips:
            print("    [*] Expanding custom targets (CIDRs/ASNs)...")
            for t in raw_ips:
                custom_ips.extend(expand_target(t, silent=True))
            custom_ips = list(set(custom_ips))
            print(f"    [+] Loaded {len(custom_ips)} custom IPs.")

    do_mine = choice_ip in ["1", "2"]
    mined_pairs = {sni: set(custom_ips) for sni in target_snis}

    if do_mine:
        rounds_str = input("\n[?] Enter number of DNS resolution rounds [Default 5]: ").strip()
        rounds = int(rounds_str) if rounds_str.isdigit() else 5
        delay_str = input("[?] Enter delay between rounds in seconds [Default 2]: ").strip()
        delay = int(delay_str) if delay_str.isdigit() else 2

        print("\n[*] Mining IPs via DNS...")
        loop = asyncio.get_running_loop()
        
        for r in range(rounds):
            sys.stdout.write(f"\r[*] Round {r+1}/{rounds} - Resolving...     ")
            sys.stdout.flush()
            
            snis = list(target_snis)
            random.shuffle(snis)
            
            async def resolve_sni(domain):
                try:
                    info = await asyncio.wait_for(
                        loop.getaddrinfo(domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM),
                        timeout=3.0
                    )
                    ips = [item[4][0] for item in info]
                    mined_pairs[domain].update(ips)
                except Exception:
                    pass

            # Resolve concurrently for massive speed boost!
            await asyncio.gather(*[asyncio.create_task(resolve_sni(sni)) for sni in snis])
            
            if r < rounds - 1:
                await asyncio.sleep(delay)
        print()

    total_potential = sum(len(ips) for ips in mined_pairs.values())
    print(f"\n[*] Discovery complete. Found {total_potential} potential (SNI, IP) combinations.")
    
    if total_potential == 0:
        print("[-] No pairs to test.")
        input("\nPress Enter to return...")
        return
        
    print(f"[*] Verifying TLS reachability on port 443 (Concurrency: {config.MAX_CONCURRENT_SCANS})...")

    semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_SCANS)
    valid_pairs = {}
    tasks = []
    completed = 0
    total_tasks = total_potential

    async def check(sni, ip):
        nonlocal completed
        async with semaphore:
            # We reuse the robust verify_sni method from our routing layer
            if await verify_sni(ip, sni, 443, timeout=3.0):
                valid_pairs.setdefault(sni, set()).add(ip)
                sys.stdout.write('\r' + ' ' * 80 + '\r')
                print(f"[+] VERIFIED: {sni} -> {ip}")
                
            completed += 1
            if completed % 10 == 0 or completed == total_tasks:
                bar_len = 30
                filled = int(bar_len * completed / total_tasks)
                bar = '█' * filled + '-' * (bar_len - filled)
                percent = (completed / total_tasks) * 100
                sys.stdout.write(f"\r   [{bar}] {percent:.1f}% ({completed}/{total_tasks}) Verifying...")
                sys.stdout.flush()

    for sni, ips in mined_pairs.items():
        for ip in ips:
            tasks.append(asyncio.create_task(check(sni, ip)))

    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        print("\n\n[-] Scan cancelled by user.")
        for t in tasks:
            if not t.done(): t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    
    sys.stdout.write('\r' + ' ' * 80 + '\r')

    # Convert sets back to lists for JSON serialization
    valid_pairs_list = {sni: list(ips) for sni, ips in valid_pairs.items() if ips}
    total_ips = sum(len(ips) for ips in valid_pairs_list.values())
    
    print(f"\n[+] Validation complete! Found {total_ips} fully working IPs across {len(valid_pairs_list)} SNIs.")

    if valid_pairs_list:
        data_store.write_json("desync_pairs.json", valid_pairs_list, indent=4)
        print("[✓] Saved to data/desync_pairs.json")

        print("\nTop working SNIs:")
        sorted_snis = sorted(valid_pairs_list.keys(), key=lambda k: len(valid_pairs_list[k]), reverse=True)
        for sni in sorted_snis[:10]:
            print(f"  -> {sni:<30} : {len(valid_pairs_list[sni])} IPs (e.g. {valid_pairs_list[sni][0]})")
        if len(sorted_snis) > 10:
            print("  ... and more.")

    input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    asyncio.run(run())
