import os
import csv
import ipaddress
import re
from utils import paths

# ==========================================
# ASN DATA CACHE
# ==========================================
ASN_DATA_V4 = {i: [] for i in range(256)} 
ASN_DATA_V6 = []
ASN_LOADED = False

def load_asn_data():
    """Loads ASN datasets into memory for fast IP lookups."""
    global ASN_LOADED
    if ASN_LOADED: return

    v4_path = paths.root_path("IranASNs", "filtered_ipv4.csv")
    if os.path.exists(v4_path):
        with open(v4_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            next(reader, None) # Skip header
            for row in reader:
                if len(row) >= 9:
                    try:
                        net = ipaddress.IPv4Network(row[0].strip(), strict=False)
                        first_octet = net.network_address.packed[0]
                        ASN_DATA_V4[first_octet].append((net, row[5].strip(), row[6].strip(), row[8].strip()))
                    except Exception:
                        pass

    v6_path = paths.root_path("IranASNs", "filtered_ipv6.csv")
    if os.path.exists(v6_path):
        with open(v6_path, 'r', encoding='utf-8-sig') as f:
            reader = csv.reader(f)
            next(reader, None) # Skip header
            for row in reader:
                if len(row) >= 9:
                    try:
                        net = ipaddress.IPv6Network(row[0].strip(), strict=False)
                        ASN_DATA_V6.append((net, row[5].strip(), row[6].strip(), row[8].strip()))
                    except Exception:
                        pass

    ASN_LOADED = True

def get_asn_info(ip_str):
    """Takes an IP string and returns a tuple: (asn, as_name, as_type)"""
    if not ASN_LOADED:
        load_asn_data()
    try:
        ip_str = ip_str.strip()
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.version == 4:
            # Use packed bytes for the first-octet bucket — avoids split/int parsing entirely
            first_octet = ip_obj.packed[0]
            for net, asn, name, as_type in ASN_DATA_V4.get(first_octet, []):
                if ip_obj in net:
                    return asn, name, as_type
        else:
            # Transparently resolve IPv4-mapped IPv6 addresses (e.g. ::ffff:2.144.5.6)
            mapped = ip_obj.ipv4_mapped
            if mapped is not None:
                first_octet = mapped.packed[0]
                for net, asn, name, as_type in ASN_DATA_V4.get(first_octet, []):
                    if mapped in net:
                        return asn, name, as_type
            else:
                for net, asn, name, as_type in ASN_DATA_V6:
                    if ip_obj in net:
                        return asn, name, as_type
    except Exception:
        pass
    return None, "Unknown ASN", "Unknown"


def is_iranian_ip(ip_str):
    """Returns True if the given IP belongs to an Iranian ASN."""
    asn, _, _ = get_asn_info(ip_str)
    return asn is not None


def filter_to_iranian(items):
    """
    Filters a list of IP strings or (ip, port) tuples to only Iranian IPs.
    Returns (filtered_items, dropped_count).
    """
    if not ASN_LOADED:
        load_asn_data()
    result = []
    dropped = 0
    for item in items:
        if isinstance(item, tuple):
            ip = str(item[0]).strip()
        else:
            ip = str(item).split(':')[0].strip()
        if is_iranian_ip(ip):
            result.append(item)
        else:
            dropped += 1
    return result, dropped

def search_asns_by_regex(pattern_str, silent=False):
    """
    Searches for ASNs matching a regex pattern against ASN numbers and names.
    Returns list of subnets that match the pattern.
    """
    if not ASN_LOADED:
        load_asn_data()
    
    try:
        pattern = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        if not silent:
            print(f"[-] Invalid regex pattern: {e}")
        return []
    
    subnets = []
    matched_asns = set()
    
    # Search IPv4 ASNs
    for octet_list in ASN_DATA_V4.values():
        for net, asn, name, as_type in octet_list:
            # Match against ASN number or name
            if pattern.search(asn) or pattern.search(name):
                matched_asns.add(asn.upper())
                subnets.append(net)
    
    # Search IPv6 ASNs
    for net, asn, name, as_type in ASN_DATA_V6:
        if pattern.search(asn) or pattern.search(name):
            matched_asns.add(asn.upper())
            subnets.append(net)
    
    return subnets

def expand_target(target, silent=False):
    """
    Expands an AS Number (e.g. AS12345), CIDR, single IP, or regex pattern into a list of individual IP strings.
    Supports regex patterns with 'regex:' prefix for ASN matching.
    Protects against memory overflow from massive IPv6/IPv4 blocks.
    """
    target = target.strip()
    upper_target = target.upper()
    
    # Check if the target is a regex pattern for ASN search
    if target.startswith('regex:'):
        pattern_str = target[6:].strip()
        subnets = search_asns_by_regex(pattern_str, silent=silent)
        if not subnets and not silent:
            print(f"[-] No ASNs found matching regex: {pattern_str}")
            return []
        
        asn_ips = []
        total_ips = sum(net.num_addresses for net in subnets if net.version == 4)
        if total_ips > 1000000 and not silent:
            print(f"[*] Warning: Regex matched ASNs contain {total_ips} IPs. Expansion may take a moment...")
        
        for net in subnets:
            if net.version == 6 and net.num_addresses > 65536:
                if not silent:
                    print(f"[-] Skipping IPv6 subnet {net} to prevent memory overflow.")
                continue
            if net.num_addresses > 65536:
                if not silent:
                    print(f"[*] Warning: Subnet {net} is massive. Truncating to 65536 IPs.")
                asn_ips.extend([str(ip) for _, ip in zip(range(65536), net.hosts())])
                continue
            asn_ips.extend([str(ip) for ip in net])
        
        return asn_ips
    
    # Check if the target is an ASN (starts with 'AS' and followed by digits)
    if upper_target.startswith('AS') and upper_target[2:].isdigit():
        if not ASN_LOADED: 
            load_asn_data()
            
        asn_ips = []
        subnets = []
        
        for octet_list in ASN_DATA_V4.values():
            for net, asn, name, as_type in octet_list:
                if asn.upper() == upper_target: 
                    subnets.append(net)
                    
        for net, asn, name, as_type in ASN_DATA_V6:
            if asn.upper() == upper_target: 
                subnets.append(net)
                
        if not subnets and not silent:
            print(f"[-] No subnets found for {upper_target} in database.")
            return []
            
        total_ips = sum(net.num_addresses for net in subnets if net.version == 4)
        if total_ips > 1000000 and not silent: 
            print(f"[*] Warning: {upper_target} contains {total_ips} IPs. Expansion may take a moment...")
            
        for net in subnets:
            if net.version == 6 and net.num_addresses > 65536:
                if not silent: 
                    print(f"[-] Skipping IPv6 subnet {net} to prevent memory overflow.")
                continue
            if net.num_addresses > 65536:
                if not silent: 
                    print(f"[*] Warning: Subnet {net} is massive. Truncating to 65536 IPs.")
                # Fast generator evaluation trick to truncate without a memory crash
                asn_ips.extend([str(ip) for _, ip in zip(range(65536), net.hosts())])
                continue
            asn_ips.extend([str(ip) for ip in net])
            
        return asn_ips
        
    # Standard IP or CIDR expansion
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.version == 6 and net.num_addresses > 65536:
            if not silent: 
                print(f"[-] Skipping IPv6 subnet {target} to prevent memory overflow.")
            return []
        if net.num_addresses > 65536:
            if not silent: 
                print(f"[*] Warning: Subnet {target} is massive. Truncating to 65536 IPs.")
            return [str(ip) for _, ip in zip(range(65536), net.hosts())]
        return [str(ip) for ip in net]
    except ValueError: 
        return [target] # Treat as a raw domain or invalid string if parsing fails
