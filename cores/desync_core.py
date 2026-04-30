import os
import struct
import socket
import threading
import asyncio
import sys

# Prevent namespace collision with global 'utils' packages
import utils.helpers as helpers

# ==========================================
# TLS FAKE CLIENT HELLO GENERATOR (Modern Mimic)
# ==========================================
def generate_fake_client_hello(sni_str):
    sni_bytes = sni_str.encode()
    
    # --- Extensions ---
    def ext(type_id, data): 
        return struct.pack('!HH', type_id, len(data)) + data

    # SNI (0x0000)
    sni_data = struct.pack('!HBH', len(sni_bytes)+3, 0, len(sni_bytes)) + sni_bytes
    sni_ext = ext(0x0000, sni_data)
    
    # Extended master secret (0x0017) - empty
    ems_ext = ext(0x0017, b'')
    
    # Renegotiation info (0xff01)
    renego_ext = ext(0xff01, b'\x00')
    
    # Supported groups (0x000a): x25519, secp256r1, secp384r1
    groups_ext = ext(0x000a, struct.pack('!H3H', 6, 0x001d, 0x0017, 0x0018))
    
    # EC point formats (0x000b)
    points_ext = ext(0x000b, b'\x02\x00\x01')
    
    # Session ticket (0x0023) - empty (common in real handshakes)
    ticket_ext = ext(0x0023, b'')
    
    # ALPN (0x0010): h2, http/1.1
    alpn_list = b'\x00\x02h2' + b'\x00\x08http/1.1'
    alpn_ext = ext(0x0010, struct.pack('!H', len(alpn_list)) + alpn_list)
    
    # Status request (0x0005)
    status_ext = ext(0x0005, b'\x01\x00\x00\x00\x00')
    
    # Signature algorithms (0x000d)
    sig_algs = struct.pack('!H8H', 16, 0x0403,0x0503,0x0603,0x0804,0x0805,0x0806,0x0401,0x0501)
    sig_ext = ext(0x000d, sig_algs)
    
    # Supported versions (0x002b): TLS 1.3, TLS 1.2
    sv_ext = ext(0x002b, b'\x04\x03\x04\x03\x03')
    
    # PSK key exchange modes (0x002d)
    psk_ext = ext(0x002d, b'\x01\x01')
    
    # Key share (0x0033): x25519 with random 32-byte key
    ks_key = os.urandom(32)
    ks_ext = ext(0x0033, struct.pack('!HHH', 36, 0x001d, 32) + ks_key)
    
    # Compress certificate (0x001b)
    compress_ext = ext(0x001b, b'\x02\x00\x01')

    extensions = (sni_ext + ems_ext + renego_ext + groups_ext + points_ext + 
                  ticket_ext + alpn_ext + status_ext + sig_ext + sv_ext + 
                  psk_ext + ks_ext + compress_ext)

    # Cipher suites: TLS 1.3 + TLS 1.2 fallbacks (matches Chrome 120 profile)
    ciphers = bytes([
        0x13,0x01, 0x13,0x02, 0x13,0x03,    # TLS 1.3
        0xC0,0x2B, 0xC0,0x2F, 0xC0,0x2C, 0xC0,0x30,  # ECDHE-ECDSA/RSA GCM
        0xC0,0x0A, 0xC0,0x14, 0x00,0x9C, 0x00,0x9D,  # more TLS 1.2
        0x00,0xFF  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ])
    
    cipher_block = struct.pack('!H', len(ciphers)) + ciphers
    session_id = os.urandom(32)
    random_bytes = os.urandom(32)

    client_hello = (b'\x03\x03' + random_bytes + b'\x20' + session_id +
                    cipher_block + b'\x01\x00' +
                    struct.pack('!H', len(extensions)) + extensions)

    handshake = b'\x01' + struct.pack('!I', len(client_hello))[1:] + client_hello
    record = b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake
    return record

# ==========================================
# RAW SOCKET DPI INJECTOR (LINUX ONLY)
# ==========================================
class LinuxDpiEngine:
    def __init__(self):
        self.monitored = {}
        self.lock = threading.Lock()
        self.running = False
        self.sniff_sock = None
        self.send_sock = None

    def start(self):
        if self.running: return
        
        if not hasattr(socket, 'AF_PACKET'):
            print("\n[-] Pure Python DPI Engine requires Linux (AF_PACKET). Windows/macOS is not supported.")
            self.running = False
            return
            
        try:
            self.sniff_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003)) 
            self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.running = True
            threading.Thread(target=self._sniff_loop, daemon=True).start()
        except PermissionError:
            if getattr(self, 'sniff_sock', None):
                self.sniff_sock.close()
                self.sniff_sock = None
            if getattr(self, 'send_sock', None):
                self.send_sock.close()
                self.send_sock = None
            print("\n[-] Sudo/root privileges required to start raw socket DPI Engine!")
            self.running = False
        except Exception as e:
            if getattr(self, 'sniff_sock', None):
                self.sniff_sock.close()
                self.sniff_sock = None
            if getattr(self, 'send_sock', None):
                self.send_sock.close()
                self.send_sock = None
            print(f"\n[-] Failed to start raw socket DPI Engine: {e}")
            print("[-] Sudo/root privileges are typically required.")
            self.running = False

    def _sniff_loop(self):
        while self.running:
            try:
                packet, _ = self.sniff_sock.recvfrom(65535)
                
                # Robust EtherType validation (Bug D Fix)
                ip_offset = -1
                if len(packet) >= 14:
                    ethertype = struct.unpack('!H', packet[12:14])[0]
                    if ethertype == 0x0800:   # IPv4
                        ip_offset = 14
                    elif ethertype == 0x8100: # VLAN-tagged
                        inner = struct.unpack('!H', packet[16:18])[0]
                        ip_offset = 18 if inner == 0x0800 else -1
                    elif ethertype == 0x86DD: # IPv6 - skip
                        continue
                elif len(packet) >= 4 and (packet[0] >> 4) == 4:  # loopback/raw
                    ip_offset = 0
                    
                if ip_offset == -1 or len(packet) < ip_offset + 20: 
                    continue
                    
                ip_header = packet[ip_offset:ip_offset+20]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                if iph[6] != socket.IPPROTO_TCP:
                    continue
                    
                ihl = (iph[0] & 0xF) * 4
                ip_total_len = iph[2]

                src_ip = socket.inet_ntoa(iph[8])
                dst_ip = socket.inet_ntoa(iph[9])

                tcp_offset = ip_offset + ihl
                tcph = packet[tcp_offset:tcp_offset+20]
                if len(tcph) < 20: continue

                src_port, dst_port, seq, ack, offset_res, flags = struct.unpack('!HHLLBB', tcph[:14])
                tcp_data_offset = offset_res >> 4
                payload_len = ip_total_len - ihl - (tcp_data_offset * 4)
                
                if (flags & 0x10) and not (flags & 0x02):
                    if payload_len == 0:
                        key_outbound = (src_port, dst_ip, dst_port)
                        with self.lock:
                            if key_outbound in self.monitored:
                                conn = self.monitored[key_outbound]
                                if not conn['done']:
                                    conn['seq'] = seq
                                    conn['ack'] = ack
                                    conn['src_ip'] = src_ip
                                    conn['done'] = True
                                    conn['loop'].call_soon_threadsafe(conn['event'].set)
                    
                    key_inbound = (dst_port, src_ip, src_port)
                    with self.lock:
                        if key_inbound in self.monitored:
                            conn = self.monitored[key_inbound]
                            if conn['fake_seq'] is not None and not conn['t2a_done']:
                                expected_ack = conn['seq'] 
                                if ack == expected_ack:
                                    conn['t2a_done'] = True
                                    conn['loop'].call_soon_threadsafe(conn['t2a_event'].set)

            except Exception:
                pass

    def monitor_connection(self, local_port, dst_ip, dst_port):
        loop = asyncio.get_running_loop()
        event = asyncio.Event()
        t2a_event = asyncio.Event()
        key = (local_port, dst_ip, dst_port)
        with self.lock:
            self.monitored[key] = { 
                'event': event, 't2a_event': t2a_event, 'loop': loop, 
                'done': False, 't2a_done': False, 'seq': None, 'ack': None,
                'src_ip': None, 'fake_seq': None, 'fake_len': None
            }
        return event, t2a_event

    def get_seq_ack_ip(self, local_port, dst_ip, dst_port):
        key = (local_port, dst_ip, dst_port)
        with self.lock:
            conn = self.monitored.get(key, None)
            if conn: return conn['seq'], conn['ack'], conn['src_ip']
        return None, None, None

    def inject_fake_packet(self, src_ip, dst_ip, src_port, dst_port, seq, ack, payload, strategy="oob"):
        c_id = (src_port, dst_ip, dst_port)
        
        offset = 5 << 4
        flags = 0x18  
        window = 5840
        use_seq = seq
        bad_csum = False
        
        if strategy == "oob":
            use_seq = (seq + 100000) & 0xffffffff
        elif strategy == "bad_csum":
            bad_csum = True
        elif strategy == "ttl":
            try: self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 8)
            except: pass
        elif strategy == "syn":
            flags = 0x02
            use_seq = (seq + 100000) & 0xffffffff 
        elif strategy == "rst":
            flags = 0x04
            use_seq = (seq + 100000) & 0xffffffff 
        elif strategy == "fin":
            flags = 0x01
            use_seq = (seq + 100000) & 0xffffffff 
            
        with self.lock:
            if c_id in self.monitored:
                self.monitored[c_id]['fake_seq'] = use_seq
                self.monitored[c_id]['fake_len'] = len(payload)
        
        tcp_header_raw = struct.pack('!HHLLBBHHH', src_port, dst_port, use_seq, ack, offset, flags, window, 0, 0)
        psh = struct.pack('!4s4sBBH', socket.inet_aton(src_ip), socket.inet_aton(dst_ip), 0, socket.IPPROTO_TCP, len(tcp_header_raw) + len(payload))
        
        if bad_csum:
            tcp_header_final = struct.pack('!HHLLBBH', src_port, dst_port, use_seq, ack, offset, flags, window) + struct.pack('!H', 0xBAD0) + struct.pack('!H', 0)
        else:
            tcp_check = helpers.tcp_checksum(psh + tcp_header_raw + payload)
            tcp_header_final = struct.pack('!HHLLBBH', src_port, dst_port, use_seq, ack, offset, flags, window) + struct.pack('!H', tcp_check) + struct.pack('!H', 0)
            
        try: 
            self.send_sock.sendto(tcp_header_final + payload, (dst_ip, dst_port))
        except Exception: 
            pass
        finally:
            if strategy == "ttl":
                try: self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 64)
                except: pass

# Global singleton instance used by the proxy core
dpi_injector = LinuxDpiEngine()
