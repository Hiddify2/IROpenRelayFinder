import asyncio
import socket
import struct
import time
import sys
import ipaddress
import random

# Updated imports to prevent namespace collision with global 'utils' libraries
import utils.config as config
import utils.helpers as helpers
import utils.workers as workers
from utils.app_service import APP_SERVICE
from utils.runtime_state import STATE
from utils.route_service import ROUTE_SERVICE

# ==========================================
# DPI LOGGING TOGGLE
# ==========================================
PROXY_START_TIME = 0.0
_LOG_DPI_ALWAYS = False  # Cached after _run_proxy starts; avoids getattr on every log call

def log_dpi(message):
    """
    Prints DPI & V2Ray logs only if within the first 10 seconds of proxy startup,
    or if ALWAYS_SHOW_DPI_LOGS is manually enabled in the config.
    This prevents severe CPU bottlenecking from massive stdout spam.
    """
    if _LOG_DPI_ALWAYS or (time.time() - PROXY_START_TIME < 10.0):
        print(message)


def _set_active_proxy_connections(delta):
    """Best-effort global active-connection counter for background worker throttling."""
    try:
        STATE.add_active_proxy_connections(delta)
    except Exception:
        pass


async def _cancel_and_await(tasks):
    pending = [t for t in tasks if t and not t.done()]
    for task in pending:
        task.cancel()
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)

# ==========================================
# RELAY & DPI DESYNC INJECTION
# ==========================================
async def relay(reader, writer, is_client_to_remote=False, first_byte=b'', track_dpi=False, fragment_payload=False, sni_split_offset=-1, route_host=None, route_endpoint=None):
    start_time = time.time()
    bytes_transferred = 0
    first_byte_time = None
    first_packet = True
    _loop_counter = 0  # FIX: Event loop starvation prevention counter
    pending_bytes = 0

    # Read size optimized for throughput
    read_size = 65536

    # Throughput watchdog only runs on the remote→client (download) leg of a
    # white-routed connection. DPI traffic deliberately uses a different
    # endpoint and is scored elsewhere.
    watchdog_active = (not is_client_to_remote) and route_host is not None and route_endpoint is not None
    slow_threshold = float(getattr(config, 'RELAY_SLOW_TTFB_SEC', 5.0))

    try:
        # Send intercepted first_byte (ClientHello) immediately before blocking on read()
        if first_byte:
            bytes_transferred += len(first_byte)
            if is_client_to_remote and fragment_payload and config.DPI_FRAGMENTATION and len(first_byte) > 10:
                # Dynamic SNI Splitting: Split inside the SNI string to defeat DPI heuristics
                split = sni_split_offset if sni_split_offset > 5 else (len(first_byte) // 2)
                writer.write(first_byte[:split])
                await writer.drain()
                await asyncio.sleep(0.01) # 10ms delay to prevent DPI packet gluing
                writer.write(first_byte[split:])
            else:
                writer.write(first_byte)
            await writer.drain()
            first_packet = False

        while True:
            data = await reader.read(read_size)
            if not data:
                if pending_bytes > 0:
                    await writer.drain()
                    pending_bytes = 0
                if writer.can_write_eof():
                    writer.write_eof()
                break
            if first_byte_time is None:
                first_byte_time = time.time() - start_time
            bytes_transferred += len(data)

            if first_packet and is_client_to_remote and fragment_payload and config.DPI_FRAGMENTATION and len(data) > 10:
                split = sni_split_offset if sni_split_offset > 5 else (len(data) // 2)
                writer.write(data[:split])
                await writer.drain()
                await asyncio.sleep(0.01) # 10ms delay to prevent DPI packet gluing
                writer.write(data[split:])
            else:
                # FAST UPLOAD/DOWNLOAD PATH
                # No manual chunking/pacing overhead. Let the kernel manage the TCP window.
                writer.write(data)
                pending_bytes += len(data)

            first_packet = False

            _loop_counter += 1

            # Adaptive drain: preserve throughput while preventing large burst backlogs.
            if pending_bytes >= 262144 or (_loop_counter % 4 == 0):
                await writer.drain()
                pending_bytes = 0

            # BUG FIX: Prevent Event Loop Starvation
            # If reader and writer buffers are optimally filled, the async fast-paths
            # will return instantly, turning this into a blocking synchronous loop.
            # Yielding every 8 iterations guarantees other concurrent connections and
            # background health checks get their fair share of CPU time.
            if _loop_counter % 8 == 0:
                await asyncio.sleep(0)

    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
        pass
    except Exception:
        pass
    finally:
        # Auto-Tune DPI strategies if connection drops instantly
        if track_dpi and not is_client_to_remote and bytes_transferred == 0 and (time.time() - start_time) < 5.0:
            rotated = APP_SERVICE.record_dpi_failure_and_maybe_rotate()
            if rotated:
                old_strat, new_strat = rotated
                print(f"\n[🔄 AUTO-TUNE] DPI blocked strategy '{old_strat.upper()}'. Dynamically switching to '{new_strat.upper()}'!")
        elif track_dpi and not is_client_to_remote and bytes_transferred > 0:
            APP_SERVICE.clear_dpi_failures()

        # Watchdog: demote routes that connect but stall, deliver no bytes,
        # or take far too long for the first response. The next request for
        # this hostname will re-race instead of hitting the same dead/slow IP.
        if watchdog_active:
            elapsed = time.time() - start_time
            try:
                if bytes_transferred == 0 and elapsed >= 1.0:
                    ROUTE_SERVICE.mark_route_slow(route_host, route_endpoint[1], route_endpoint)
                elif first_byte_time is not None and first_byte_time > slow_threshold:
                    ROUTE_SERVICE.mark_route_slow(route_host, route_endpoint[1], route_endpoint)
            except Exception:
                pass

        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

async def _run_relay_pair(t1, t2):
    """
    Graceful teardown helper.
    If one side closes cleanly (common for HTTP request bodies), let the opposite
    direction continue until it naturally finishes to avoid truncating downloads.
    """
    all_tasks = [t1, t2]
    try:
        done, pending = await asyncio.wait(all_tasks, return_when=asyncio.FIRST_COMPLETED)
        first_completed = next(iter(done))

        if first_completed.cancelled():
            await _cancel_and_await(list(pending))
            return

        first_exc = first_completed.exception()
        if first_exc is not None:
            await _cancel_and_await(list(pending))
            raise first_exc

        if pending:
            try:
                await asyncio.gather(*pending)
            except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, OSError):
                pass
            except Exception:
                pass
    except asyncio.CancelledError:
        await _cancel_and_await(all_tasks)
        raise
    finally:
        await _cancel_and_await(all_tasks)

async def _resolve_and_connect(target_host, target_port, client_writer, use_dpi=False):
    """
    Resolves the route and opens the upstream connection. For white-routed
    (non-DPI) traffic, on a connect-time failure the chosen IP is marked
    dead, the cache is invalidated, and the resolution is retried with the
    failed IP forbidden, up to ``ROUTE_CONNECT_RETRIES`` extra attempts.

    Returns ``(remote_reader, remote_writer, actual_ip, actual_port)`` on
    success or ``(None, None, None, None)`` if every attempt fails.
    """
    attempts = max(1, int(getattr(config, 'ROUTE_CONNECT_RETRIES', 1)) + 1)
    forbidden = set()

    for attempt in range(attempts):
        if use_dpi:
            raw_route = config.DPI_IP if config.DPI_IP else await ROUTE_SERVICE.resolve_target(config.DPI_SNI, target_port)
        else:
            raw_route = await ROUTE_SERVICE.get_routed_ip(
                target_host,
                target_port,
                forbidden_eps=(forbidden if forbidden else None),
            )

        actual_ip, actual_port = _normalize_route(raw_route, target_port)
        if not actual_ip:
            return None, None, None, None

        remote_reader, remote_writer = await _dpi_connect_and_tune(
            actual_ip, actual_port, client_writer, use_dpi=use_dpi
        )
        if remote_reader is not None:
            return remote_reader, remote_writer, actual_ip, actual_port

        if use_dpi:
            # DPI uses a configured/derived IP — retrying won't change it.
            return None, None, None, None

        # Connect failed for a white-routed IP. Demote it, exclude it from
        # the next resolve, and try again.
        ROUTE_SERVICE.mark_route_dead(target_host, target_port, (actual_ip, actual_port))
        forbidden.add((actual_ip, actual_port))
        if attempt + 1 < attempts:
            print(f"[↻ REROUTE] {target_host}:{target_port} via {actual_ip}:{actual_port} failed. Re-racing without it...")

    return None, None, None, None


def _normalize_route(route_result, default_port):
    """Safely extracts IP and Port tuples from varying Route Service return types."""
    if not route_result:
        return None, default_port
    if isinstance(route_result, tuple) and len(route_result) >= 2:
        return str(route_result[0]), int(route_result[1])
    elif isinstance(route_result, dict):
        return str(route_result.get('ip', '')), int(route_result.get('port', default_port))
    elif isinstance(route_result, str):
        parsed = helpers.parse_ip_port(route_result)
        if parsed:
            return parsed[0], parsed[1]
        return route_result, default_port
    return str(route_result), default_port

async def _dpi_connect_and_tune(actual_ip, target_port, client_writer, use_dpi=False):
    """Establishes connection to the target/proxy IP and optionally intercepts for DPI injection."""
    if not actual_ip:
        return None, None
        
    # --- PATH 1: NATIVE CONNECTION (NON-DPI) ---
    # Bypass manual DNS resolution and manual sockets for standard traffic.
    if not use_dpi:
        try:
            connect_timeout = float(getattr(config, 'PROXY_CONNECT_TIMEOUT', 4.0))
            remote_reader, remote_writer = await asyncio.wait_for(
                asyncio.open_connection(host=actual_ip, port=target_port),
                timeout=connect_timeout
            )
            # Increase stream buffers for high-throughput capability over high-latency links
            remote_writer.transport.set_write_buffer_limits(high=262144, low=32768)
            client_writer.transport.set_write_buffer_limits(high=524288, low=65536)
            helpers.tune_socket(client_writer.get_extra_info('socket'))
            helpers.tune_socket(remote_writer.get_extra_info('socket'))
            return remote_reader, remote_writer
        except Exception:
            return None, None

    # --- PATH 2: RAW DPI ENGINE CONNECTION ---
    # DPI strictly requires numerical IPs to build raw headers
    try:
        ip_obj = ipaddress.ip_address(actual_ip)
    except ValueError:
        try:
            actual_ip_resolved = await ROUTE_SERVICE.resolve_target(actual_ip, target_port)
            if actual_ip_resolved == actual_ip:
                return None, None
            actual_ip = actual_ip_resolved
            ip_obj = ipaddress.ip_address(actual_ip)
        except Exception:
            return None, None

    # Force correct family based on IP version to prevent IPv6 crash on AF_INET binding
    family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.setblocking(False)
    bind_ip = '::' if family == socket.AF_INET6 else ''
    sock.bind((bind_ip, 0))
    local_ip, local_port = sock.getsockname()[:2] # slice robustly for IPv6 tuples
    
    connect_task = None
    try:
        loop = asyncio.get_running_loop()
        from cores.desync_core import dpi_injector, generate_fake_client_hello
        
        if dpi_injector.running:
            # Dynamically pull an SNI from the rotation pool
            active_sni = config.get_active_dpi_sni()
            log_dpi(f"[DPI] Intercepting connection to {actual_ip}:{target_port} (Spoofing: {active_sni})")
            event, t2a_event = dpi_injector.monitor_connection(local_port, actual_ip, target_port)
            
            # Safe wrapper to silently swallow any low-level socket or cancellation exceptions
            async def safe_connect():
                try: await loop.sock_connect(sock, (actual_ip, target_port))
                except Exception: pass
                
            connect_task = asyncio.create_task(safe_connect())
            
            try:
                # Calculate dynamic RTT for adaptive DPI timeouts
                connect_start = time.monotonic()
                await asyncio.wait_for(event.wait(), timeout=0.5)
                rtt_estimate = time.monotonic() - connect_start
                
                seq, ack, real_src_ip = dpi_injector.get_seq_ack_ip(local_port, actual_ip, target_port)
                
                if seq is not None and real_src_ip is not None:
                    if config.ACTIVE_DPI_STRATEGY == "classic":
                        try:
                            # Classic just relies on fragmentation chunking, adapt wait to RTT
                            t2a_timeout = max(0.1, min(rtt_estimate * 2.0, 0.5))
                            await asyncio.wait_for(t2a_event.wait(), timeout=t2a_timeout) 
                        except asyncio.TimeoutError:
                            pass
                        log_dpi(f"[DPI] [+] Segment Only selected (Strategy: CLASSIC / No Fake Packet injected)")
                    else:
                        fake_payload = generate_fake_client_hello(active_sni)
                        dpi_injector.inject_fake_packet(real_src_ip, actual_ip, local_port, target_port, seq, ack, fake_payload, strategy=config.ACTIVE_DPI_STRATEGY)
                        
                        if config.ACTIVE_DPI_STRATEGY in ["ttl", "bad_csum"]:
                            # Timing Jitter: Prevents mechanical timing signatures on dropped packets
                            await asyncio.sleep(0.015 + random.uniform(0, 0.010)) 
                            log_dpi(f"[DPI] [+] Fake ClientHello Injected (Strategy: {config.ACTIVE_DPI_STRATEGY.upper()} / Proceeding immediately)")
                        else:
                            try:
                                # Adaptive timeout: Wait for remote ACK based on connection latency
                                t2a_timeout = max(0.15, min(rtt_estimate * 2.5, 0.8))
                                await asyncio.wait_for(t2a_event.wait(), timeout=t2a_timeout)
                                log_dpi(f"[DPI] [+] Fake ClientHello Injected (Strategy: {config.ACTIVE_DPI_STRATEGY.upper()} / Dup-ACK caught)")
                            except asyncio.TimeoutError:
                                log_dpi(f"[DPI] [+] Fake ClientHello Injected (Strategy: {config.ACTIVE_DPI_STRATEGY.upper()} / No ACK)")
            except asyncio.TimeoutError:
                log_dpi(f"[DPI] [-] Handshake sniff timed out. Connection dropped.")
                if not connect_task.done():
                    connect_task.cancel()
                    await asyncio.gather(connect_task, return_exceptions=True)
                sock.close()
                with dpi_injector.lock:
                    dpi_injector.monitored.pop((local_port, actual_ip, target_port), None)
                return None, None
                
            await connect_task
            with dpi_injector.lock: 
                dpi_injector.monitored.pop((local_port, actual_ip, target_port), None)
        else:
            # Fallback if injector failed to start
            await asyncio.wait_for(loop.sock_connect(sock, (actual_ip, target_port)), timeout=8.0)
            
        remote_reader, remote_writer = await asyncio.open_connection(sock=sock)
        # Increase stream buffers for high-throughput capability over high-latency links
        remote_writer.transport.set_write_buffer_limits(high=262144, low=32768)
        client_writer.transport.set_write_buffer_limits(high=524288, low=65536)
        helpers.tune_socket(client_writer.get_extra_info('socket'))
        helpers.tune_socket(remote_writer.get_extra_info('socket'))
        return remote_reader, remote_writer
        
    except Exception:
        if connect_task and not connect_task.done():
            connect_task.cancel()
            await asyncio.gather(connect_task, return_exceptions=True)
        sock.close()
        try:
            with dpi_injector.lock:
                dpi_injector.monitored.pop((local_port, actual_ip, target_port), None)
        except Exception:
            pass
        return None, None

# ==========================================
# PROTOCOL HANDLERS
# ==========================================
async def parse_tls_sni(first_byte, reader):
    """Dynamically extracts the SNI and returns: (sni, buf, sni_start_offset_in_buf)"""
    try:
        buf = first_byte
        chunk = await asyncio.wait_for(reader.read(8192), timeout=0.5)
        buf += chunk
        
        if len(buf) < 43: return None, buf, -1
        session_id_len = buf[43]
        offset = 44 + session_id_len
        if offset + 2 > len(buf): return None, buf, -1
        cipher_suites_len = struct.unpack('!H', buf[offset:offset+2])[0]
        offset += 2 + cipher_suites_len
        if offset + 1 > len(buf): return None, buf, -1
        comp_methods_len = buf[offset]
        offset += 1 + comp_methods_len
        if offset + 2 > len(buf): return None, buf, -1
        ext_len = struct.unpack('!H', buf[offset:offset+2])[0]
        offset += 2
        end = min(offset + ext_len, len(buf))
        
        while offset + 4 <= end:
            ext_type = struct.unpack('!H', buf[offset:offset+2])[0]
            ext_size = struct.unpack('!H', buf[offset+2:offset+4])[0]
            offset += 4
            if ext_type == 0: # SNI Extension
                sni_len = struct.unpack('!H', buf[offset+3:offset+5])[0]
                sni_start = offset + 5 # byte offset of the SNI string in buf
                sni = buf[sni_start:sni_start+sni_len].decode('utf-8', errors='ignore')
                return sni, buf, sni_start
            offset += ext_size
    except Exception:
        pass
    return None, buf, -1

async def handle_transparent(first_byte, client_reader, client_writer):
    """Handles standard transparent TLS connections (e.g. from V2Ray/Xray routing)."""
    try:
        # Infer destination port from the local socket the client connected to
        sockname = client_writer.get_extra_info('sockname')
        target_port = int(sockname[1]) if sockname and len(sockname) > 1 else 443
        
        sni, initial_data, sni_offset = await parse_tls_sni(first_byte, client_reader)
        target_host = sni if sni else config.DPI_SNI
        
        is_dpi = config.CONNECTION_MODE in ['dpi_desync', 'mixed']

        remote_reader, remote_writer, actual_ip, actual_port = await _resolve_and_connect(
            target_host, target_port, client_writer, use_dpi=is_dpi
        )

        if is_dpi and actual_ip:
            log_dpi(f"[🔥 ROUTE] Transparent TLS -> {helpers.format_ip_port(actual_ip, actual_port)} (Mode: {config.CONNECTION_MODE}, SNI: {target_host})")

        if not remote_reader:
            client_writer.close()
            return

        download_endpoint = (actual_ip, actual_port) if not is_dpi else None
        t1 = asyncio.create_task(relay(client_reader, remote_writer, is_client_to_remote=True, first_byte=initial_data, track_dpi=False, fragment_payload=is_dpi, sni_split_offset=sni_offset))
        t2 = asyncio.create_task(relay(remote_reader, client_writer, is_client_to_remote=False, track_dpi=is_dpi, fragment_payload=False, route_host=target_host, route_endpoint=download_endpoint))
        await _run_relay_pair(t1, t2)
    except Exception:
        client_writer.close()

async def handle_socks5(client_reader, client_writer):
    """Handles SOCKS5 Proxy Handshakes."""
    try:
        nmethods_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=10.0)
        nmethods = nmethods_byte[0]
        await client_reader.readexactly(nmethods)
        client_writer.write(b"\x05\x00") 
        await client_writer.drain()

        version, cmd, _, address_type = struct.unpack("!BBBB", await client_reader.readexactly(4))
        if version != 5 or cmd != 1: 
            client_writer.close()
            return

        if address_type == 1: 
            target_host = socket.inet_ntoa(await client_reader.readexactly(4))
        elif address_type == 3: 
            domain_len = (await client_reader.readexactly(1))[0]
            target_host = (await client_reader.readexactly(domain_len)).decode()
        elif address_type == 4:
            target_host = socket.inet_ntop(socket.AF_INET6, await client_reader.readexactly(16))
        else: 
            client_writer.close()
            return

        target_port = struct.unpack("!H", await client_reader.readexactly(2))[0]
        await asyncio.sleep(0)
        
        is_dpi = (config.CONNECTION_MODE == 'dpi_desync' and config.is_tls_port(target_port))

        remote_reader, remote_writer, actual_ip, actual_port = await _resolve_and_connect(
            target_host, target_port, client_writer, use_dpi=is_dpi
        )

        if is_dpi and actual_ip:
            log_dpi(f"[🔥 ROUTE] {target_host}:{target_port} -> {helpers.format_ip_port(actual_ip, actual_port)} (Mode: {config.CONNECTION_MODE})")

        if not remote_reader:
            client_writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            client_writer.close()
            return

        client_writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00" + struct.pack("!H", target_port))
        await client_writer.drain()

        download_endpoint = (actual_ip, actual_port) if not is_dpi else None
        t1 = asyncio.create_task(relay(client_reader, remote_writer, is_client_to_remote=True, track_dpi=False, fragment_payload=is_dpi))
        t2 = asyncio.create_task(relay(remote_reader, client_writer, is_client_to_remote=False, track_dpi=is_dpi, fragment_payload=False, route_host=target_host, route_endpoint=download_endpoint))
        await _run_relay_pair(t1, t2)
    except Exception:
        client_writer.close()

async def handle_http(first_byte, client_reader, client_writer):
    """Handles standard HTTP and HTTPS (CONNECT) proxy requests."""
    try:
        headers_data = first_byte
        while b'\r\n\r\n' not in headers_data:
            chunk = await asyncio.wait_for(client_reader.read(4096), timeout=5.0)
            if not chunk: break
            headers_data += chunk

        headers_text = headers_data.decode('utf-8', errors='ignore')
        lines = headers_text.split('\r\n')
        request_line = lines[0].split()

        if len(request_line) < 2: 
            client_writer.close()
            return

        method = request_line[0]
        url = request_line[1]
        target_port = 80
        target_host = ""

        if method == 'CONNECT':
            if ']:' in url:
                target_host, port_str = url.rsplit(':', 1)
                target_host = target_host.strip('[]')
                target_port = int(port_str)
            elif ':' in url and not url.startswith('['):
                target_host, port_str = url.rsplit(':', 1)
                target_port = int(port_str)
            else:
                target_host = url.strip('[]')
                target_port = 443
        else:
            for line in lines[1:]:
                if line.lower().startswith('host:'):
                    host_header = line.split(':', 1)[1].strip()
                    if ']:' in host_header:
                        target_host, port_str = host_header.rsplit(':', 1)
                        target_host = target_host.strip('[]')
                        target_port = int(port_str)
                    elif ':' in host_header and not host_header.startswith('['):
                        target_host, port_str = host_header.rsplit(':', 1)
                        target_port = int(port_str)
                    else: 
                        target_host = host_header.strip('[]')
                    break

        if not target_host: 
            client_writer.close()
            return
            
        await asyncio.sleep(0)
        is_dpi = (config.CONNECTION_MODE == 'dpi_desync' and config.is_tls_port(target_port))

        remote_reader, remote_writer, actual_ip, actual_port = await _resolve_and_connect(
            target_host, target_port, client_writer, use_dpi=is_dpi
        )

        if is_dpi and actual_ip:
            log_dpi(f"[🔥 ROUTE] {target_host}:{target_port} -> {helpers.format_ip_port(actual_ip, actual_port)} (Mode: {config.CONNECTION_MODE})")

        if not remote_reader:
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            return

        if method == 'CONNECT':
            client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await client_writer.drain()
        else:
            if url.startswith('http://') or url.startswith('https://'):
                try:
                    scheme_end = url.index('//') + 2
                    path_start = url.find('/', scheme_end)
                    relative = url[path_start:] if path_start != -1 else '/'
                    rewritten_line = f"{method} {relative} {request_line[2]}\r\n".encode()
                    eol = headers_data.find(b'\r\n')
                    headers_data = rewritten_line + headers_data[eol + 2:]
                except Exception:
                    pass
            remote_writer.write(headers_data)
            await remote_writer.drain()

        download_endpoint = (actual_ip, actual_port) if not is_dpi else None
        t1 = asyncio.create_task(relay(client_reader, remote_writer, is_client_to_remote=True, track_dpi=False, fragment_payload=is_dpi))
        t2 = asyncio.create_task(relay(remote_reader, client_writer, is_client_to_remote=False, track_dpi=is_dpi, fragment_payload=False, route_host=target_host, route_endpoint=download_endpoint))
        await _run_relay_pair(t1, t2)
    except Exception:
        client_writer.close()

async def handle_client(client_reader, client_writer):
    """Protocol Sniffer: Identifies SOCKS5 vs HTTP vs Transparent TLS based on the first byte."""
    _set_active_proxy_connections(1)
    try:
        first_byte = await asyncio.wait_for(client_reader.readexactly(1), timeout=30.0)
        
        peer = client_writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else '?'
        
        if first_byte == b'\x05':
            msg = f"[PROTO] {peer_ip} connected via SOCKS5"
            if config.CONNECTION_MODE == 'dpi_desync': log_dpi(msg)
            else: print(msg)
            await handle_socks5(client_reader, client_writer)
        elif first_byte == b'\x16':
            msg = f"[PROTO] {peer_ip} connected via Transparent TLS (V2Ray/Xray)"
            if config.CONNECTION_MODE in ['dpi_desync', 'mixed']: log_dpi(msg)
            else: print(msg)
            await handle_transparent(first_byte, client_reader, client_writer)
        else:
            msg = f"[PROTO] {peer_ip} connected via HTTP"
            if config.CONNECTION_MODE == 'dpi_desync': log_dpi(msg)
            else: print(msg)
            await handle_http(first_byte, client_reader, client_writer)
    except Exception:
        client_writer.close()
    finally:
        _set_active_proxy_connections(-1)

# ==========================================
# PROXY ENTRY POINT
# ==========================================
async def run():
    """Main execution point for the IROpenRelayFinder server engine."""
    try:
        await _run_proxy()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"\n[-] FATAL CRASH in proxy engine: {e}")
        input("Press Enter to return to main menu...")

async def _run_proxy():
    config.load_config()
    
    # Establish proxy start time to hide DPI logs after 10 seconds
    global PROXY_START_TIME, _LOG_DPI_ALWAYS
    PROXY_START_TIME = time.time()
    _LOG_DPI_ALWAYS = getattr(config, 'ALWAYS_SHOW_DPI_LOGS', False)  # Cache once after config loads
    
    # Ensure locks are bound to the running loop
    ROUTE_SERVICE.ensure_locks()

    if not STATE.ip_pool(): 
        ROUTE_SERVICE.load_ip_pool()
        
    ROUTE_SERVICE.load_routes()
    await ROUTE_SERVICE.purge_media_wildcard_routes()
    ROUTE_SERVICE.load_banned_routes()
    
    # Dual-stack binding: try IPv4+IPv6 first, fall back to IPv4-only if IPv6 is
    # unavailable or restricted (common on Windows and some Termux environments).
    try:
        server = await asyncio.start_server(handle_client, host=['0.0.0.0', '::'], port=config.PROXY_PORT)
    except OSError:
        print("[!] IPv6 binding failed — falling back to IPv4-only (0.0.0.0). This is normal on Windows/Termux.")
        server = await asyncio.start_server(handle_client, host='0.0.0.0', port=config.PROXY_PORT)
    
    helpers.clear_screen()
    local_ip = helpers.get_local_ip()
    print("=" * 50)
    print(f"[*] IROpenRelayFinder LISTENING ON {config.PROXY_HOST}:{config.PROXY_PORT}")
    print(f"[*] Connect your devices to: {local_ip}:{config.PROXY_PORT}")
    print("[*] Supporting MIXED mode: SOCKS5, HTTP/HTTPS, and V2Ray Transparent TLS")
    
    mode_display = "White IPs (Routing)"
    if config.CONNECTION_MODE == "dpi_desync": 
        mode_display = "DPI Desync Engine (Pure Python + Windows/Linux native)"
    elif config.CONNECTION_MODE == "mixed":
        mode_display = "Mixed (V2Ray=Desync, Web=White IPs)"
    
    print(f"[🔥] CONNECTION MODE: {mode_display}")
    if config.CONNECTION_MODE in ["dpi_desync", "mixed"]:
        print(f"    -> Spoofed SNI:  {config.DPI_SNI} (Pool Rotation Active)")
        print(f"    -> Routing IP:   {config.DPI_IP if config.DPI_IP else 'Auto-resolve'}")
        print(f"    -> Active Strat: {config.ACTIVE_DPI_STRATEGY.upper()} (Pool: {', '.join(config.DPI_STRATEGIES).upper()})")
        if not getattr(config, 'ALWAYS_SHOW_DPI_LOGS', False):
            print("[*] Note: DPI/Desync connection logs will auto-hide after 10 seconds to save CPU.")
            
    if config.CONNECTION_MODE in ["white_ip", "mixed"]:
        print(f"[DEBUG] IP Pool size at proxy start: {len(STATE.ip_pool())}")
        
    print("[*] Press Ctrl+C to stop the proxy and return to menu.")
    print("=" * 50 + "\n")
    
    # Initialize DPI desync injector if required
    if config.CONNECTION_MODE in ["dpi_desync", "mixed"]:
        from cores.desync_core import dpi_injector
        dpi_injector.start()
        if not dpi_injector.running:
            print("[!] DPI engine failed to start. Aborting proxy.")
            return
        
    prewarm_task = None
    passive_task = None
    health_task = None
    if config.CONNECTION_MODE in ["white_ip", "mixed"]:
        prewarm_task = asyncio.create_task(workers.prewarm_routes())
        passive_task = asyncio.create_task(workers.passive_scanner())
        health_task = asyncio.create_task(workers.health_checker())
    
    try:
        async with server:
            await server.serve_forever()
    finally:
        if config.CONNECTION_MODE in ["white_ip", "mixed"]:
            await _cancel_and_await([prewarm_task, passive_task, health_task])
            
        if config.CONNECTION_MODE in ["dpi_desync", "mixed"]:
            from cores.desync_core import dpi_injector
            if dpi_injector:
                dpi_injector.running = False
