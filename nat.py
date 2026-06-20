import socket
import struct
import threading
import logging
import time

log = logging.getLogger("NAT")

def _detect_real_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip.startswith("10.99.99."):
            return ""
        return ip
    except Exception:
        return ""

BIND_IP = ""

def _background_detect():
    global BIND_IP
    BIND_IP = _detect_real_ip()
    if BIND_IP:
        log.info(f"  NAT: bind na interface real: {BIND_IP}")
    else:
        pass

threading.Thread(target=_background_detect, daemon=True, name="NAT-detect").start()

def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def build_ip(src: str, dst: str, proto: int, payload: bytes, ip_id: int = 0) -> bytes:
    total = 20 + len(payload)
    hdr = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, total, ip_id, 0x4000,
        64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst)
    )
    ck = _checksum(hdr)
    return hdr[:10] + struct.pack('!H', ck) + hdr[12:] + payload

def build_tcp(src_ip: str, dst_ip: str,
              src_port: int, dst_port: int,
              seq: int, ack: int,
              flags: int, window: int,
              payload: bytes = b'') -> bytes:
    hdr = struct.pack('!HHIIBBHHH',
        src_port, dst_port,
        seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
        0x50,   # data offset = 5 (20 bytes)
        flags,
        window,
        0, 0    # checksum, urgent
    )
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 6, len(hdr) + len(payload)
    )
    ck = _checksum(pseudo + hdr + payload)
    hdr = hdr[:16] + struct.pack('!H', ck) + hdr[18:]
    return hdr + payload

def build_udp(src_ip: str, dst_ip: str,
              src_port: int, dst_port: int,
              payload: bytes) -> bytes:
    length = 8 + len(payload)
    hdr = struct.pack('!HHHH', src_port, dst_port, length, 0)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, 17, length
    )
    ck = _checksum(pseudo + hdr + payload)
    return struct.pack('!HHHH', src_port, dst_port, length, ck) + payload

F_FIN = 0x01
F_SYN = 0x02
F_RST = 0x04
F_PSH = 0x08
F_ACK = 0x10

class TCPConnection:

    WINDOW = 65535

    def __init__(self, engine, client_ip, client_port, server_ip, server_port):
        self.engine      = engine
        self.client_ip   = client_ip
        self.client_port = client_port
        self.server_ip   = server_ip
        self.server_port = server_port

        self.state       = "CLOSED"
        self.client_seq  = 0   
        self.our_seq     = 0x61626364  

        self.sock        = None
        self._lock       = threading.Lock()

    def on_packet(self, tcp_data: bytes):
        if len(tcp_data) < 20:
            return

        flags      = tcp_data[13]
        seq        = struct.unpack('!I', tcp_data[4:8])[0]
        data_off   = (tcp_data[12] >> 4) * 4
        payload    = tcp_data[data_off:]

        if flags & F_RST:
            self._close()
            return

        if flags & F_SYN and not (flags & F_ACK):
            self._handle_syn(seq, payload)
        elif self.state == "ESTABLISHED":
            if payload:
                self._forward_to_server(seq, payload)
            if flags & F_FIN:
                self._handle_fin_from_client(seq)

    def _handle_syn(self, client_isn, payload):
        self.client_seq = (client_isn + 1) & 0xFFFFFFFF

        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if BIND_IP:
                self.sock.bind((BIND_IP, 0))
            self.sock.settimeout(10)
            self.sock.connect((self.server_ip, self.server_port))
            self.sock.settimeout(None)
        except Exception as e:
            self._send_tcp(F_RST, b'')
            self.state = "CLOSED"
            return

        self.state = "ESTABLISHED"
        log.info(f"  NAT TCP: {self.client_ip}:{self.client_port} → {self.server_ip}:{self.server_port} ABERTO")

        self._send_tcp(F_SYN | F_ACK, b'')
        self.our_seq = (self.our_seq + 1) & 0xFFFFFFFF

        # Thread que le respostas do servidor real e manda pro cliente
        t = threading.Thread(target=self._relay_server_to_client, daemon=True)
        t.start()

    def _forward_to_server(self, seq, payload):
        try:
            self.sock.sendall(payload)
            self.client_seq = (seq + len(payload)) & 0xFFFFFFFF
            self._send_tcp(F_ACK, b'')
        except Exception as e:
            self._close()

    def _handle_fin_from_client(self, seq):
        self.client_seq = (seq + 1) & 0xFFFFFFFF
        self._send_tcp(F_ACK, b'')
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _relay_server_to_client(self):
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                with self._lock:
                    self._send_tcp(F_PSH | F_ACK, chunk)
                    self.our_seq = (self.our_seq + len(chunk)) & 0xFFFFFFFF
        except Exception as e:
            if self.state == "ESTABLISHED":
                log.debug(f"  NAT TCP relay: {e}")
        finally:
            if self.state == "ESTABLISHED":
                self._send_tcp(F_FIN | F_ACK, b'')
                self.our_seq = (self.our_seq + 1) & 0xFFFFFFFF
            self.state = "CLOSED"
            log.info(f"  NAT TCP: {self.client_ip}:{self.client_port} → {self.server_ip}:{self.server_port} FECHADO")
            self._close()

    def _send_tcp(self, flags, payload):
        tcp = build_tcp(
            self.server_ip if False else "10.99.99.1",  # src = nosso IP PPP
            self.client_ip,
            self.server_port,
            self.client_port,
            self.our_seq,
            self.client_seq,
            flags,
            self.WINDOW,
            payload
        )
        ip_pkt = build_ip("10.99.99.1", self.client_ip, 6, tcp)
        self.engine.send_ip(ip_pkt)

    def _close(self):
        self.state = "CLOSED"
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        key = (self.client_ip, self.client_port, self.server_ip, self.server_port)
        self.engine.connections.pop(key, None)

class NATEngine:

    def __init__(self, send_ip_callback):
        self.send_ip     = send_ip_callback
        self.connections = {}   # (client_ip, client_port, dst_ip, dst_port) → TCPConnection
        self._lock       = threading.Lock()

    def handle_ip(self, data: bytes):
        if len(data) < 20:
            return

        proto  = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        ihl    = (data[0] & 0x0F) * 4
        payload = data[ihl:]

        if proto == 6:   
            self._handle_tcp(src_ip, dst_ip, payload)
        elif proto == 17:
            self._handle_udp(src_ip, dst_ip, payload)
      
    def _handle_tcp(self, src_ip, dst_ip, tcp_data):
        if len(tcp_data) < 20:
            return

        src_port = struct.unpack('!H', tcp_data[0:2])[0]
        dst_port = struct.unpack('!H', tcp_data[2:4])[0]
        flags    = tcp_data[13]

        key = (src_ip, src_port, dst_ip, dst_port)

        with self._lock:
            if flags & F_SYN and not (flags & F_ACK):
                if key in self.connections:
                    self.connections[key]._close()
                conn = TCPConnection(self, src_ip, src_port, dst_ip, dst_port)
                self.connections[key] = conn
                log.debug(f"  NAT: nova conexao TCP {src_ip}:{src_port} → {dst_ip}:{dst_port}")

            conn = self.connections.get(key)

        if conn:
            conn.on_packet(tcp_data)
        else:
  
            log.debug(f"  NAT: TCP sem conexao {src_ip}:{src_port} → {dst_ip}:{dst_port}, mandando RST")
            seq = struct.unpack('!I', tcp_data[4:8])[0]
            ack_seq = (seq + 1) & 0xFFFFFFFF
            rst = build_tcp("10.99.99.1", src_ip, dst_port, src_port,
                            0, ack_seq, F_RST | F_ACK, 0)
            self.send_ip(build_ip("10.99.99.1", src_ip, 6, rst))

    def _handle_udp(self, src_ip, dst_ip, udp_data):
        if len(udp_data) < 8:
            return

        src_port = struct.unpack('!H', udp_data[0:2])[0]
        dst_port = struct.unpack('!H', udp_data[2:4])[0]
        payload  = udp_data[8:]

        log.debug(f"  NAT UDP: {src_ip}:{src_port} → {dst_ip}:{dst_port} ({len(payload)}b)")

        t = threading.Thread(
            target=self._udp_proxy,
            args=(src_ip, src_port, dst_ip, dst_port, payload),
            daemon=True
        )
        t.start()

    def _udp_proxy(self, src_ip, src_port, dst_ip, dst_port, payload):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if BIND_IP:
                sock.bind((BIND_IP, 0))
            sock.settimeout(5)
            sock.sendto(payload, (dst_ip, dst_port))
            resp, _ = sock.recvfrom(4096)
            sock.close()

            udp_resp = build_udp(dst_ip, src_ip, dst_port, src_port, resp)
            ip_resp  = build_ip(dst_ip, src_ip, 17, udp_resp)
            self.send_ip(ip_resp)

            if dst_port == 53:
                log.debug(f"  NAT DNS: resposta {len(resp)}b de {dst_ip}")

        except socket.timeout:
            pass
        except Exception as e:
            pass
