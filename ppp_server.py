import struct
import threading
import time
import logging
import socket
import os
import sys
import hashlib
import hmac
import ipaddress
import configparser
from datetime import datetime, timedelta
from nat import NATEngine

log = logging.getLogger("PPP")

_cfg = configparser.ConfigParser()
_cfg.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"), encoding="utf-8")

SERVER_IP         = _cfg.get("rede",      "servidor_ip",       fallback="10.99.99.1")
CLIENT_IP         = _cfg.get("rede",      "cliente_ip",        fallback="10.99.99.2")
DNS_IP            = _cfg.get("rede",      "dns",               fallback="8.8.8.8")
MAX_TENTATIVAS    = _cfg.getint("seguranca", "max_tentativas",    fallback=3)
BLOQUEIO_SEGUNDOS = _cfg.getint("seguranca", "bloqueio_segundos", fallback=60)
TIMEOUT_SESSAO    = _cfg.getint("seguranca", "timeout_sessao",    fallback=3600)
MAX_SESSOES       = _cfg.getint("seguranca", "max_sessoes",       fallback=1)

USUARIOS_HASH = {
    usuario: hashlib.sha256(senha.encode()).hexdigest()
    for usuario, senha in _cfg.items("usuarios")
} if _cfg.has_section("usuarios") else {}

_tentativas   = {}   # {ip_ou_porta: (contador, ultimo_erro)}
_sessoes_ativas = 0

def _senha_ok(usuario: str, senha: str) -> bool:
    if usuario not in USUARIOS_HASH:
        # Faz comparacao dummy para nao vazar tempo
        hmac.compare_digest("x", "y")
        return False
    h = hashlib.sha256(senha.encode()).hexdigest()
    return hmac.compare_digest(USUARIOS_HASH[usuario], h)

def _verificar_bloqueio(chave: str) -> tuple:
    if chave not in _tentativas:
        return False, 0
    count, ultimo = _tentativas[chave]
    if count >= MAX_TENTATIVAS:
        restante = BLOQUEIO_SEGUNDOS - (time.time() - ultimo)
        if restante > 0:
            return True, int(restante)
        else:
            del _tentativas[chave]
            return False, 0
    return False, 0

def _registrar_falha(chave: str):
    count = _tentativas.get(chave, (0, 0))[0]
    _tentativas[chave] = (count + 1, time.time())
    if count + 1 >= MAX_TENTATIVAS:
        pass

def _registrar_sucesso(chave: str):
    if chave in _tentativas:
        del _tentativas[chave]

HDLC_FLAG    = 0x7E
HDLC_ESCAPE  = 0x7D
HDLC_XOR     = 0x20
HDLC_ADDR    = 0xFF
HDLC_CTRL    = 0x03

PROTO_LCP    = 0xC021
PROTO_PAP    = 0xC023
PROTO_IPCP   = 0x8021
PROTO_IP     = 0x0021

CODE_CONF_REQ  = 1
CODE_CONF_ACK  = 2
CODE_CONF_NAK  = 3
CODE_CONF_REJ  = 4
CODE_TERM_REQ  = 5
CODE_TERM_ACK  = 6
CODE_CODE_REJ  = 7
CODE_ECHO_REQ  = 9
CODE_ECHO_REP  = 10

PAP_AUTH_REQ   = 1
PAP_AUTH_ACK   = 2
PAP_AUTH_NAK   = 3

LCP_OPT_MRU      = 1
LCP_OPT_ACCM     = 2
LCP_OPT_AUTH     = 3
LCP_OPT_MAGIC    = 5
LCP_OPT_PFC      = 7    # Protocol-Field-Compression  (rejeitamos — simplifica parsing)
LCP_OPT_ACFC     = 8    # Addr-and-Ctrl-Field-Compression (rejeitamos)
LCP_OPT_CALLBACK = 13   # Callback — NUNCA aceitar (travaria o Windows esperando callback)

IPCP_OPT_ADDR      = 3
IPCP_OPT_DNS       = 129   # DNS primario  (0x81)
IPCP_OPT_NBNS      = 130   
IPCP_OPT_DNS2      = 131   # DNS secundario (0x83)
IPCP_OPT_NBNS2     = 132   # WINS/NBNS secundario (0x84)

class PPPState:
    DEAD        = "DEAD"
    LCP_REQ     = "LCP_REQ"
    LCP_ACK     = "LCP_ACK"
    AUTH        = "AUTH"
    IPCP_REQ    = "IPCP_REQ"
    CONNECTED   = "CONNECTED"
    CLOSING     = "CLOSING"

def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))

def bytes_to_ip(b: bytes) -> str:
    return ".".join(str(x) for x in b)

def calc_fcs(data: bytes) -> int:
    fcs = 0xFFFF
    for byte in data:
        fcs ^= byte
        for _ in range(8):
            if fcs & 1:
                fcs = (fcs >> 1) ^ 0x8408
            else:
                fcs >>= 1
    return fcs ^ 0xFFFF

def hdlc_encode(payload: bytes) -> bytes:
    raw = bytes([HDLC_ADDR, HDLC_CTRL]) + payload
    fcs = calc_fcs(raw)
    raw += struct.pack("<H", fcs)

    out = bytearray([HDLC_FLAG])
    for b in raw:
        if b in (HDLC_FLAG, HDLC_ESCAPE, 0x11, 0x13):
            out.append(HDLC_ESCAPE)
            out.append(b ^ HDLC_XOR)
        else:
            out.append(b)
    out.append(HDLC_FLAG)
    return bytes(out)

def hdlc_decode(frame: bytes):
    frame = frame.strip(bytes([HDLC_FLAG]))
    
    unescaped = bytearray()
    i = 0
    while i < len(frame):
        b = frame[i]
        if b == HDLC_ESCAPE:
            i += 1
            if i < len(frame):
                unescaped.append(frame[i] ^ HDLC_XOR)
        else:
            unescaped.append(b)
        i += 1

    if len(unescaped) < 4:
        return None

    data = bytes(unescaped[:-2])
    fcs_recv = struct.unpack("<H", unescaped[-2:])[0]
    if calc_fcs(data) != fcs_recv:
        log.debug("  HDLC: FCS invalido")
        return None

    if data[0] == HDLC_ADDR and data[1] == HDLC_CTRL:
        return data[2:]
    return data

class HDLCReceiver:
    def __init__(self):
        self._buf = bytearray()
        self._in_frame = False
        self._frames = []

    def feed(self, data: bytes):
        for b in data:
            if b == HDLC_FLAG:
                if self._in_frame and len(self._buf) > 4:
                    self._buf.append(HDLC_FLAG)
                    frame = hdlc_decode(bytes(self._buf))
                    if frame is not None:
                        self._frames.append(frame)
                    else:
                        log.debug(f"  HDLC: frame invalido descartado ({len(self._buf)}b)")
                self._buf = bytearray([HDLC_FLAG])
                self._in_frame = True
            elif self._in_frame:
                self._buf.append(b)
                # Proteção contra frame muito grande (lixo na linha)
                if len(self._buf) > 4096:
                    self._buf = bytearray()
                    self._in_frame = False

    def get_frames(self):
        frames = list(self._frames)
        self._frames.clear()
        return frames

class PPPServer:
    def __init__(self, serial_port):
        self.ser      = serial_port
        self.state    = PPPState.DEAD
        self.rx       = HDLCReceiver()
        self.running  = False

        self.lcp_id        = 1
        self.lcp_magic     = 0xDEADBEEF
        self.peer_magic    = 0
        self.mru           = 1500
        self.lcp_acked     = False
        self.lcp_peer_ack  = False

        self.auth_user = ""
        self.auth_ok   = False

        self.ipcp_id          = 1
        self.ipcp_acked       = False
        self.ipcp_peer_ack    = False
        self.ipcp_our_req_sent = False   # flag: ja enviamos nosso Conf-Req?
        self.client_ip        = CLIENT_IP
        self._ipcp_send_after = 0.0      # timestamp: quando enviar o 1o Conf-Req
        self._ipcp_first_sent = False    # se ja enviou o primeiro Conf-Req

        self._lock = threading.Lock()

        
        self.nat = NATEngine(self._send_ip_pkt)

    def _send(self, proto: int, payload: bytes):
        pkt = struct.pack("!H", proto) + payload
        frame = hdlc_encode(pkt)
        log.debug(f"  PPP TX proto=0x{proto:04X} len={len(payload)}")
        try:
            self.ser.write(frame)
        except Exception as e:
            log.error(f"  PPP TX erro: {e}")

    def _send_lcp(self, code: int, id_: int, data: bytes = b""):
        payload = struct.pack("!BBH", code, id_, len(data) + 4) + data
        self._send(PROTO_LCP, payload)

    def _send_ipcp(self, code: int, id_: int, data: bytes = b""):
        payload = struct.pack("!BBH", code, id_, len(data) + 4) + data
        self._send(PROTO_IPCP, payload)

    def _send_pap(self, code: int, id_: int, data: bytes = b""):
        payload = struct.pack("!BBH", code, id_, len(data) + 4) + data
        self._send(PROTO_PAP, payload)

    def _lcp_send_conf_req(self):
        opts = bytearray()
        opts += bytes([LCP_OPT_MRU, 4]) + struct.pack("!H", self.mru)
        opts += bytes([LCP_OPT_MAGIC, 6]) + struct.pack("!I", self.lcp_magic)
        opts += bytes([LCP_OPT_AUTH, 4]) + struct.pack("!H", PROTO_PAP)

        self._send_lcp(CODE_CONF_REQ, self.lcp_id, bytes(opts))
        log.info("  LCP → Configure-Request enviado")

    def _lcp_handle(self, code, id_, data):
        if code == CODE_CONF_REQ:
            log.info(f"  LCP ← Configure-Request (id={id_})")

         
            ack_opts = bytearray()
            rej_opts = bytearray()
            i = 0
            while i < len(data):
                if i + 1 >= len(data):
                    break
                opt_type = data[i]
                opt_len  = data[i+1]
                if opt_len < 2:
                    break
                opt_data = data[i:i+opt_len]   # inclui type+len+value
                i += opt_len

                if opt_type in (LCP_OPT_MRU, LCP_OPT_ACCM, LCP_OPT_MAGIC):
                    ack_opts += opt_data
                    if opt_type == LCP_OPT_MAGIC and len(opt_data) >= 6:
                        self.peer_magic = struct.unpack("!I", opt_data[2:6])[0]
                else:
                    log.info(f"  LCP: rejeitando opcao type={opt_type} (nao suportada)")
                    rej_opts += opt_data

            if rej_opts:
                self._send_lcp(CODE_CONF_REJ, id_, bytes(rej_opts))
                log.info("  LCP → Configure-Reject enviado (opcoes nao suportadas)")
                # Nao marca lcp_peer_ack ainda — Windows vai reenviar sem essas opcoes
            else:
                self._send_lcp(CODE_CONF_ACK, id_, bytes(ack_opts))
                self.lcp_peer_ack = True
                log.info("  LCP → Configure-Ack enviado")
                self._check_lcp_done()

        elif code == CODE_CONF_ACK:
            log.info(f"  LCP ← Configure-Ack (id={id_})")
            self.lcp_acked = True
            self._check_lcp_done()

        elif code == CODE_CONF_NAK:
            log.info(f"  LCP ← Configure-Nak (id={id_})")
            # Reenviar com ajustes (simplificado: reenvia igual)
            self.lcp_id += 1
            self._lcp_send_conf_req()

        elif code == CODE_CONF_REJ:
            log.info(f"  LCP ← Configure-Reject (id={id_})")
            self.lcp_id += 1
            self._lcp_send_conf_req()

        elif code == CODE_TERM_REQ:
            log.info("  LCP ← Terminate-Request")
            if self.state == PPPState.IPCP_REQ:
                log.error("  !! Windows terminou durante IPCP. Possiveis causas:")
                log.error(f"     ipcp_acked={self.ipcp_acked}  ipcp_peer_ack={self.ipcp_peer_ack}  ipcp_first_sent={self._ipcp_first_sent}")
                log.error("     1. TCP/IP nao esta vinculado ao adaptador de rede")
                log.error("        → Painel de Controle > Conexoes de Rede > Discada > Propriedades")
                log.error("          > Rede > marcar 'Protocolo Internet (TCP/IP)'")
                log.error("     2. Executar como admin no cmd: netsh int ip reset && reiniciar")
            self._send_lcp(CODE_TERM_ACK, id_)
            self.state = PPPState.CLOSING
            if self.auth_ok:
                _sessoes_ativas_ref = globals()["_sessoes_ativas"]
                globals()["_sessoes_ativas"] = max(0, _sessoes_ativas_ref - 1)
            self.running = False

        elif code == CODE_ECHO_REQ:
            self._send_lcp(CODE_ECHO_REP, id_, struct.pack("!I", self.lcp_magic))

        elif code == 8:  
            if len(data) >= 2:
                rej_proto = struct.unpack("!H", data[:2])[0]
                if rej_proto == PROTO_IPCP:
                    log.error("  IPCP rejeitado pelo Windows — TCP/IP pode nao estar ligado ao adaptador!")
                    self.running = False

    def _check_lcp_done(self):
        if self.lcp_acked and self.lcp_peer_ack:
            log.info("  LCP negociado! Aguardando autenticacao PAP...")
            self.state = PPPState.AUTH

    def _pap_handle(self, code, id_, data):
        if code == PAP_AUTH_REQ:
            log.debug(f"  PAP raw data ({len(data)} bytes): {data.hex()}")

            if len(data) < 1:
                return

            user_len = data[0]
            user = data[1:1+user_len].decode("ascii", errors="replace") if user_len > 0 else ""

            passwd = ""
            if len(data) >= 2 + user_len:
                pass_len = data[1+user_len]
                passwd = data[2+user_len:2+user_len+pass_len].decode("ascii", errors="replace") if pass_len > 0 else ""

            log.info(f"  PAP ← Auth-Request user={user!r} pass={passwd!r}")

            bloqueado, restante = _verificar_bloqueio(user)
            if bloqueado:
                self._send_pap(PAP_AUTH_NAK, id_, bytes([13]) + b"Locked out!")
                return

            if _sessoes_ativas >= MAX_SESSOES:
                self._send_pap(PAP_AUTH_NAK, id_, bytes([10]) + b"Line busy!")
                return

            if user and _senha_ok(user, passwd):
                _registrar_sucesso(user)
                globals()["_sessoes_ativas"] += 1
                self._send_pap(PAP_AUTH_ACK, id_, bytes([7]) + b"Welcome")
                log.info(f"  PAP → Auth-Ack ✔ usuario '{user}' autenticado!")
                self.auth_user = user
                self.auth_ok   = True
                self.state     = PPPState.IPCP_REQ
                # Envia IPCP Conf-Req imediatamente (0ms).
                # O loop principal nao bloqueia — le o serial normalmente.
                # Windows manda seu proprio IPCP Conf-Req logo apos PAP-Ack
                # e espera resposta rapida; qualquer delay > ~50ms causa Terminate.
                self._ipcp_send_after = time.time()   # agora = sem delay
                self._ipcp_first_sent = False
            else:
                _registrar_falha(user if user else "?")
                self._send_pap(PAP_AUTH_NAK, id_, bytes([13]) + b"Auth failed!")

    def _ipcp_send_conf_req(self):
        opts = bytearray()
        opts += bytes([IPCP_OPT_ADDR, 6]) + ip_to_bytes(SERVER_IP)
        self._send_ipcp(CODE_CONF_REQ, self.ipcp_id, bytes(opts))
        log.info(f"  IPCP → Configure-Request (server={SERVER_IP})")

    def _ipcp_handle(self, code, id_, data):
        log.info(f"  IPCP ← code={code} id={id_} data={data.hex()}")
        if code == CODE_CONF_REQ:
            log.info(f"  IPCP ← Configure-Request (id={id_})")
            nak_opts  = bytearray()
            ack_opts  = bytearray()
            rej_opts  = bytearray()
            i = 0
            while i < len(data):
                if i + 1 >= len(data):
                    break
                opt_type = data[i]
                opt_len  = data[i+1]
                if opt_len < 2:
                    break
                opt_data = data[i+2:i+opt_len]
                i += opt_len

                if opt_type == IPCP_OPT_ADDR:
                    req_ip = bytes_to_ip(opt_data) if len(opt_data) >= 4 else "0.0.0.0"
                    if req_ip == "0.0.0.0":
                        nak_opts += bytes([IPCP_OPT_ADDR, 6]) + ip_to_bytes(self.client_ip)
                        log.info(f"  IPCP → Nak com IP={self.client_ip}")
                    else:
                        self.client_ip = req_ip
                        ack_opts += bytes([IPCP_OPT_ADDR, 6]) + ip_to_bytes(req_ip)

                elif opt_type == IPCP_OPT_DNS:
                    req_dns = bytes_to_ip(opt_data) if len(opt_data) >= 4 else "0.0.0.0"
                    if req_dns == "0.0.0.0":
                        nak_opts += bytes([IPCP_OPT_DNS, 6]) + ip_to_bytes(DNS_IP)
                        log.info(f"  IPCP → Nak DNS={DNS_IP}")
                    else:
                        ack_opts += bytes([IPCP_OPT_DNS, 6]) + opt_data[:4]

                elif opt_type == IPCP_OPT_DNS2:
                    # DNS secundario: se cliente pede 0.0.0.0, ACKamos com 0.0.0.0
                    # (nao temos DNS2 para oferecer — NAK com 0.0.0.0 causaria loop infinito)
                    ack_opts += bytes([IPCP_OPT_DNS2, 6]) + (opt_data[:4] if len(opt_data) >= 4 else b'\x00\x00\x00\x00')

                elif opt_type in (IPCP_OPT_NBNS, IPCP_OPT_NBNS2):
                    # WINS/NBNS — aceita com 0.0.0.0 (sem WINS)
                    ack_opts += bytes([opt_type, 6]) + ip_to_bytes("0.0.0.0")

                else:
                    log.debug(f"  IPCP: opcao desconhecida type={opt_type}, rejeitando")
                    rej_opts += bytes([opt_type, opt_len]) + opt_data

            if rej_opts:
                self._send_ipcp(CODE_CONF_REJ, id_, bytes(rej_opts))
                log.info("  IPCP → Conf-Reject (opcoes desconhecidas)")
            elif nak_opts:
                self._send_ipcp(CODE_CONF_NAK, id_, bytes(nak_opts))
            else:
                self._send_ipcp(CODE_CONF_ACK, id_, bytes(ack_opts) if ack_opts else data)
                self.ipcp_peer_ack = True
                log.info(f"  IPCP → Ack. Cliente IP={self.client_ip}")
                self._check_ipcp_done()

        elif code == CODE_CONF_ACK:
            log.info(f"  IPCP ← Configure-Ack (id={id_})")
            self.ipcp_acked = True
            self._check_ipcp_done()

        elif code == CODE_CONF_NAK:
            log.info(f"  IPCP ← Configure-Nak (id={id_})")
            # Tenta novamente com os valores sugeridos
            self.ipcp_id += 1
            self._ipcp_send_conf_req()

        elif code == CODE_CONF_REJ:
            log.info(f"  IPCP ← Configure-Reject (id={id_})")
            self.ipcp_id += 1
            self._ipcp_send_conf_req()

    def _check_ipcp_done(self):
        if self.ipcp_acked and self.ipcp_peer_ack:
            self.state = PPPState.CONNECTED
            log.info("=" * 50)
            log.info(f"  ✔ PPP CONECTADO!")
            log.info(f"  Servidor : {SERVER_IP}")
            log.info(f"  Cliente  : {self.client_ip}")
            log.info(f"  Usuario  : {self.auth_user}")
            log.info(f"  DNS      : {DNS_IP}")
            log.info("=" * 50)

    # ── Envio de pacote IP de volta para o cliente ──
    def _send_ip_pkt(self, pkt: bytes):
        self._send(PROTO_IP, pkt)

    def _ip_handle(self, data: bytes):
        if len(data) < 20:
            return
        proto  = data[9]
        src_ip = bytes_to_ip(data[12:16])
        dst_ip = bytes_to_ip(data[16:20])
        log.debug(f"  IP ← proto={proto} {src_ip} → {dst_ip}")

        # ICMP echo (ping) — responde diretamente (sem NAT)
        if proto == 1:
            if len(data) >= 24 and data[20] == 8:
                log.info(f"  PING de {src_ip} → respondendo!")
                self._icmp_reply(data)
            return

        self.nat.handle_ip(data)

    def _icmp_reply(self, req: bytes):
        reply = bytearray(req)
        reply[12:16] = req[16:20]
        reply[16:20] = req[12:16]
        reply[20] = 0
        reply[22] = 0
        reply[23] = 0
        icmp_data = bytes(reply[20:])
        cksum = self._checksum(icmp_data)
        reply[22] = (cksum >> 8) & 0xFF
        reply[23] = cksum & 0xFF
        self._send(PROTO_IP, bytes(reply))

    def _checksum(self, data: bytes) -> int:
        if len(data) % 2:
            data += b'\x00'
        s = 0
        for i in range(0, len(data), 2):
            s += (data[i] << 8) + data[i+1]
        while s >> 16:
            s = (s & 0xFFFF) + (s >> 16)
        return ~s & 0xFFFF

    def _dispatch(self, payload: bytes):
        if len(payload) < 2:
            return
        proto = struct.unpack("!H", payload[:2])[0]
        data  = payload[2:]

        if proto == PROTO_LCP:
            if len(data) < 4:
                return
            code, id_ = data[0], data[1]
            length = struct.unpack("!H", data[2:4])[0]
            self._lcp_handle(code, id_, data[4:length])

        elif proto == PROTO_PAP:
            if len(data) < 4:
                return
            code, id_ = data[0], data[1]
            length = struct.unpack("!H", data[2:4])[0]
            self._pap_handle(code, id_, data[4:length])

        elif proto == PROTO_IPCP:
            if len(data) < 4:
                return
            code, id_ = data[0], data[1]
            length = struct.unpack("!H", data[2:4])[0]
            self._ipcp_handle(code, id_, data[4:length])

        elif proto == PROTO_IP:
            if self.state == PPPState.CONNECTED:
                self._ip_handle(data)

        else:
            proto_name = {0x80FD: "CCP", 0x8207: "BACP", 0xC025: "LQR",
                          0xC223: "CHAP", 0x8021: "IPCP"}.get(proto, f"0x{proto:04X}")
            rej = struct.pack("!H", proto) + data[:32]
            self._send_lcp(8, self.lcp_id, rej)

    def run(self):
        global _sessoes_ativas  
        self.running = True
        self.state   = PPPState.LCP_REQ
        log.info("  PPP iniciado — enviando LCP Configure-Request...")
        log.info("  PPP aguardando Windows entrar em modo dados...")
        time.sleep(2.0)

        self.ser.read(self.ser.in_waiting or 1)

        self._lcp_send_conf_req()

        last_retry   = time.time()
        sessao_start = time.time()
        retries      = 0
        prev_state   = self.state

        while self.running:
            try:
                data = self.ser.read(256)
                if data:
                    log.debug(f"  PPP RAW RX ({len(data)}b): {data.hex()}")
                    = data.decode("ascii", errors="ignore").strip()
                    _upper = texto.upper()
                    _is_at = (not data.startswith(b'\x7e') and
                              (_upper.startswith("AT") or _upper == "+++"))
                    if _is_at:
                        if "ATH" in _upper:
                            log.info("  PPP: ATH recebido — encerrando sessao")
                            self.ser.write(b"\r\nOK\r\n")
                            time.sleep(0.1)
                            self.ser.write(b"\r\nNO CARRIER\r\n")
                            self.running = False
                        else:
                            self.ser.write(b"\r\nOK\r\n")
                        continue
                    self.rx.feed(data)
                    for frame in self.rx.get_frames():
                        self._dispatch(frame)

                if self.state != prev_state:
                    last_retry = time.time()
                    retries    = 0
                    prev_state = self.state

                if self.state == PPPState.LCP_REQ:
                    if time.time() - last_retry > 1.0:
                        retries += 1
                        if retries > 20:
                            log.error("  PPP: timeout LCP — desistindo")
                            self.running = False
                            break
                        log.info(f"  PPP: reenviando LCP ({retries}/20)...")
                        self._lcp_send_conf_req()
                        last_retry = time.time()

                if self.state == PPPState.IPCP_REQ:
                    now = time.time()
                    if not self._ipcp_first_sent:
                        if now >= self._ipcp_send_after:
                            self._ipcp_first_sent = True
                            last_retry = now
                            retries    = 0
                            self._ipcp_send_conf_req()
                    elif now - last_retry > 0.5:
                        retries += 1
                        if retries > 20:
                            log.error("  PPP: timeout IPCP — desistindo")
                            self.running = False
                            break
                        log.info(f"  PPP: reenviando IPCP ({retries}/20)...")
                        self._ipcp_send_conf_req()
                        last_retry = now

                if self.state == PPPState.CONNECTED:
                    if time.time() - sessao_start > TIMEOUT_SESSAO:
                        self._send_lcp(CODE_TERM_REQ, self.lcp_id)
                        _sessoes_ativas = max(0, _sessoes_ativas - 1)
                        self.running = False
                        break

                if self.state == PPPState.AUTH:
                    if time.time() - sessao_start > 30:
                        self._send_lcp(CODE_TERM_REQ, self.lcp_id)
                        self.running = False
                        break

            except Exception as e:
                log.error(f"  PPP erro: {e}")
                time.sleep(0.1)

        if self.auth_ok and _sessoes_ativas > 0:
            _sessoes_ativas -= 1
        log.info("  PPP encerrado.")
