import serial
import serial.tools.list_ports
import threading
import time
import sys
import os
import random
import logging
import winsound
from datetime import datetime
from ppp_server import PPPServer

SOUND_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dial-up-sound_1.wav")

def play_dialup_sound(wait=False):
    if wait:
        # Toca sincrono — bloqueia ate o WAV terminar
        if os.path.exists(SOUND_FILE):
            try:
                log.info("  [SOM] Tocando som completo de discagem...")
                winsound.PlaySound(SOUND_FILE, winsound.SND_FILENAME)
                log.info("  [SOM] Audio concluido.")
            except Exception as e:
                pass
        else:
            winsound.MessageBeep(winsound.MB_ICONASTERISK)
            time.sleep(2)
    else:
        def _play():
            if os.path.exists(SOUND_FILE):
                try:
                    winsound.PlaySound(SOUND_FILE, winsound.SND_FILENAME | winsound.SND_ASYNC)
                    log.info("  [SOM] Tocando som de discagem...")
                except Exception as e:
                    pass
            else:
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
        threading.Thread(target=_play, daemon=True).start()

def stop_dialup_sound():
    try:
        winsound.PlaySound(None, winsound.SND_ASYNC)
    except Exception:
        pass

import configparser
_cfg = configparser.ConfigParser()
_cfg.read(os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini"), encoding="utf-8")

SIM_PORT    = _cfg.get("modem", "porta_simulador", fallback="COM11")
DUN_PORT    = _cfg.get("modem", "porta_windows",   fallback="COM2")
BAUD_RATE   = _cfg.getint("modem", "baud_rate",    fallback=115200)
MODEM_SPEED = _cfg.getint("modem", "velocidade",   fallback=56000)
BYTE_DELAY  = 1.0 / (MODEM_SPEED / 8)

logging.raiseExceptions = False  

_console_handler = logging.StreamHandler(sys.stderr)
_console_handler.setLevel(logging.INFO)
_console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logging.basicConfig(level=logging.INFO, handlers=[_console_handler])
log = logging.getLogger("Modem56k")

class St:
    COMMAND    = "COMMAND"
    CONNECTING = "CONNECTING"
    CONNECTED  = "CONNECTED"
    HANGUP     = "HANGUP"

DEFAULT_S = {
    "S0": 0,  "S1": 0,  "S2": 43, "S3": 13,
    "S4": 10, "S5": 8,  "S6": 2,  "S7": 50,
    "S8": 2,  "S9": 6,  "S10": 14,"S11": 95,
    "S95": 0,  
}

class FaxModem56k:

    RESULT_CODES = {
        "OK": "0", "CONNECT": "1", "RING": "2",
        "NO CARRIER": "3", "ERROR": "4",
        "NO DIALTONE": "6", "BUSY": "7", "NO ANSWER": "8",
    }

    def __init__(self, port: str = SIM_PORT):
        self.port    = port
        self.ser     = None
        self.state   = St.COMMAND
        self.running = False

        self.s        = dict(DEFAULT_S)
        self.echo     = True    # ATE1
        self.verbose  = True    # ATV1
        self.quiet    = False   # ATQ0
        self.speaker  = 1       # ATM1
        self.volume   = 2       # ATL2

        self.cmd_buf      = ""
        self.escape_buf   = 0
        self.last_rx_time = 0.0
        self.dial_num     = ""
        self.connected_at = None
        self._sound_played = False   
    def _open(self) -> bool:
        try:
            self.ser = serial.Serial(
                port     = self.port,
                baudrate = BAUD_RATE,
                bytesize = serial.EIGHTBITS,
                parity   = serial.PARITY_NONE,
                stopbits = serial.STOPBITS_ONE,
                timeout  = 0.05,
                rtscts   = False,
            )
            log.info(f"✔ Porta {self.port} aberta.")
            # Força RTS e DTR ativos — o com0com espelha como DCD/DSR no lado do Windows
            # Sem isso o Windows detecta DCD inativo e manda +++ ATH
            self.ser.setRTS(True)
            self.ser.setDTR(True)
            return True
        except serial.SerialException as e:
            log.error(f"✘ Erro ao abrir {self.port}: {e}")
            return False

    def _tx(self, msg: str):
        if self.quiet:
            return
        if not self.verbose:
            for k, v in self.RESULT_CODES.items():
                if msg.strip().startswith(k):
                    msg = msg.replace(k, v, 1)
        frame = f"\r\n{msg}\r\n"
        log.debug(f"  ← {repr(frame)}")
        self.ser.write(frame.encode("ascii", errors="replace"))

    def _tx_raw(self, data: bytes):
        time.sleep(len(data) * BYTE_DELAY)
        self.ser.write(data)

    def _process(self, raw: str):
        cmd = raw.strip().upper()
        log.info(f"  → AT CMD: {cmd!r}")

        if not cmd.startswith("AT"):
            self._tx("ERROR"); return

        body = cmd[2:]
        if not body:
            self._tx("OK"); return

        i = 0
        while i < len(body):
            c = body[i]

            if c == "Z":
                self._reset(); self._tx("OK"); i += 1

            elif c == "A":
                self._do_answer(); return

            elif c == "H":
                i += 1
                n = 0
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self._do_hangup(n)

            elif c == "E":
                i += 1
                n = 1
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self.echo = bool(n); self._tx("OK")

            elif c == "V":
                i += 1
                n = 1
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self.verbose = bool(n); self._tx("OK")

            elif c == "Q":
                i += 1
                n = 0
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self.quiet = bool(n); self._tx("OK")

            elif c == "M":
                i += 1
                n = 1
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self.speaker = n; self._tx("OK")

            elif c == "L":
                i += 1
                n = 2
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self.volume = n; self._tx("OK")

            elif c == "D":
                num = body[i+1:]
                self._do_dial(num); return

            elif c == "I":
                i += 1
                n = 0
                if i < len(body) and body[i].isdigit():
                    n = int(body[i]); i += 1
                self._do_identify(n)

            elif c == "S":
                i += 1
                reg_n = ""
                while i < len(body) and body[i].isdigit():
                    reg_n += body[i]; i += 1
                reg = f"S{reg_n}"
                if i < len(body) and body[i] == "=":
                    i += 1
                    val = ""
                    while i < len(body) and body[i].isdigit():
                        val += body[i]; i += 1
                    self.s[reg] = int(val)
                    self._tx("OK")
                elif i < len(body) and body[i] == "?":
                    i += 1
                    self._tx(f"{self.s.get(reg, 0):03d}")
                    self._tx("OK")
                else:
                    self._tx("ERROR"); return

            elif body[i:i+2] == "&F":
                self._reset(); self._tx("OK"); i += 2

            elif body[i:i+2] == "&C":
                i += 2
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            elif body[i:i+2] == "&D":
                i += 2
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            # &K: flow control (0=none, 3=RTS/CTS, 4=XON/XOFF)
            elif body[i:i+2] == "&K":
                i += 2
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            elif body[i:i+2] == "&W":
                i += 2
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            # N: negociacao de velocidade (N0=fixo, N1=auto)
            elif c == "N":
                i += 1
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            # X: nivel de resultado estendido (X0-X4)
            elif c == "X":
                i += 1
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            elif c == "W":
                i += 1
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            elif c == "Y":
                i += 1
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            # %: comandos extendidos (Ex: %C0 compressao)
            elif c == "%":
                i += 2
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            # \: comandos backslash (Ex: \N3 protocolo de correcao)
            elif c == "\\": 
                i += 2
                if i < len(body) and body[i].isdigit(): i += 1
                self._tx("OK")

            elif body[i:].startswith("+FCLASS"):
                rest = body[i+7:]
                if "=?" in rest:
                    self._tx("+FCLASS: 0,1,2")
                elif "?" in rest:
                    self._tx("+FCLASS: 0")
                self._tx("OK")
                i = len(body)

            elif body[i:].startswith("+GMI"):
                self._tx("+GMI: SimModem Virtual"); self._tx("OK"); i = len(body)
            elif body[i:].startswith("+GMM"):
                self._tx("+GMM: VirtualFaxModem56K"); self._tx("OK"); i = len(body)
            elif body[i:].startswith("+GMR"):
                self._tx("+GMR: V.90/V.92 Rev1.0"); self._tx("OK"); i = len(body)

            # +MS (modulation select — só responde OK)
            elif body[i:].startswith("+MS"):
                self._tx("OK"); i = len(body)

            else:
                self._tx("OK"); return

    def _reset(self):
        self.s      = dict(DEFAULT_S)
        self.echo   = True
        self.verbose= True
        self.quiet  = False
        self.speaker= 1
        self.volume = 2
        self.state  = St.COMMAND
        self.cmd_buf= ""
        log.info("  Modem resetado (ATZ / AT&F)")

    def _do_dial(self, number: str):
        clean = number.lstrip("TPW ,;!@").strip()
        self.dial_num = clean
        log.info(f"  Discando: {clean!r}")

        play_dialup_sound(wait=False)

        time.sleep(1.0)
        log.info("  [SOM] Handshake em andamento...")

        if random.random() < 0.05:
            self._tx("NO CARRIER")
            self.state = St.COMMAND
            return

        speed = random.choice([28800,33600,44000,48000,50666,53333,56000])
        self.connected_at = datetime.now()
        self._sound_played = False
        log.info(f"  ✔ CONECTADO @ {speed} bps")
        self._tx(f"CONNECT {speed}")

        try:
            self.ser.setRTS(True)
            self.ser.setDTR(True)
            log.info("  DCD/RTS/DTR ativados.")
        except Exception as e:
            pass

        self.state = St.CONNECTED
        log.info("  Iniciando servidor PPP imediatamente...")
        ppp = PPPServer(self.ser)
        ppp.run()
        stop_dialup_sound()
        self.state = St.COMMAND
        self._sound_played = False
        log.info("  PPP encerrado. Voltando ao modo AT.")

    def _do_answer(self):
        log.info("  Atendendo chamada recebida...")
        play_dialup_sound()
        time.sleep(1.2)
        speed = random.choice([48000,50666,53333,56000])
        self.state        = St.CONNECTED
        self.connected_at = datetime.now()
        stop_dialup_sound()
        self._sound_played = False
        self._tx(f"CONNECT {speed}")

    def _do_hangup(self, n: int = 0):
        if self.state == St.CONNECTED:
            log.info("  Desconectando (ATH)...")
            stop_dialup_sound()
            self.state = St.COMMAND
            self._sound_played = False
            self._tx("NO CARRIER")
        else:
            self._tx("OK")

    def _do_identify(self, n: int):
        info = {
            0: "SimModem56k",
            1: "V.90/V.92 56000bps Virtual Fax/Modem",
            2: "Revision 1.0 (Python)",
            3: "SimModem56k — github/seuusuario",
        }
        self._tx(info.get(n, "SimModem56k"))
        self._tx("OK")

    def _check_escape(self, ch: str) -> bool:
        esc = chr(self.s["S2"])
        now = time.time()
        if ch == esc and (now - self.last_rx_time) > 1.0:
            self.escape_buf += 1
            if self.escape_buf >= 3:
                time.sleep(1.0)
                self.state = St.COMMAND
                self.escape_buf = 0
                self._tx("OK")
                log.info("  Escape (+++) → modo comando")
                return True
        elif ch != esc:
            self.escape_buf = 0
        self.last_rx_time = now
        return False

    def run(self):
        if not self._open():
            print(f"\n[ERRO] Não foi possível abrir {self.port}.")
            print("Verifique se o com0com está instalado e o par COM10↔COM11 criado.")
            return

        self.running = True
        banner()

        while self.running:
            try:
                data = self.ser.read(256)
                if not data:
                    continue

                for b in data:
                    ch = chr(b)
                    if self.echo:
                        self.ser.write(bytes([b]))  # eco

                    if b == self.s["S3"]:      # CR → executar
                        cmd = self.cmd_buf.strip()
                        self.cmd_buf = ""
                        if cmd:
                            self._process(cmd)
                    elif b == self.s["S5"]:    # Backspace
                        self.cmd_buf = self.cmd_buf[:-1]
                    elif 32 <= b <= 126:
                        self.cmd_buf += ch

            except serial.SerialException as e:
                log.error(f"Erro serial: {e}")
                time.sleep(0.3)
            except KeyboardInterrupt:
                print("\n[!] Encerrado pelo usuário.")
                break

        self.running = False
        if self.ser and self.ser.is_open:
            self.ser.close()
        log.info("Simulador encerrado.")

def banner():
    print("=" * 58)
    print("  🖥️  Simulador Fax/Modem V.90 56kbps")
    print(f"  Escutando em: {SIM_PORT}  (par com0com → {DUN_PORT})")
    print("  Windows deve usar a porta: COM10")
    print("  Pressione Ctrl+C para encerrar")
    print("=" * 58)
    ports = [p.device for p in serial.tools.list_ports.comports()]
    print(f"  Portas detectadas: {', '.join(ports) if ports else 'nenhuma'}")
    
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Simulador Fax/Modem 56kbps")
    p.add_argument("--port",  default=SIM_PORT,
                   help=f"Porta COM do simulador (padrão: {SIM_PORT})")
    p.add_argument("--baud",  type=int, default=BAUD_RATE)
    args = p.parse_args()

    SIM_PORT  = args.port
    BAUD_RATE = args.baud

    modem = FaxModem56k(SIM_PORT)
    modem.run()
