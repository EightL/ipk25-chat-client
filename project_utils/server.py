#!/usr/bin/env python3
"""
IPK25-CHAT test-server with readable debug logging.
"""
import argparse
import socket
import struct
import threading
import itertools
import logging
import signal
import sys

# Configure logger
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("ipk25_server")

# Protocol constants
CONFIRM = 0x00
REPLY   = 0x01
AUTH    = 0x02
JOIN    = 0x03
MSG     = 0x04
PING    = 0xFD
ERR     = 0xFE
BYE     = 0xFF
TCP_EOL = b"\r\n"

# Message ID generator
MSG_ID_GEN = itertools.count(0)

def next_msg_id():
    mid = next(MSG_ID_GEN) & 0xFFFF
    logger.debug("[ID_GEN] -> %d", mid)
    return mid

# Helpers for binary packing

def pack16(val):
    packed = struct.pack('!H', val)
    logger.debug("[PACK16] %d -> %s", val, packed)
    return packed

# === UDP Builders ===

def build_confirm(ref_id):
    logger.debug("[BUILD] CONFIRM refMsgId=%d", ref_id)
    pkt = bytes([CONFIRM]) + pack16(ref_id)
    logger.debug("[BYTES] %s", pkt)
    return pkt


def build_reply(ok, ref_id, text):
    mid = next_msg_id()
    logger.debug("[BUILD] REPLY mid=%d (ref %d)", mid, ref_id)
    logger.debug("  Success: %s", ok)
    logger.debug("  Text: '%s'", text)
    body = bytearray([REPLY])
    body += pack16(mid)
    body.append(1 if ok else 0)
    body += pack16(ref_id)
    body.extend(text.encode('ascii', 'ignore') + b'\x00')
    logger.debug("[BYTES] %s", body)
    return bytes(body), mid


def build_msg(display, content):
    mid = next_msg_id()
    logger.debug("[BUILD] MSG mid=%d from='%s'", mid, display)
    logger.debug("  Content: '%s'", content)
    pkt = bytearray([MSG])
    pkt += pack16(mid)
    pkt.extend(display.encode('ascii', 'ignore') + b'\x00')
    pkt.extend(content.encode('ascii', 'ignore') + b'\x00')
    logger.debug("[BYTES] %s", pkt)
    return bytes(pkt), mid

# === UDP Parser ===

def parse_udp_packet(data):
    length = len(data)
    if length < 3:
        logger.warning("[PARSE] Packet too short (%d bytes)", length)
        return None

    mtype = data[0]
    msg_id = struct.unpack('!H', data[1:3])[0]
    payload = data[3:]
    logger.debug("[PARSE] type=0x%02X id=%d payload_len=%d", mtype, msg_id, len(payload))

    params = []
    if mtype in (AUTH, JOIN, MSG, ERR, BYE):
        parts = payload.split(b'\x00')
        params = [p.decode('ascii', 'ignore') for p in parts if p]
        logger.debug("  Fields: %s", params)

    elif mtype == REPLY:
        success = bool(payload[0])
        ref_id = struct.unpack('!H', payload[1:3])[0]
        text = payload[3:].split(b'\x00')[0].decode('ascii', 'ignore')
        params = [success, ref_id, text]
        logger.debug("  REPLY success=%s refMsgId=%d text='%s'", success, ref_id, text)

    else:
        logger.debug("  No rules for type=0x%02X", mtype)

    return mtype, msg_id, params

# === TCP Builders ===

def build_tcp_reply(ok, text):
    line = f"REPLY {'OK' if ok else 'NOK'} IS {text}\r\n"
    data = line.encode('ascii', 'ignore')
    logger.debug("[TCP BUILD] %s", line.strip())
    return data


def build_tcp_msg(from_name, text):
    line = f"MSG FROM {from_name} IS {text}\r\n"
    data = line.encode('ascii', 'ignore')
    logger.debug("[TCP BUILD] %s", line.strip())
    return data

# === Client Handlers ===

class TcpClientHandler(threading.Thread):
    def __init__(self, conn, addr):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.display = None
        logger.info("[TCP] Connected %s", addr)

    def run(self):
        buf = b''
        while True:
            try:
                chunk = self.conn.recv(4096)
            except OSError as e:
                logger.debug("[TCP] recv error: %s", e)
                break
            if not chunk:
                logger.info("[TCP] %s disconnected", self.addr)
                break

            buf += chunk
            logger.debug("[TCP] chunk: %s", chunk)

            while TCP_EOL in buf:
                line, buf = buf.split(TCP_EOL, 1)
                if self.handle_line(line.decode()):
                    break

        self.conn.close()
        logger.info("[TCP] Handler closed %s", self.addr)

    def handle_line(self, line):
        parts = line.strip().split()
        logger.debug("[TCP] line parts: %s", parts)
        if not parts:
            return False

        cmd = parts[0]
        if cmd == 'AUTH' and len(parts) >= 6:
            self.display = parts[3]
            logger.info("[TCP] AUTH user=%s display=%s", parts[1], self.display)
            self.conn.sendall(build_tcp_reply(True, 'Auth success.'))
            self.conn.sendall(build_tcp_msg('Server', f"{self.display} has joined default."))

        elif cmd == 'JOIN' and len(parts) >= 4:
            logger.info("[TCP] JOIN channel=%s display=%s", parts[1], self.display)
            self.conn.sendall(build_tcp_msg('Server', f"{self.display} has joined {parts[1]}."))
            self.conn.sendall(build_tcp_reply(True, 'Join success.'))

        elif cmd == 'MSG' and 'IS' in parts:
            content = ' '.join(parts[parts.index('IS')+1:])
            logger.info("[TCP] MSG from %s: %s", self.display, content) 
            self.conn.sendall(build_tcp_msg(f"{self.display}", f"{content}"))

        elif cmd == 'BYE':
            logger.info("[TCP] BYE from %s", self.display)
            return True

        else:
            logger.warning("[TCP] Unknown cmd: %s", parts)
            self.conn.sendall(build_tcp_reply(False, 'Unknown command'))

        return False

class UdpClientHandler(threading.Thread):
    def __init__(self, sock, addr, pkt):
        super().__init__(daemon=True)
        self.sock = sock
        self.addr = addr
        self.pkt = pkt
        self.display = None

    def run(self):
        mtype, mid, params = self.pkt
        logger.debug("[UDP INIT] type=0x%02X id=%d params=%s", mtype, mid, params)

        if mtype == AUTH and len(params) == 3:
            _, disp, _ = params
            self.display = disp
            logger.info("[UDP] AUTH display=%s", self.display)
            self.sock.sendto(build_confirm(mid), self.addr)
        else:
            logger.error("[UDP] Bad initial pkt, dropping")
            return

        dyn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dyn.bind(('', 0))
        port = dyn.getsockname()[1]
        logger.info("[UDP] Using port %d for %s", port, self.addr)

        reply_pkt, _ = build_reply(True, mid, 'Auth success.')
        dyn.sendto(reply_pkt, self.addr)

        while True:
            data, addr = dyn.recvfrom(65535)
            parsed = parse_udp_packet(data)
            if not parsed:
                continue

            typ, dm_id, prms = parsed
            logger.debug("[UDP] pkt type=0x%02X id=%d params=%s", typ, dm_id, prms)
            dyn.sendto(build_confirm(dm_id), addr)

            if typ == JOIN and len(prms) == 2:
                _, disp = prms
                logger.info("[UDP] JOIN display=%s", disp)
                pkt, _ = build_msg('Server', f"{disp} has joined {prms[0]}.")
                dyn.sendto(pkt, addr)
                rep, _ = build_reply(True, dm_id, 'Join success.')
                dyn.sendto(rep, addr)

            elif typ == MSG and len(prms) == 2:
                disp, txt = prms
                logger.info("[UDP] MSG from %s: %s", disp, txt)
                echo, _ = build_msg(f"{disp}", txt)
                dyn.sendto(echo, addr)

            elif typ == BYE:
                logger.info("[UDP] BYE from %s, closing", self.display)
                break

            else:
                logger.warning("[UDP] Unknown type=0x%02X", typ)

        dyn.close()

# === Server entrypoints ===
def serve_tcp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', port))
    sock.listen()
    logger.info("[TCP] Listening on %d", port)
    while True:
        conn, addr = sock.accept()
        TcpClientHandler(conn, addr).start()


def serve_udp(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', port))
    logger.info("[UDP] Listening on %d", port)
    while True:
        data, addr = sock.recvfrom(65535)
        parsed = parse_udp_packet(data)
        if not parsed:
            continue
        typ, mid, prms = parsed
        if typ == AUTH:
            UdpClientHandler(sock, addr, parsed).start()
        else:
            sock.sendto(build_confirm(mid), addr)
            logger.warning("[UDP] Rejecting pre-AUTH type=0x%02X", typ)

# === Main CLI ===

def main():
    p = argparse.ArgumentParser()
    p.add_argument('-t', '--transport', choices=['tcp','udp'], default='tcp')
    p.add_argument('-p', '--port', type=int, default=4567)
    args = p.parse_args()
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))

    if args.transport == 'tcp':
        serve_tcp(args.port)
    else:
        serve_udp(args.port)

if __name__ == '__main__':
    main()