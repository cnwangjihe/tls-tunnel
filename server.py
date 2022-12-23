from threading import Thread

from typing import TypedDict
from struct import pack, unpack

from proxy_protocol import pack_addr_info, proxy_protocol_packet
from key_exchange import recv_exchange_packet, generate_exchange_packet, generate_shared_key
from utils import xor_ECDSA_privkey, load_ECDSA_privkey, to_bytes


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import socket
import logging
import select

class TunnelServerConfig(TypedDict):
    cert: str
    privkey: ec.EllipticCurvePrivateKey
    dest: tuple[str, int]
    addr_info: bytes
    proxy_protocol: bool

class TunnelServerThread(Thread):
    def __init__(
        self,
        config: TunnelServerConfig,
        conn: socket.socket
    ):
        super().__init__()
        self.config = config
        self.tun = conn
    
    def run(self):
        tun = self.tun
        dst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # blocking first, for recv and send handshake packet
            tun.setblocking(True)
            key_spec = recv_exchange_packet(tun, False)
            xchg_privkey, raw_packet = generate_exchange_packet(0, self.config["cert"], self.config["privkey"])
            tun.send(raw_packet)
            server_iv, client_iv, aes_key = generate_shared_key(key_spec, xchg_privkey)
            logging.info(f"X25519 key exchange success: {aes_key}")
            cipher = AESGCM(aes_key)

            # connect to dst
            dst.connect(tuple(self.config["dest"]))

            # send proxy_protocol header first
            if self.config["proxy_protocol"]:
                dst.send(proxy_protocol_packet(b"", self.config["addr_info"]))

            # for select, non-blocking is a better choice
            tun.setblocking(False)
            dst.setblocking(False)

            tun_recv_buf = b""
            tun_send_buf = b""
            dst_send_buf = b""
            # data packet: 4byte length || data
            # lower layer is TCP, don't need to consider data corrupt
            while True:
                wlist = []
                if tun_send_buf:
                    wlist.append(tun)
                if dst_send_buf:
                    wlist.append(dst)
                readable, writable, exceptional = select.select([tun, dst], wlist, [tun, dst])
                if exceptional:
                    logging.warning("socket closed")
                    break
                if tun in readable:
                    raw = tun.recv(0x1000)
                    if len(raw) == 0:
                        logging.info("tun socket closed.")
                        break
                    tun_recv_buf += raw
                    # check and decrypt packet
                    while len(tun_recv_buf) > 4:
                        l = unpack("<I", tun_recv_buf[:4])[0]
                        # have a full packet
                        if len(tun_recv_buf) - 4 < l:
                            break
                        # send decrypt data to dst socket
                        dst_send_buf += cipher.decrypt(to_bytes(client_iv, 96), tun_recv_buf[4:][:l], None)
                        tun_recv_buf = tun_recv_buf[4+l:]
                        client_iv += 1
                if dst in readable:
                    raw = dst.recv(0x1000)
                    if len(raw) == 0:
                        logging.info("dst socket closed.")
                        break
                    encrypted = cipher.encrypt(to_bytes(server_iv, 96), raw, None)
                    tun_send_buf += pack("<I", len(encrypted)) + encrypted
                    server_iv += 1
                if tun in writable:
                    tun_send_buf = tun_send_buf[tun.send(tun_send_buf):]
                if dst in writable:
                    dst_send_buf = dst_send_buf[dst.send(dst_send_buf):]
        except (BrokenPipeError, ConnectionResetError):
            logging.warning("socket closed unexpected.")
        finally:
            tun.close()
            dst.close()

class TunnelServer(Thread):
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
    
    def run(self):
        config = self.config
        assert config["mode"] == 0
        bind_addr = config["listen"]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setblocking(True)
        s.bind(tuple(bind_addr))
        s.listen()

        with open(config["privkey"], "r") as f:
            privkey_raw = f.read()
            if "privkey_password" in config:
                privkey_raw = xor_ECDSA_privkey(privkey_raw, config["privkey_password"])
            privkey = load_ECDSA_privkey(privkey_raw)

        with open(config["cert"], "r") as f:
            cert = f.read()

        while True:
            conn, addr = s.accept()
            logging.info(f"accept client {addr}.")
            TunnelServerThread({
                "cert": cert,
                "privkey": privkey,
                "dest": config["dest"],
                "addr_info": pack_addr_info(addr, bind_addr),
                "proxy_protocol": config["proxy_protocol"]
            }, conn).start()
