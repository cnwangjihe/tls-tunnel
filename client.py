from threading import Thread

from typing import TypedDict
from struct import pack, unpack

from key_exchange import recv_exchange_packet, generate_exchange_packet, generate_shared_key
from utils import AppException, to_bytes


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import socket
import logging
import select

class TunnelClientConfig(TypedDict):
    dest: tuple[str, int]
    uid: str

class TunnelClientThread(Thread):
    def __init__(
        self,
        config: TunnelClientConfig,
        conn: socket.socket
    ):
        super().__init__()
        self.config = config
        self.src = conn
    
    def run(self):
        src = self.src
        tun = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # establish tunnel
            tun.connect(tuple(self.config["dest"]))
            # blocking first, for recv and send handshake packet
            tun.setblocking(True)
            xchg_privkey, raw_packet = generate_exchange_packet(1)
            tun.send(raw_packet)
            # verify server cert and msg sig
            try:
                key_spec = recv_exchange_packet(tun, True)
            except AppException:
                logging.error("cert verify failed")
                return
            if key_spec.uid != self.config["uid"]:
                raise Exception("Cert common_name mismatch")
            server_iv, client_iv, aes_key = generate_shared_key(key_spec, xchg_privkey)
            logging.info(f"X25519 key exchange success: {aes_key}")
            cipher = AESGCM(aes_key)

            # for select, non-blocking is a better choice
            tun.setblocking(False)
            src.setblocking(False)

            tun_recv_buf = b""
            tun_send_buf = b""
            src_send_buf = b""
            # data packet: 4byte length || data
            # lower layer is TCP, don't need to consider data corrupt
            while True:
                wlist = []
                if tun_send_buf:
                    wlist.append(tun)
                if src_send_buf:
                    wlist.append(src)
                readable, writable, exceptional = select.select([src, tun], wlist, [src, tun])
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
                        raw = cipher.decrypt(to_bytes(server_iv, 96), tun_recv_buf[4:][:l], None)
                        tun_recv_buf = tun_recv_buf[4+l:]
                        server_iv += 1
                        # send decrypt data to src socket
                        src_send_buf += raw
                if src in readable:
                    raw = src.recv(0x1000)
                    if len(raw) == 0:
                        logging.info("src socket closed.")
                        break
                    encrypted = cipher.encrypt(to_bytes(client_iv, 96), raw, None)
                    tun_send_buf += pack("<I", len(encrypted)) + encrypted
                    client_iv += 1
                if tun in writable:
                    tun_send_buf = tun_send_buf[tun.send(tun_send_buf):]
                if src in writable:
                    src_send_buf = src_send_buf[src.send(src_send_buf):]
        except (BrokenPipeError, ConnectionResetError):
            logging.warning("socket closed unexpected.")
        finally:
            tun.close()
            src.close()

class TunnelClient(Thread):
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
    
    def run(self):
        config = self.config
        assert config["mode"] == 1
        bind_addr = config["listen"]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setblocking(True)
        s.bind(tuple(bind_addr))
        s.listen()
        
        while True:
            conn, addr = s.accept()
            logging.info(f"accept client {addr}.")
            TunnelClientThread({
                "dest": config["dest"],
                "uid": config["uid"]
            }, conn).start()
