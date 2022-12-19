from struct import pack, unpack
import socket
# proxy protocol

# signature: \x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A
# 13: 0b 0010 0001 (v2 || PROXY)
# 14: 0b 0001 0001 (AF_INET || TCP)
# 15-16: \x0c\x00 (IPv4 addr len)
HEADER = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x0c\x00"

# struct {        /* for TCP/UDP over IPv4, len = 12 */
#             uint32_t src_addr;
#             uint32_t dst_addr;
#             uint16_t src_port;
#             uint16_t dst_port;
#         } ipv4_addr;

def pack_addr_info(
    src: tuple[str, int],
    dst: tuple[str, int]
) -> bytes:
    return socket.inet_aton(src[0]) + socket.inet_aton(dst[0]) + pack("!HH", src[1], dst[1])

def proxy_protocol_packet(data: bytes, addr_info: bytes) -> bytes:
    return HEADER + addr_info + data