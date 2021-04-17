
import socket
import select
import struct
import ssl

from util import sendSocket, recvSocket, is_multicast
from common import options, ErrorMessage, dprint, TIMEOUT_MAX, Counter, BUFSIZE
from dnsparam import rc
from dnsmsg import DNSresponse



def send_request_udp(pkt, host, port, family, itimeout, retries):
    response, responder = b"", ("", 0)
    s = socket.socket(family, socket.SOCK_DGRAM)
    if options["srcip"]:
        s.bind((options["srcip"], 0))
        if is_multicast(host) and (host.find('.') != -1):
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, \
                         socket.inet_aton(options["srcip"]))
    timeout = itimeout
    while retries > 0:
        s.settimeout(timeout)
        try:
            s.sendto(pkt, (host, port))
            (response, responder) = s.recvfrom(BUFSIZE)
            break
        except socket.timeout:
            timeout = timeout * 2
            dprint("Request timed out with no answer")
        retries -= 1
    s.close()
    return (response, responder)


def send_request_tcp(pkt, host, port, family):

    pkt = struct.pack("!H", len(pkt)) + pkt       
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT_MAX)
    if options["srcip"]:
        s.bind((options["srcip"], 0))

    response = b""

    try:
        s.connect((host, port))
        if not sendSocket(s, pkt):
            raise ErrorMessage("send() on socket failed.")
    except socket.error as e:
        s.close()
        raise ErrorMessage("tcp socket send error: %s" % e)

    while True:
        try:
            ready_r, _, _ = select.select([s], [], [])
        except select.error as e:
            raise ErrorMessage("fatal error from select(): %s" % e)
        if ready_r and (s in ready_r):
            lbytes = recvSocket(s, 2)
            if len(lbytes) != 2:
                raise ErrorMessage("recv() on socket failed.")
            resp_len, = struct.unpack('!H', lbytes)
            response = recvSocket(s, resp_len)
            break

    s.close()
    return response


