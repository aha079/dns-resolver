"""
Misc utility functions.

"""

import os
import socket
import struct
import random
import hashlib
import binascii

from common import RESOLV_CONF, ErrorMessage



printables_txt = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ '
backslash_txt = b'"'

printables_label = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~.'
backslash_label = b'.\\'


class Struct:
    pass


def random_init():
    random.seed(os.urandom(64))
    return


def hexdump(inputbytes):

    return binascii.hexlify(inputbytes).decode('ascii')


def h2bin(x):

    return binascii.unhexlify(x.replace(' ', '').replace('\n', ''))


def packed2int(input):

    sum = 0
    for (i, x) in enumerate(input[::-1]):
        sum += x * 2**(8*i)
    return sum


def bytes2escapedstring(indata, to_backslash, printables):
    out = ''
    for c in indata:
        c_chr = chr(c)
        if c in to_backslash:
            out += ("\\" + c_chr)
        elif c in printables:
            out += c_chr
        else:
            out += r"\{:03d}".format(c)
    return out


def randomize_case(input):
    outlist = []
    random.seed()
    for c in input:
        if c.isalpha():
            if random.choice([0, 1]):
                outlist.append(chr((ord(c) ^ 0x20)))
                continue
        outlist.append(c)
    return "".join(outlist)


def ip2ptr(address):
    v4_suffix = '.in-addr.arpa.'
    v6_suffix = '.ip6.arpa.'
    error = False
    try:
        if address.find('.') != -1:                             
            packed = socket.inet_pton(socket.AF_INET, address)
            octetlist = ["%d" % x for x in packed]
            ptrowner = "%s%s" % ('.'.join(octetlist[::-1]), v4_suffix)
        elif address.find(':') != -1:                          
            packed = socket.inet_pton(socket.AF_INET6, address)
            hexstring = ''.join(["%02x" % x for x in packed])
            ptrowner = "%s%s" % \
                       ('.'.join([x for x in hexstring[::-1]]), v6_suffix)
        else:
            error = True
    except socket.error:
        error = True
    if error:
        raise ErrorMessage("%s isn't an IPv4 or IPv6 address" % address)

    return ptrowner


def is_multicast(address):
    if address.find('.') != -1:
        return 224 <= int(address.split('.')[0]) <= 239
    elif address.find(':') != -1:
        field1 = address.split(':')[0]
        return (len(field1) == 4) and (field1.lower()[:2] == 'ff')


def get_socketparams(server, port, af, type):
    ai = socket.getaddrinfo(server, port, af, type)[0]
    family, socktype, _, _, sockaddr = ai
    server_addr, port = sockaddr[0:2]
    return (server_addr, port, family, socktype)


def sendSocket(s, message):

    try:
        octetsSent = 0
        while octetsSent < len(message):
            sentn = s.send(message[octetsSent:])
            if sentn == 0:
                raise ErrorMessage("send() returned 0 bytes")
            octetsSent += sentn
    except Exception as e:
        print("DEBUG: Exception: %s" % e)
        return False
    else:
        return True


def recvSocket(s, numOctets):

    response = b""
    octetsRead = 0
    while octetsRead < numOctets:
        chunk = s.recv(numOctets-octetsRead)
        chunklen = len(chunk)
        if chunklen == 0:
            return b""
        octetsRead += chunklen
        response += chunk
    return response


def xor_string(a, b):

    result = b''
    for (x, y) in zip(a, b):
        result += struct.pack('B', (x ^ y))
    return result


def hmac(key, data, func):

    BLOCKSIZE = 64                                  # 64 bytes = 512 bits
    ipad = b'\x36' * BLOCKSIZE
    opad = b'\x5c' * BLOCKSIZE

    key = key + b'\x00' * (BLOCKSIZE - len(key))    # pad to blocksize

    m = func()
    m.update(xor_string(key, ipad) + data)
    r1 = m.digest()

    m = func()
    m.update(xor_string(key, opad) + r1)

    return m.digest()


def get_default_server():

    if os.name != 'nt':
        for line in open(RESOLV_CONF):
            if line.startswith("nameserver"):
                return line.split()[1]
        raise ErrorMessage("No default server in %s" % RESOLV_CONF)
    else:
        raise ErrorMessage("Use linux")


def uid2ownername(uid, qtype):

    if qtype == 'OPENPGPKEY':
        applabel = '_openpgpkey'
    elif qtype == 'SMIMEA':
        applabel = '_smimecert'
    else:
        raise ErrorMessage('Invalid qtype (%s) for uid2owner' % qtype)
    localpart, rhs = uid.split('@')
    h = hashlib.sha256()
    h.update(localpart.encode('utf8'))
    owner = "{}.{}.{}".format(h.hexdigest()[0:56], applabel, rhs)
    if not owner.endswith('.'):
        owner = owner + '.'
    return owner
