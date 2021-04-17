import socket
import struct
import time
import base64

from common import options
from dnsparam import qt, rc, sshfp_alg, sshfp_fptype, dnssec_alg, dnssec_digest
from name import name_from_wire_message
from util import hexdump, bytes2escapedstring, backslash_txt, printables_txt, packed2int


def print_optrr(rcode, rrclass, ttl, rdata):

    packed_ttl = struct.pack('!I', ttl)
    ercode_hi, version, z = struct.unpack('!BBH', packed_ttl)
    ercode = (ercode_hi << 4) | rcode
    flags = []
    if z & 0x8000:
        flags.append("do")                 
    print(";; OPT: edns_version=%d, udp_payload=%d, flags=%s, ercode=%d(%s)" %
          (version, rrclass, ' '.join(flags), ercode, rc.get_name(ercode)))
    blob = rdata
    while blob:
        ocode, olen = struct.unpack('!HH', blob[:4])
        odesc = edns_opt.get(ocode, "Unknown")
        print(";; OPT code=%d (%s), length=%d" % (ocode, odesc, olen))
        data_raw = blob[4:4+olen]
        data_out = hexdump(data_raw)
        if ocode == 3:                           
            human_readable_data = ''
            try:
                human_readable_data = data_raw.decode('ascii')
            except (TypeError, UnicodeDecodeError):
                pass
            if human_readable_data:
                data_out = '%s (%s)' % (data_out, human_readable_data)
        elif ocode in [5, 6, 7]:                
            data_out = ' '.join([str(x) for x in data_raw])
        elif ocode == 15:                       
            info_code, = struct.unpack('!H', data_raw[0:2])
            extra_text = data_raw[2:]
            info_code_desc = extended_error.get(info_code, "Unknown")
            data_out = "{} ({})".format(info_code, info_code_desc)
            if extra_text:
                data_out += " :{}".format(extra_text)
        print(";; DATA: %s" % data_out)
        blob = blob[4+olen:]


def generic_rdata_encoding(rdata, rdlen):

    return r"\# %d %s" % (rdlen, hexdump(rdata))


def decode_txt_rdata(rdata, rdlen):
    
    txtstrings = []
    position = 0
    while position < rdlen:
        slen, = struct.unpack('B', rdata[position:position+1])
        s = rdata[position+1:position+1+slen]
        txtstring = '"{}"'.format(
            bytes2escapedstring(s, backslash_txt, printables_txt))
        txtstrings.append(txtstring)
        position += 1 + slen
    return ' '.join(txtstrings)


def decode_soa_rdata(pkt, offset, rdlen):

    d, offset = name_from_wire_message(pkt, offset)
    mname = d.text()
    d, offset = name_from_wire_message(pkt, offset)
    rname = d.text()
    serial, refresh, retry, expire, min = \
            struct.unpack("!IiiiI", pkt[offset:offset+20])
    return "%s %s %d %d %d %d %d" % \
           (mname, rname, serial, refresh, retry, expire, min)


def decode_srv_rdata(pkt, offset):

    priority, weight, port = struct.unpack("!HHH", pkt[offset:offset+6])
    d, offset = name_from_wire_message(pkt, offset+6)
    target = d.text()
    return "%d %d %d %s" % (priority, weight, port, target)


def decode_naptr_rdata(pkt, offset, rdlen):

    param = {}
    order, pref = struct.unpack('!HH', pkt[offset:offset+4])
    position = offset+4
    for name in ["flags", "svc", "regexp"]:
        slen, = struct.unpack('B', pkt[position])
        s = pkt[position+1:position+1+slen]
        param[name] = '"%s"' % s.replace('\\', '\\\\')
        position += (1+slen)
    d, _ = name_from_wire_message(pkt, position)
    replacement = d.text()
    return "%d %d %s %s %s %s" % (order, pref, param["flags"], param["svc"],
                                  param["regexp"], replacement)


def decode_ipseckey_rdata(pkt, offset, rdlen):

    prec, gwtype, alg = struct.unpack('BBB', pkt[offset:offset+3])
    position = offset+3
    if gwtype == 0:                           
        gw = "."
    elif gwtype == 1:                          
        gw = socket.inet_ntop(socket.AF_INET, pkt[position:position+4])
        position += 4
    elif gwtype == 2:                          
        gw = socket.inet_ntop(socket.AF_INET6, pkt[position:position+16])
        position += 16
    elif gwtype == 3:                          
        d, position = name_from_wire_message(pkt, position)
        gw = d.text()
    if alg == 0:                               
        pubkey = ""
    else:
        pubkeylen = rdlen - (position - offset)
        pubkey = base64.standard_b64encode(pkt[position:position+pubkeylen]).decode('ascii')
    return "{} {} {} {} {}".format(prec, gwtype, alg, gw, pubkey)


def decode_dnskey_rdata(pkt, offset, rdlen):

    flags, proto, alg = struct.unpack('!HBB', pkt[offset:offset+4])
    pubkey = pkt[offset+4:offset+rdlen]
    if options['DEBUG']:
        zonekey = (flags >> 8) & 0x1          
        sepkey = flags & 0x1                  
        keytype = None
        if proto == 3:
            if zonekey and sepkey:
                keytype = "KSK"
            elif zonekey:
                keytype = "ZSK"
        if keytype:
            comments = "%s, " % keytype
        comments += "proto=%s, alg=%s" % \
                   (dnssec_proto[proto], dnssec_alg[alg])
        if alg in [5, 7, 8, 10]:              
            if pubkey[0] == '\x00':   
                elen, = struct.unpack('!H', pubkey[1:3])
                exponent = packed2int(pubkey[1:1+elen])
                modulus_len = len(pubkey[1+elen:]) * 8
            else:                     
                elen, = struct.unpack('B', pubkey[0:1])
                exponent = packed2int(pubkey[1:1+elen])
                modulus_len = len(pubkey[1+elen:]) * 8
            comments = comments + ", e=%d modulus_size=%d" % \
                       (exponent, modulus_len)
        elif alg in [3, 6]:                
            pass
        elif alg in [13, 14]:                 
            comments = comments + ", size=%d" % (len(pubkey) * 8)
        result = "{} {} {} {} ; {}".format(
            flags, proto, alg,
            base64.standard_b64encode(pubkey).decode('ascii'), comments)
    else:
        result = "{} {} {} {}".format(
            flags, proto, alg,
            base64.standard_b64encode(pubkey).decode('ascii'))
    return result


def decode_ds_rdata(pkt, offset, rdlen):

    keytag, alg, digesttype = struct.unpack('!HBB', pkt[offset:offset+4])
    digest = hexdump(pkt[offset+4:offset+rdlen])
    if options['DEBUG']:
        result = "%d %d(%s) %d(%s) %s" % \
                 (keytag, alg, dnssec_alg[alg], digesttype,
                  dnssec_digest[digesttype], digest)
    else:
        result = "%d %d %d %s" % (keytag, alg, digesttype, digest)
    return result


def decode_rrsig_rdata(pkt, offset, rdlen):
    end_rdata = offset + rdlen
    type_covered, alg, labels, orig_ttl, sig_exp, sig_inc, keytag = \
          struct.unpack('!HBBIIIH', pkt[offset:offset+18])
    sig_exp_text = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_exp))
    sig_inc_text = time.strftime("%Y%m%d%H%M%S", time.gmtime(sig_inc))
    d, offset = name_from_wire_message(pkt, offset+18)
    signer_name = d.text()
    signature = pkt[offset:end_rdata]
    retval = "{} {} {} {} {} {} {} {} {}".format(
        qt.get_name(type_covered), alg, labels, orig_ttl,
        sig_exp_text, sig_inc_text, keytag, signer_name,
        base64.standard_b64encode(signature).decode('ascii'))
    if options['DEBUG']:
        sig_validity = "%.2fd" % ((sig_exp - sig_inc) / 86400.0)
        retval += " ; sigsize=%d, validity=%s" % \
            (len(signature) * 8, sig_validity)
    return retval


def decode_typebitmap(windownum, bitmap):

    rrtypelist = []
    for (charpos, c) in enumerate(bitmap):
        for i in range(8):
            isset = (c << i) & 0x80
            if isset:
                bitpos = (256 * windownum) + (8 * charpos) + i
                rrtypelist.append(qt.get_name(bitpos))
    return rrtypelist


def decode_nsec_rdata(pkt, offset, rdlen):

    end_rdata = offset + rdlen
    d, offset = name_from_wire_message(pkt, offset)
    nextrr = d.text()
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    return "%s %s" % (nextrr, ' '.join(rrtypelist))


def decode_nsec3param_rdata(rdata):
 
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        rdata[:5])
    salt = hexdump(rdata[5:5+saltlen])
    result = "%d %d %d %s" % (hashalg, flags, iterations, salt)
    return result


def decode_nsec3_rdata(pkt, offset, rdlen):

    b32_to_ext_hex = bytes.maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
                                     b'0123456789ABCDEFGHIJKLMNOPQRSTUV')

    end_rdata = offset + rdlen
    hashalg, flags, iterations, saltlen = struct.unpack('!BBHB',
                                                        pkt[offset:offset+5])
    salt = hexdump(pkt[offset+5:offset+5+saltlen])
    offset += (5 + saltlen)
    hashlen, = struct.unpack('!B', pkt[offset:offset+1])
    offset += 1

    hashed_next_owner = base64.b32encode(pkt[offset:offset+hashlen])
    hashed_next_owner = hashed_next_owner.translate(b32_to_ext_hex).decode()
    offset += hashlen
    type_bitmap = pkt[offset:end_rdata]
    p = type_bitmap
    rrtypelist = []
    while p:
        windownum, winlen = struct.unpack('BB', p[0:2])
        bitmap = p[2:2+winlen]
        rrtypelist += decode_typebitmap(windownum, bitmap)
        p = p[2+winlen:]
    rrtypes = ' '.join(rrtypelist)
    result = "%d %d %d %s %s %s" % \
             (hashalg, flags, iterations, salt, hashed_next_owner, rrtypes)
    return result


def decode_caa_rdata(rdata):
    """decode CAA rdata: TLSA rdata: flags(1), tag-length, tag, value;
       see RFC 6844"""
    flags, taglen = struct.unpack("BB", rdata[0:2])
    tag = rdata[2:2+taglen]
    value = rdata[2+taglen:]
    return "{} {} \"{}\"".format(flags, tag.decode(), value.decode())


def decode_rr(pkt, offset, hexrdata):
    """ Decode a resource record, given DNS packet and offset"""

    orig_offset = offset
    domainname, offset = name_from_wire_message(pkt, offset)
    rrtype, rrclass, ttl, rdlen = \
            struct.unpack("!HHIH", pkt[offset:offset+10])
    offset += 10
    rdata = pkt[offset:offset+rdlen]
    if hexrdata:
        rdata = hexdump(rdata)
    elif options["generic"]:
        rdata = generic_rdata_encoding(rdata, rdlen)
    elif rrtype == 1:                                        # A
        rdata = socket.inet_ntop(socket.AF_INET, rdata)
    elif rrtype in [2, 5, 12, 39]:                           # NS, CNAME, PTR
        rdata, _ = name_from_wire_message(pkt, offset)       # DNAME
        rdata = rdata.text()
    elif rrtype == 6:                                        # SOA
        rdata = decode_soa_rdata(pkt, offset, rdlen)
    elif rrtype == 15:                                       # MX
        mx_pref, = struct.unpack('!H', pkt[offset:offset+2])
        rdata, _ = name_from_wire_message(pkt, offset+2)
        rdata = "%d %s" % (mx_pref, rdata.text())
    elif rrtype in [16, 99]:                                 # TXT, SPF
        rdata = decode_txt_rdata(rdata, rdlen)
    elif rrtype == 28:                                       # AAAA
        rdata = socket.inet_ntop(socket.AF_INET6, rdata)
    elif rrtype == 33:                                       # SRV
        rdata = decode_srv_rdata(pkt, offset)
    elif rrtype == 41:                                       # OPT
        pass
    elif rrtype in [43, 59, 32769]:                          # [C]DS, DLV
        rdata = decode_ds_rdata(pkt, offset, rdlen)
    elif rrtype == 45:                                       # IPSECKEY
        rdata = decode_ipseckey_rdata(pkt, offset, rdlen)
    elif rrtype in [46, 24]:                                 # RRSIG, SIG
        rdata = decode_rrsig_rdata(pkt, offset, rdlen)
    elif rrtype == 47:                                       # NSEC
        rdata = decode_nsec_rdata(pkt, offset, rdlen)
    elif rrtype in [48, 25, 60]:                             # [C]DNSKEY, KEY
        rdata = decode_dnskey_rdata(pkt, offset, rdlen)
    elif rrtype == 50:                                       # NSEC3
        rdata = decode_nsec3_rdata(pkt, offset, rdlen)
    elif rrtype == 51:                                       # NSEC3PARAM
        rdata = decode_nsec3param_rdata(rdata)
    elif rrtype == 257:                                      # CAA
        rdata = decode_caa_rdata(rdata)
    else:                                                    # use RFC 3597
        rdata = generic_rdata_encoding(rdata, rdlen)
    offset += rdlen
    return (domainname, rrtype, rrclass, ttl, rdata, offset)
