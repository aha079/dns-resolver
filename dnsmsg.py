
import socket
import struct
import math
import random

from options import options
from common import ErrorMessage
from rdata import decode_rr, print_optrr
from name import name_from_wire_message, name_from_text, name_match
from dnsparam import qt, qc, rc
from util import randomize_case


class DNSquery:


    def __init__(self, qname, qtype, qclass):
        self.qname = qname
        if not options["emptyquestion"]:
            self.qname = name_from_text(self.qname)
        self.qtype = qtype
        self.qclass = qclass
        self.set_txid()
        self.set_flags()
        self.set_section_counts()
        self.mk_question()
        self.authority = b''
        self.additional = b''
        self.msglen_without_opt = 12 + len(self.question) + len(self.authority)
        self.mk_header_fields()
        self.assemble_message()
        self.msglen = len(self.message)

    def get_message(self):

        return self.message

    def get_length(self):

        return self.msglen

    def set_txid(self):
        if options["msgid"]:
            self.txid = options["msgid"]
        else:
            self.txid = random.randint(1, 65535)

    def set_flags(self):

        self.qr = 0
        self.opcode = 0
        self.aa = options["aa"]
        self.tc = 0
        self.rd = options["rd"]
        self.ra = 0
        self.z = 0
        self.ad = options["ad"]
        self.cd = options["cd"]
        self.rcode = 0

    def set_section_counts(self):
        if options["emptyquestion"]:
            self.qdcount = 0
        else:
            self.qdcount = 1
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0

    def mk_header_fields(self):
        self.packed_txid = struct.pack('!H', self.txid)
        flags = (self.qr << 15) + \
                (self.opcode << 11) + \
                (self.aa << 10) + \
                (self.tc << 9) + \
                (self.rd << 8) + \
                (self.ra << 7) + \
                (self.z << 6) + \
                (self.ad << 5) + \
                (self.cd << 4) + \
                self.rcode
        self.flags = struct.pack('!H', flags)
        self.packed_qdcount = struct.pack('!H', self.qdcount)
        self.packed_ancount = struct.pack('!H', self.ancount)
        self.packed_nscount = struct.pack('!H', self.nscount)
        self.packed_arcount = struct.pack('!H', self.arcount)

    def mk_question(self):

        if options["emptyquestion"]:
            self.question = b""
        else:
            wire_qname = self.qname.wire()
            self.question = wire_qname + struct.pack('!H', self.qtype) + \
                struct.pack('!H', self.qclass)

    def assemble_message(self):

        self.message = self.packed_txid + \
                       self.flags + \
                       self.packed_qdcount + \
                       self.packed_ancount + \
                       self.packed_nscount + \
                       self.packed_arcount + \
                       self.question + \
                       self.authority + \
                       self.additional

    def add_soa(self, serial):
        self.rd = 0
        self.nscount += 1
        self.packed_nscount = struct.pack('!H', self.nscount)
        rrname = b'\xc0\x0c'            
        rrtype = struct.pack('!H', qt.get_val("SOA"))
        rrclass = b'\x00\x01'
        ttl = b'\x00\x00\x00\x00'
        rdata = b'\x00' + \
                b'\x00' + \
                struct.pack('!I', serial) + \
                b'\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00' + \
                b'\x00\x00\x00\x00'
        rdlen = struct.pack('!H', len(rdata))
        self.authority = rrname + rrtype + rrclass + ttl + \
                         rdlen + rdata

    def add_tsig(self):

        self.tsig_rr = self.tsig.mk_request_tsig(self.txid, self.message)
        self.arcount += 1
        self.packed_arcount = struct.pack('!H', self.arcount)
        self.additional += self.tsig_rr

    def __repr__(self):
        return "<DNSquery: {},{},{}>".format(self.qname, self.qtype, self.qclass)


class DNSresponse:


    cnt_compression = 0
    sections = ["QUESTION", "ANSWER", "AUTHORITY", "ADDITIONAL"]
    print_section_bitmap = 0b1111          

    def __init__(self, family, query, msg, used_tcp=False, checkid=True):
        self.family = family
        self.query = query
        self.message = msg
        self.msglen = len(self.message)
        self.used_tcp = used_tcp
        self.decode_header(checkid)
    def decode_header(self, checkid=True):
        self.txid, flags, self.qdcount, self.ancount, self.nscount, \
            self.arcount = struct.unpack('!HHHHHH', self.message[:12])
        if checkid and (self.txid != self.query.txid):
            raise ErrorMessage("got response with id: %ld (expecting %ld)" %
                               (self.txid, self.query.txid))
        self.qr = flags >> 15
        self.opcode = (flags >> 11) & 0xf
        self.aa = (flags >> 10) & 0x1
        self.tc = (flags >> 9) & 0x1
        self.rd = (flags >> 8) & 0x1
        self.ra = (flags >> 7) & 0x1
        self.z = (flags >> 6) & 0x1
        self.ad = (flags >> 5) & 0x1
        self.cd = (flags >> 4) & 0x1
        self.rcode = (flags) & 0xf

    def print_ampratio(self):
        if self.family == socket.AF_INET:
            overhead = 42               
        elif self.family == socket.AF_INET6:
            overhead = 62               
        else:
            overhead = 0                 
        amp1 = (self.msglen * 1.0/self.query.msglen)
        w_qsize = self.query.msglen + overhead
        w_rsize = self.msglen + \
                  overhead * math.ceil(self.msglen/(1500.0-overhead))
        amp2 = w_rsize/w_qsize

        print(";; Size query=%d, response=%d, amp1=%.2f amp2=%.2f" %
              (self.query.msglen, self.msglen, amp1, amp2))

    def print_preamble(self):
        if options["do_0x20"]:
            print(";; 0x20-hack qname: %s" % self.query.qname)
        print(";; rcode=%d(%s), id=%d" %
              (self.rcode, rc.get_name(self.rcode), self.txid))
        print(";; qr=%d opcode=%d aa=%d tc=%d rd=%d ra=%d z=%d ad=%d cd=%d" %
              (self.qr,
               self.opcode,
               self.aa,
               self.tc,
               self.rd,
               self.ra,
               self.z,
               self.ad,
               self.cd))
        print(";; question=%d, answer=%d, authority=%d, additional=%d" %
              (self.qdcount, self.ancount, self.nscount, self.arcount))
        self.print_ampratio()

    def print_rr(self, rrname, ttl, rrtype, rrclass, rdata):

        print("%s\t%d\t%s\t%s\t%s" %
              (rrname.text(), ttl,
               qc.get_name(rrclass), qt.get_name(rrtype), rdata))
        return
    
    def decode_question(self, offset):

        domainname, offset = name_from_wire_message(self.message, offset)
        rrtype, rrclass = struct.unpack("!HH", self.message[offset:offset+4])
        offset += 4
        return (domainname, rrtype, rrclass, offset)

    def question_matched(self, qname, qtype, qclass):

        if self.rcode in [0, 3]:
            if (not name_match(qname, self.query.qname, options["do_0x20"])) \
                or (qtype != self.query.qtype) \
                or (qclass != self.query.qclass):
                print("*** WARNING: Answer didn't match question!\n")
        return

    def decode_sections(self, is_axfr=False):
        offset = 12                     
        answer_qname = None

        for (secname, rrcount) in zip(self.sections,
                                      [self.qdcount, self.ancount, self.nscount, self.arcount]):
            if rrcount and (not is_axfr):
                print("\n;; %s SECTION:" % secname)
            if secname == "QUESTION":
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, offset = \
                            self.decode_question(offset)
                    answer_qname = rrname
                    if is_axfr:
                        continue
                    print("%s\t%s\t%s" % (answer_qname.text(),
                                          qc.get_name(rrclass),
                                          qt.get_name(rrtype)))
                    self.question_matched(answer_qname, rrtype, rrclass)
            else:
                for _ in range(rrcount):
                    rrname, rrtype, rrclass, ttl, rdata, offset = \
                            decode_rr(self.message, offset, options["hexrdata"])
                    if is_axfr and (secname != "ANSWER"):
                        continue
                    elif rrtype == 41:
                        print_optrr(self.rcode, rrclass, ttl, rdata)
                    else:
                        self.print_rr(rrname, ttl, rrtype, rrclass, rdata)
        return rdata                    

    def print_all(self):

        self.print_preamble()
        self.decode_sections()

    def __repr__(self):
        return "<DNSresponse: {},{},{}>".format(
            self.query.qname, self.query.qtype, self.query.qclass)
