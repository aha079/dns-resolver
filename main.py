"""
main function.

"""

import sys
import socket
import time
import pandas as pd
from common import options, excepthook, dprint, Stats, ErrorMessage, UsageError, ITIMEOUT, RETRIES
from options import parse_args
from util import random_init, get_socketparams, is_multicast
from dnsparam import qc, qt
from dnsmsg import DNSquery, DNSresponse
from query import send_request_udp, send_request_tcp



def main(args):

    """ main function"""

    sys.excepthook = excepthook
    random_init()

    qname, qtype, qclass, csv = parse_args(args[1:])

    try:
        qtype_val = qt.get_val(qtype)
    except KeyError:
        raise UsageError("ERROR: invalid query type: {}\n".format(qtype))

    try:
        qclass_val = qc.get_val(qclass)
    except KeyError:
        raise UsageError("ERROR: invalid query class: {}\n".format(qclass))
    if csv==0:
        query = DNSquery(qname, qtype_val, qclass_val)
        try:
            server_addr, port, family, _ = \
                         get_socketparams(options["server"], options["port"],
                                          options["af"], socket.SOCK_DGRAM)
        except socket.gaierror as e:
            raise ErrorMessage("bad server: %s (%s)" % (options["server"], e))
        
        request = query.get_message()
    else:
        doc = pd.read_csv(qname)
        X = doc.iloc[:,0].values.astype(str)
        print(len(X))
        for i in X:
            print(i)
            i += "."
            query = DNSquery(i, qtype_val, qclass_val)
            try:
                server_addr, port, family, _ = \
                             get_socketparams(options["server"], options["port"],
                                              options["af"], socket.SOCK_DGRAM)
            except socket.gaierror as e:
                raise ErrorMessage("bad server: %s (%s)" % (options["server"], e))
            request = query.get_message()
            (responsepkt, responder_addr) = \
                      send_request_udp(request, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
            response = DNSresponse(family, query, responsepkt)
            doc["get"] = str(response.decode_sections())
        doc.to_csv(qname,index=False)
    response = None

    if not options["use_tcp"]:
        t1 = time.time()
        (responsepkt, responder_addr) = \
                      send_request_udp(request, server_addr, port, family,
                                       ITIMEOUT, RETRIES)
        t2 = time.time()
        if not responsepkt:
            raise ErrorMessage("No response from server")
        response = DNSresponse(family, query, responsepkt)
        if not response.tc:
            print(";; UDP response from %s, %d bytes, in %.3f sec" %
                  (responder_addr, response.msglen, (t2-t1)))
            if not is_multicast(server_addr) and \
               server_addr != "0.0.0.0" and responder_addr[0] != server_addr:
                print("WARNING: Response from unexpected address %s" %
                      responder_addr[0])

    if options["use_tcp"] or (response and response.tc) \
       or (options["tls"] and options["tls_fallback"] and not response):
        if response and response.tc:
            if options["ignore"]:
                print(";; UDP Response was truncated.")
            else:
                print(";; UDP Response was truncated. Retrying using TCP ...")
        if options["tls"] and options["tls_fallback"] and not response:
            print(";; TLS fallback to TCP ...")
        if not options["ignore"]:
            t1 = time.time()
            responsepkt = send_request_tcp(request, server_addr, port, family)
            t2 = time.time()
            response = DNSresponse(family, query, responsepkt)
            print(";; TCP response from %s, %d bytes, in %.3f sec" %
                  ((server_addr, port), response.msglen, (t2-t1)))

    response.print_all()
    dprint("Compression pointer dereferences=%d" % Stats.compression_cnt)

    return response.rcode
    
    
if __name__ == '__main__':
    sys.exit(main(sys.argv))
