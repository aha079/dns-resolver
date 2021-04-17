import socket
import base64

from common import options, ErrorMessage, UsageError, dprint
from util import get_default_server, ip2ptr, uid2ownername



def parse_args(arglist):
    csv = 0
    qtype = "A"
    qclass = "IN"

    i = 0
    tsig = None

    for (i, arg) in enumerate(arglist):
        if arg == "-h":
            raise UsageError()

        elif arg.startswith("-p"):
            options["port"] = int(arg[2:])

        elif arg.startswith("-b"):
            options["srcip"] = arg[2:]

        elif arg == "+tcp":
            options["use_tcp"] = True
            
        elif arg == "+csv":
            options["use_csv"] = True

        elif arg == "+ignore":
            options["ignore"] = True

        elif arg == "+norecurse":
            options["rd"] = 0

        elif arg == "+emptyquestion":
            options["emptyquestion"] = True

        elif arg == "+generic":
            options["generic"] = True

        elif arg == "-4":
            options["af"] = socket.AF_INET

        elif arg == "-6":
            options["af"] = socket.AF_INET6

        elif arg == "-x":
            options["ptr"] = True

        else:
            break
    else:
        i += 1


    options["server"] = get_default_server()
    if options["use_csv"]:
        qname = arglist[i]
        csv=1
    elif options["emptyquestion"]:
        qname = None
    elif not arglist[i:]:
        qname = "."
        qtype = "NS"
    else:
        qname = arglist[i]

        if not options["do_zonewalk"]:
            if arglist[i+1:]:
                qtype = arglist[i+1].upper()
            if arglist[i+2:]:
                qclass = arglist[i+2].upper()

        if options["ptr"]:
            qname = ip2ptr(qname)
            qtype = "PTR"
            qclass = "IN"
        
        if not qname.endswith("."):
            qname += "."

    return (qname, qtype, qclass,csv)
