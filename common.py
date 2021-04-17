
import os
import sys
import socket

PROGNAME       = os.path.basename(sys.argv[0])
PROGDESC       = "DNS query Python"
VERSION        = "1"

PYVERSION      = sys.version_info.major
RESOLV_CONF    = "/etc/resolv.conf"    # where to find default server
DEFAULT_PORT   = 53
DEFAULT_PORT_TLS = 853
ITIMEOUT       = 0.5                   # initial timeout in seconds
RETRIES        = 3                     # how many times to try
TIMEOUT_MAX    = 10
BUFSIZE        = 65535                 # socket read/write buffer size
EDNS0_UDPSIZE  = 4096
PAD_BLOCK_SIZE = 128
DEFAULT_URL    = 'www.google.com'

class Stats:

    compression_cnt = 0


USAGE_STRING = """\
{0} ({1}), version {2}

Usage: {0} [list of options] <qname> [<qtype>] [<qclass>]
       {0} @server +walk <zone>
Options:
        -h                        print program usage information
        +csv                      use csv for resolve dns
        -pNN                      use port NN (default is port 53)
        -bIP                      use IP as source IP address
        +tcp                      send query via TCP
        +ignore                   ignore truncation (don't retry with TCP)
        +norecurse                set rd bit to 0 (recursion not desired)
        +emptyquestion            send an empty question section
        -4                        perform queries using IPv4
        -6                        perform queries using IPv6
        -x                        reverse lookup of IPv4/v6 address in qname
""".format(PROGNAME, PROGDESC, VERSION)


def dprint(input):
    if options["DEBUG"]:
        print(";; DEBUG: %s" % input)
    return


class ErrorMessage(Exception):

    name = PROGNAME
    def __str__(self):
        val = Exception.__str__(self)
        if val:
            return '%s: %s' % (self.name, val)
        else:
            return ''


class UsageError(ErrorMessage):

    def __str__(self):
        val = ErrorMessage.__str__(self)
        if val:
            return '%s\n%s' % (val, USAGE_STRING)
        else:
            return USAGE_STRING


def excepthook(exc_type, exc_value, exc_traceback):

    if issubclass(exc_type, ErrorMessage):
        _ = sys.stderr.write("{}\n".format(exc_value))
    else:
        sys.__excepthook__(exc_type, exc_value, exc_traceback)


class Counter:

    def __init__(self):
        self.max = None
        self.min = None
        self.count = 0
        self.total = 0
    def addvalue(self, val):
        if self.max == None:
            self.max = val
            self.min = val
        else:
            self.max = max(self.max, val)
            self.min = min(self.min, val)
        self.count += 1
        self.total += val
    def average(self):
        return (1.0 * self.total)/self.count


options = dict(
    DEBUG=False,
    server=None,
    port=DEFAULT_PORT,
    srcip=None,
    use_tcp=False,
    ignore=False,
    aa=0,
    ad=0,
    cd=0,
    rd=1,
    use_edns=False,
    edns_version=0,
    edns_flags=0,
    ednsopt=[],
    bufsize=EDNS0_UDPSIZE,
    dnssec_ok=0,
    serial=None,                                   
    hexrdata=False,
    do_zonewalk=False,
    nsid=False,
    expire=False,
    cookie=False,
    subnet=None,
    chainquery=False,
    padding=False,
    use_csv=False,
    padding_blocksize=None,
    do_0x20=False,
    ptr=False,
    emptyquestion=False,
    generic=False,                                  
    af=socket.AF_UNSPEC,
    do_tsig=False,
    tsig=None,                                      
    tsig_sigtime=None,
    unsigned_messages="",
    msgid=None,
    tls=False,
    tls_auth=False,
    tls_port=DEFAULT_PORT_TLS,
    tls_fallback=False,
    tls_hostname=None,
    have_https=False,
    https=False,
    https_url=DEFAULT_URL,
)
