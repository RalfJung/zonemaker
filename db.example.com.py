from zone import *

# Our IP addresses; we have machine one and machine two.
one4 = A("172.16.254.1") # for each record type, there's a corresponding class with the same name
one6 = AAAA("2606:2800:220:6d:26bf:1447:1097:aa7")
one  = [one4, one6] # collect all addresses of this machine
two4 = A("172.16.254.2")
two  = [two4] # collext all addresses of this machine
# our mail servers
mail = [MX('mx', 10)] # this is first server name, then priority (as in plain DNS, lower numbers denote higher priorities)

# define a useful shorthand to store HTTPS keys via TLSA
def HTTPS(key):
    return TLSA(Protocol.TCP, 443, TLSA.Usage.EndEntity, TLSA.Selector.Full, TLSA.MatchingType.SHA256, key)

# setup TTLs by record type
TTLs = {
    '':     1*day,  # special value: default TTL
    'NX':   1*hour, # special value: TTL for NXDOMAIN replies
    'A':    1*hour, # for the rest, just use the type of the resource records
    'AAAA': 1*hour,
}

# Now to the actual zone: the header part should be fairly self-explanatory.
__zone__ = Zone('example.com.', serialfile = 'db.example.com.srl',
    mail = 'root@example.com.', NS = ['ns', 'ns.example.org.'], TTLs = TTLs,
    secondary_refresh = 6*hour, secondary_retry = 1*hour, secondary_expire = 7*day,
    # Here come the actual domains. Each takes records as argument, either individually or as lists.
    domains = {
        '@':            Name(one, mail, HTTPS('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')), # this will all all records from the list "one" and the list "mail" to this name
        'ns':           Name(one),
        'ipv4.ns':      Name(one4), # just a single record
        'ipv6.ns':      Name(one6),
        'mx' :          Name(two), # mail is handled by machine two
        'www':          Name(one, HTTPS('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')), # since this is python, we can define shorthands
        'lists':        Name(one, mail, HTTPS('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')), # this domain can both receive mail, and publishes its HTTPS key
        #
        'jabber':       Name(SRV(Protocol.TCP, 'xmpp-client', 'jabber.example.org.', port = 5222, prio = 0, weight = 5),  # forward jabber clients to jabber.example.org
                             SRV(Protocol.TCP, 'xmpp-server', 'jabber.example.org.', port = 5269, prio = 0, weight = 5)), # and similar for server-to-server connections
        #
        'orgstuff':     CName('example.org.'), # CNAMEs cannot be combined with other records
        #
        'sub1':         Delegation('ns.example.org.'), # this adds an NS record
        'sub2':         SecureDelegation('ns.example.com.', 12345, Algorithm.RSA_SHA256, Digest.SHA256, '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF'), # this adds an NS and a DS record
    })
