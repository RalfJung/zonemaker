import ipaddress

second = 1
minute = 60*second
hour = 60*minute
day = 24*hour

class Address:
    def __init__(self, IPv4 = None, IPv6 = None):
        self._IPv4 = None if IPv4 is None else ipaddress.IPv4Address(IPv4)
        self._IPv6 = None if IPv6 is None else ipaddress.IPv6Address(IPv6)
    
    def IPv4(self):
        return Address(IPv4 = self._IPv4)
    
    def IPv6(self):
        return Address(IPv6 = self._IPv6)

class Name:
    def __init__(self, address = None, MX = None, TCP = None, UDP = None):
        self._address = address

class Service:
    def __init__(self, SRV = None, TLSA=None):
        self._SRV = SRV
        self._TLSA = TLSA

class CName:
    def __init__(self, name):
        self._name = name

class Delegation():
    def __init__(self, NS, DS = None):
        pass

class Zone:
    def __init__(self, name, mail, NS,
                 secondary_refresh, secondary_retry, secondary_discard,
                 NX_TTL = None, A_TTL = None, other_TTL = None,
                 domains = []):
        assert other_TTL is not None
        self._NX_TTL = other_TTL if NX_TTL is None else NX_TTL
        self._A_TTL = other_TTL if A_TTL is None else A_TTL
        self._other_TTL = other_TTL
    
    def write(self, file):
        raise NotImplementedError()
