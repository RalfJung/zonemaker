import re
from ipaddress import IPv4Address, IPv6Address
from typing import List, Dict, Any, Iterator


second = 1
minute = 60*second
hour = 60*minute
day = 24*hour
week = 7*day

def check_hostname(name: str) -> str:
    # check hostname for validity
    label = r'[a-zA-Z90-9]([a-zA-Z90-9-]{0,61}[a-zA-Z90-9])?' # must not start or end with hyphen
    pattern = r'^{0}(\.{0})*\.?'.format(label)
    if re.match(pattern, name):
        return name
    raise Exception(name+" is not a valid hostname")

def time(time: int) -> str:
    if time == 0:
        return "0"
    elif time % week == 0:
        return str(time//week)+"w"
    elif time % day == 0:
        return str(time//day)+"d"
    elif time % hour == 0:
        return str(time//hour)+"h"
    elif time % minute == 0:
        return str(time//minute)+"m"
    else:
        return str(time)

class Address:
    # mypy does not know about the ipaddress types, so leave this class unannotated for now
    def __init__(self, IPv4 = None, IPv6 = None) -> None:
        if IPv4 is None and IPv6 is None:
            raise Exception("There has to be at least one valid address!")
        self._IPv4 = None if IPv4 is None else IPv4Address(IPv4)
        self._IPv6 = None if IPv6 is None else IPv6Address(IPv6)
    
    def IPv4(self):
        return Address(IPv4 = self._IPv4)
    
    def IPv6(self):
        return Address(IPv6 = self._IPv6)
    
    def generate_rrs(self, owner: str, zone: 'Zone') -> Iterator:
        if self._IPv4 is not None:
            yield zone.RR(owner, 'A', self._IPv4)
        if self._IPv6 is not None:
            yield zone.RR(owner, 'AAAA', self._IPv6)

class Name:
    def __init__(self, address: Address = None, MX: List = None,
                 TCP: Dict[int, Any] = None, UDP: Dict[int, Any] = None) -> None:
        self._address = address
    
    def generate_rrs(self, owner: str, zone: 'Zone') -> Iterator:
        if self._address is not None:
            for rr in self._address.generate_rrs(owner, zone):
                yield rr
        # TODO

class Service:
    def __init__(self, SRV: str = None, TLSA: str=None) -> None:
        self._SRV = None if SRV is None else check_hostname(SRV)
        self._TLSA = TLSA

class CName:
    def __init__(self, name: str) -> None:
        self._name = check_hostname(name)
    
    def generate_rrs(self, owner: str, zone: 'Zone') -> Iterator:
        yield zone.RR(owner, 'CNAME', zone.abs_hostname(self._name))

class Delegation():
    def __init__(self, NS: str, DS: str = None) -> None:
        self._NS = NS
        self._DS = DS
    
    def generate_rrs(self, owner: str, zone: 'Zone') -> Iterator:
        yield zone.RR(owner, 'NS', zone.abs_hostname(self._NS))
        # TODO DS

class Zone:
    def __init__(self, name: str, serialfile: str, dbfile: str, mail: str, NS: List[str],
                 secondary_refresh: int, secondary_retry: int, secondary_expire: int,
                 NX_TTL: int = None, A_TTL: int = None, other_TTL: int = None,
                 domains: Dict[str, Any] = {}) -> None:
        self._serialfile = serialfile
        self._dbfile = dbfile
        
        if not name.endswith('.'): raise Exception("Expected an absolute hostname")
        self._name = check_hostname(name)
        if not mail.endswith('.'): raise Exception("Mail must be absolute, end with a dot")
        atpos = mail.find('@')
        if atpos < 0 or atpos > mail.find('.'): raise Exception("Mail must contain an @ before the first dot")
        self._mail = check_hostname(mail.replace('@', '.', 1))
        self._NS = list(map(check_hostname, NS))
        
        self._refresh = secondary_refresh
        self._retry = secondary_retry
        self._expire = secondary_expire
        
        if other_TTL is None: raise Exception("Must give other_TTL")
        self._NX_TTL = NX_TTL
        self._A_TTL = self._AAAA_TTL = A_TTL
        self._other_TTL = other_TTL
        
        self._domains = domains
    
    def RR(self, owner: str, recordType: str, data: str) -> str:
        '''generate given RR, in textual representation'''
        assert re.match(r'^[A-Z]+$', recordType), "got invalid record type"
        # figure out TTL
        attrname = "_"+recordType+"_TTL"
        TTL = None # type: int
        if hasattr(self, attrname):
            TTL = getattr(self, attrname)
        if TTL is None:
            TTL = self._other_TTL
        # be done
        return "{0}\t{1}\t{2}\t{3}".format(self.abs_hostname(owner), TTL, recordType, data)
    
    def abs_hostname(self, name):
        if name.endswith('.'):
            return name
        return name+"."+self._name
    
    def inc_serial(self) -> int:
        # get serial
        cur_serial = 0
        try:
            with open(self._serialfile) as f:
                cur_serial = int(f.read())
        except FileNotFoundError:
            pass
        # increment serial
        cur_serial += 1
        # save serial
        with open(self._serialfile, 'w') as f:
            f.write(str(cur_serial))
        # be done
        return cur_serial
    
    def generate_rrs(self) -> Iterator:
        # SOA record
        serial = self.inc_serial()
        yield self.RR(self._name, 'SOA',
                      ('{NS} {mail} ({serial} {refresh} {retry} {expire} {NX_TTL}) ; '+
                      '(serial refresh retry expire NX_TTL)').format(
                          NS=self.abs_hostname(self._NS[0]), mail=self._mail, serial=serial,
                          refresh=time(self._refresh), retry=time(self._retry), expire=time(self._expire),
                          NX_TTL=time(self._NX_TTL))
                      )
        # NS records
        for ns in self._NS:
            yield self.RR(self._name, 'NS', self.abs_hostname(ns))
        
        # all the rest
        for name in sorted(self._domains.keys(), key=lambda s: list(reversed(s.split('.')))):
            for rr in self._domains[name].generate_rrs(name, self):
                yield rr
    
    def write(self) -> None:
        for rr in self.generate_rrs():
            print(rr)
