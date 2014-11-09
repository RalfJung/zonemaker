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

def abs_hostname(name: str, root: str = None) -> str:
    if name.endswith('.'):
        return name
    if root is None:
        raise Exception("Name {0} was expected to be absolute, but it is not".format(name))
    if not root.endswith('.'):
        raise Exception("Root {0} was expected to be absolute, but it is not".format(name))
    return name+"."+root

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
        self._IPv4 = None if IPv4 is None else IPv4Address(IPv4)
        self._IPv6 = None if IPv6 is None else IPv6Address(IPv6)
    
    def IPv4(self):
        return Address(IPv4 = self._IPv4)
    
    def IPv6(self):
        return Address(IPv6 = self._IPv6)

class Name:
    def __init__(self, address: Address = None, MX: List = None,
                 TCP: Dict[int, Any] = None, UDP: Dict[int, Any] = None) -> None:
        self._address = address

class Service:
    def __init__(self, SRV: str = None, TLSA: str=None) -> None:
        self._SRV = None if SRV is None else check_hostname(SRV)
        self._TLSA = TLSA

class CName:
    def __init__(self, name: str) -> None:
        self._name = check_hostname(name)

class Delegation():
    def __init__(self, NS: str, DS: str = None) -> None:
        pass

class RR():
    def __init__(self, owner: str, TTL: int, recordType: str, data: str) -> None:
        assert owner.endswith('.') # users have to make this absolute first
        self._owner = owner
        self._TTL = TTL
        self._recordType = recordType
        self._data = data
    
    def __str__(self) -> str:
        return "{0}\t{1}\t{2}\t{3}".format(self._owner, self._TTL, self._recordType, self._data)

class Zone:
    def __init__(self, name: str, mail: str, NS: List[str],
                 secondary_refresh: int, secondary_retry: int, secondary_expire: int,
                 NX_TTL: int = None, A_TTL: int = None, other_TTL: int = None,
                 domains: Dict[str, Any] = {}) -> None:
        self._name = check_hostname(name)
        if not mail.endswith('.'): raise Exception("Mail must be absolute, end with a dot")
        atpos = mail.find('@')
        if atpos < 0 or atpos > mail.find('.'): raise Exception("Mail must contain an @ before the first dot")
        self._mail = check_hostname(mail.replace('@', '.', 1))
        self._NS = list(map(check_hostname, NS))
        
        self._refresh = secondary_refresh
        self._retry = secondary_retry
        self._expire = secondary_expire
        
        assert other_TTL is not None
        self._NX_TTL = other_TTL if NX_TTL is None else NX_TTL
        self._A_TTL = other_TTL if A_TTL is None else A_TTL
        self._other_TTL = other_TTL
    
    def generate_rrs(self) -> Iterator[RR]:
        serial = -1
        yield (RR(abs_hostname(self._name), self._other_TTL, 'SOA',
                  '{NS} {mail} ({serial} {refresh} {retry} {expire} {NX_TTL})'.format(
                      NS=self._NS[0], mail=self._mail, serial=serial,
                      refresh=time(self._refresh), retry=time(self._retry), expire=time(self._expire),
                      NX_TTL=time(self._NX_TTL))
                  ))
    
    def write(self, file:Any) -> None:
        for rr in self.generate_rrs():
            print(rr)
