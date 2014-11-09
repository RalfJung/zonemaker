import re
from ipaddress import IPv4Address, IPv6Address
from typing import List, Dict, Any, Iterator, Tuple, Sequence


second = 1
minute = 60*second
hour = 60*minute
day = 24*hour
week = 7*day

TCP = 'tcp'
UDP = 'udp'

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

def column_widths(datas: Sequence, widths: Sequence[int]):
    assert len(datas) == len(widths)+1, "There must be as one more data points as widths"
    result = ""
    width_sum = 0
    for data, width in zip(datas, widths): # will *not* cover the last point
        result += str(data)+" " # add data point, and a minimal space
        width_sum += width
        if len(result) < width_sum: # add padding
            result += (width_sum - len(result))*" "
    # last data point
    return result+str(datas[-1])


## Record types
class A:
    def __init__(self, address: str) -> None:
        self._address = IPv4Address(address)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR(owner, 'A', self._address)


class AAAA:
    def __init__(self, address: str) -> None:
        self._address = IPv6Address(address)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR(owner, 'AAAA', self._address)


class MX:
    def __init__(self, name: str, prio: int = 10) -> None:
        self._priority = int(prio)
        self._name = check_hostname(name)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR(owner, 'MX', '{0} {1}'.format(self._priority, zone.abs_hostname(self._name)))


class SRV:
    def __init__(self, protocol: str, service: str, name: str, port: int, prio: int, weight: int) -> None:
        self._service = str(service)
        self._protocol = str(protocol)
        self._priority = int(prio)
        self._weight = int(weight)
        self._port = int(port)
        self._name = check_hostname(name)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR('_{0}._{1}.{2}'.format(self._service, self._protocol, owner), 'SRV',
                       '{0} {1} {2} {3}'.format(self._priority, self._weight, self._port, zone.abs_hostname(self._name)))


class TLSA:
    def __init__(self, protocol: str, port: int, key: str) -> None:
        # TODO: fix key stuff
        self._port = int(port)
        self._protocol = str(protocol)
        self._key = str(key)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR('_{0}._{1}.{2}'.format(self._port, self._protocol, owner), 'TLSA', self._key)


class CNAME:
    def __init__(self, name: str) -> None:
        self._name = check_hostname(name)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR(owner, 'CNAME', zone.abs_hostname(self._name))


class NS:
    def __init__(self, name: str) -> None:
        self._name = check_hostname(name)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR(owner, 'NS', zone.abs_hostname(self._name))


class DS:
    def __init__(self, key: str) -> None:
        # TODO: fix key stuff
        self._key = str(key)
    
    def generate_rr(self, owner: str, zone: 'Zone') -> Any:
        return zone.RR(owner, 'DS', self._key)

## Higher-level classes
class Name:
    def __init__(self, *records: List[Any]) -> None:
        self._records = records
    
    def generate_rrs(self, owner: str, zone: 'Zone') -> Iterator:
        for record in self._records:
            # this could still be a list
            if isinstance(record, list):
                for subrecord in record:
                    yield subrecord.generate_rr(owner, zone)
            else:
                yield record.generate_rr(owner, zone)


def CName(name: str) -> Name:
    return Name(CNAME(name))


def Delegation(name: str, key: str = None) -> Name:
    records = [NS(name)]
    if key is not None:
        records.append(DS(key))
    return Name(*records)


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
        return column_widths((self.abs_hostname(owner), time(TTL), recordType, data), (32, 8, 8))
    
    def abs_hostname(self, name):
        if name == '.' or name == '@':
            return self._name
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
        for name in self._NS:
            yield NS(name).generate_rr(self._name, self)
        # all the rest
        for name in sorted(self._domains.keys(), key=lambda s: list(reversed(s.split('.')))):
            for rr in self._domains[name].generate_rrs(name, self):
                yield rr
    
    def write(self) -> None:
        with open(self._dbfile, 'w') as f:
            for rr in self.generate_rrs():
                f.write(rr+"\n")
                print(rr)
