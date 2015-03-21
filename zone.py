# Copyright (c) 2014, Ralf Jung <post@ralfj.de>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer. 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import re, datetime
#from typing import *


second = 1
minute = 60*second
hour = 60*minute
day = 24*hour
week = 7*day

REGEX_label = r'[a-zA-Z90-9]([a-zA-Z90-9-]{0,61}[a-zA-Z90-9])?' # max. 63 characters; must not start or end with hyphen
REGEX_ipv4  = r'^\d{1,3}(\.\d{1,3}){3}$'
REGEX_ipv6  = r'^[a-fA-F0-9]{1,4}(:[a-fA-F0-9]{1,4}){7}$'

def check_label(label: str) -> str:
    label = str(label)
    pattern = r'^{0}$'.format(REGEX_label)
    if re.match(pattern, label):
        return label
    raise Exception(label+" is not a valid label")

def check_hostname(name: str) -> str:
    name = str(name)
    # check hostname for validity
    pattern = r'^{0}(\.{0})*\.?$'.format(REGEX_label)
    if re.match(pattern, name):
        return name
    raise Exception(name+" is not a valid hostname")

def check_hex(data: str) -> str:
    data = str(data)
    if re.match('^[a-fA-F0-9]+$', data):
        return data
    raise Exception(data+" is not valid hex data")

def check_base64(data: str) -> str:
    data = str(data)
    if re.match('^[a-zA-Z0-9+/=]+$', data):
        return data
    raise Exception(data+" is not valid hex data")


def check_ipv4(address: str) -> str:
    address = str(address)
    if re.match(REGEX_ipv4, address):
        return address
    raise Exception(address+" is not a valid IPv4 address")

def check_ipv6(address: str) -> str:
    address = str(address)
    if re.match(REGEX_ipv6, address):
        return address
    raise Exception(address+" is not a valid IPv6 address")

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

def column_widths(datas: 'Sequence', widths: 'Sequence[int]'):
    assert len(datas) == len(widths)+1, "There must be one more data points as there are widths"
    result = ""
    width_sum = 0
    for data, width in zip(datas, widths): # will *not* cover the last point
        result += str(data)+" " # add data point, and a minimal space
        width_sum += width
        if len(result) < width_sum: # add padding
            result += (width_sum - len(result))*" "
    # last data point
    return result+str(datas[-1])


## Enums
class Protocol:
    TCP = 'tcp'
    UDP = 'udp'

class Algorithm:
    RSA_SHA256 = 8

class Digest:
    SHA1 = 1
    SHA256 = 2


## Resource records
class RR:
    def __init__(self, path, recordType, data):
        '''<path> can be relative or absolute.'''
        assert re.match(r'^[A-Z]+$', recordType), "got invalid record type"
        self.path = path
        self.recordType = recordType
        self.data = data
        self.TTL = None
    
    def mapPath(self, f):
        '''Run the path through f. Returns self, for nicer chaining.'''
        self.path = f(self.path)
        return self
    
    def relativize(self, root):
        def _relativize(path):
            if path == '' or root == '':
                raise Exception("Empty domain name is not valid")
            if path == '@':
                return root
            if root == '@' or path.endswith('.'):
                return path
            return path+"."+root
        return self.mapPath(_relativize)
    
    def mapTTL(self, f):
        '''Run the current TTL and the recordType through f.'''
        self.TTL = f(self.TTL, self.recordType)
        return self
    
    def __str__(self):
        return column_widths((self.path, time(self.TTL), self.recordType, self.data), (8*3, 8, 8))

## Record types
class A:
    def __init__(self, address: str) -> None:
        self._address = check_ipv4(address)
    
    def generate_rr(self):
        return RR('@', 'A', self._address)


class AAAA:
    def __init__(self, address: str) -> None:
        self._address = check_ipv6(address)
    
    def generate_rr(self):
        return RR('@', 'AAAA', self._address)


class MX:
    def __init__(self, name: str, prio: int = 10) -> None:
        self._priority = int(prio)
        self._name = check_hostname(name)
    
    def generate_rr(self):
        return RR('@', 'MX', '{0} {1}'.format(self._priority, self._name))


class TXT:
    def __init__(self, text: str) -> None:
        # test for bad characters
        for c in ('\n', '\r', '\t'):
            if c in text:
                raise Exception("TXT record {0} contains invalid character")
        # escape text
        for c in ('\\', '\"'):
            text = text.replace(c, '\\'+c)
        self._text = text
    
    def generate_rr(self):
        return RR('@', 'TXT', '"{0}"'.format(self._text))


class DKIM(TXT): # helper class to treat DKIM more antively
    class Version:
        DKIM1 = "DKIM1"
    
    class Algorithm:
        RSA = "rsa"
    
    def __init__(self, selector, version, alg, key):
        self._selector = check_label(selector)
        version = check_label(version)
        alg = check_label(alg)
        key = check_base64(key)
        super().__init__("v={0}; k={1}; p={2}".format(version, alg, key))
    
    def generate_rr(self):
        return super().generate_rr().relativize('{}._domainkey'.format(self._selector))


class SRV:
    def __init__(self, protocol: str, service: str, name: str, port: int, prio: int, weight: int) -> None:
        self._service = check_label(service)
        self._protocol = check_label(protocol)
        self._priority = int(prio)
        self._weight = int(weight)
        self._port = int(port)
        self._name = check_hostname(name)
    
    def generate_rr(self):
        return RR('_{}._{}'.format(self._service, self._protocol), 'SRV',
                       '{} {} {} {}'.format(self._priority, self._weight, self._port, self._name))


class TLSA:
    class Usage:
        CA = 0 # certificate must pass the usual CA check, with the CA specified by the TLSA record
        EndEntity_PlusCAs = 1 # the certificate must match the TLSA record *and* pass the usual CA check
        TrustAnchor = 2 # the certificate must pass a check with the TLSA record giving the (only) trust anchor
        EndEntity = 3 # the certificate must match the TLSA record

    class Selector:
        Full = 0
        SubjectPublicKeyInfo = 1
    
    class MatchingType:
        Exact = 0
        SHA256 = 1
        SHA512 = 2
    
    def __init__(self, protocol: str, port: int, usage: int, selector: int, matching_type: int, data: str) -> None:
        self._port = int(port)
        self._protocol = str(protocol)
        self._usage = int(usage)
        self._selector = int(selector)
        self._matching_type = int(matching_type)
        self._data = check_hex(data)
    
    def generate_rr(self):
        return RR('_{}._{}'.format(self._port, self._protocol), 'TLSA', '{} {} {} {}'.format(self._usage, self._selector, self._matching_type, self._data))


class CNAME:
    def __init__(self, name: str) -> None:
        self._name = check_hostname(name)
    
    def generate_rr(self):
        return RR('@', 'CNAME', self._name)


class NS:
    def __init__(self, name: str) -> None:
        self._name = check_hostname(name)
    
    def generate_rr(self):
        return RR('@', 'NS', self._name)


class DS:
    def __init__(self, tag: int, alg: int, digest: int, key: str) -> None:
        self._tag = int(tag)
        self._key = check_hex(key)
        self._alg = int(alg)
        self._digest = int(digest)
    
    def generate_rr(self):
        return RR('@', 'DS', '{} {} {} {}'.format(self._tag, self._alg, self._digest, self._key))

## Higher-level classes
class Name:
    def __init__(self, *records: 'List[Any]') -> None:
        self._records = records
    
    def generate_rrs(self):
        for record in self._records:
            # this could still be a list
            if isinstance(record, list):
                for subrecord in record:
                    yield subrecord.generate_rr()
            else:
                yield record.generate_rr()


def CName(name: str) -> Name:
    return Name(CNAME(name))


def Delegation(name: str) -> Name:
    return Name(NS(name))


def SecureDelegation(name: str, tag: int, alg: int, digest: int, key: str) -> Name:
    return Name(NS(name), DS(tag, alg, digest, key))


class Zone:
    def __init__(self, name: str, serialfile: str, mail: str, NS: 'List[str]', TTLs: 'Dict[str, int]',
                 secondary_refresh: int, secondary_retry: int, secondary_expire: int,
                 domains: 'Dict[str, Any]') -> None:
        if not name.endswith('.'): raise Exception("Expected an absolute hostname")
        self._name = check_hostname(name)
        self._serialfile = serialfile
        
        if not mail.endswith('.'): raise Exception("Mail must be absolute, end with a dot")
        atpos = mail.find('@')
        if atpos < 0 or atpos > mail.find('.'): raise Exception("Mail must contain an @ before the first dot")
        self._mail = check_hostname(mail.replace('@', '.', 1))
        self._NS = list(map(check_hostname, NS))
        if '' not in TTLs: raise Exception("Must give a default TTL with empty key")
        self._TTLs = TTLs
        
        self._refresh = secondary_refresh
        self._retry = secondary_retry
        self._expire = secondary_expire
        
        self._domains = domains
    
    def getTTL(self, TTL: int, recordType: str) -> int:
        if TTL is not None: return TTL
        # TTL is None, so get a global default
        return int(self._TTLs.get(recordType, self._TTLs['']))
    
    def inc_serial(self) -> int:
        # get serial
        cur_serial = 0
        try:
            with open(self._serialfile) as f:
                cur_serial = int(f.read())
        except (OSError, IOError): # FileNotFoundError has been added in Python 3.3
            pass
        # increment serial
        cur_serial += 1
        # save serial
        with open(self._serialfile, 'w') as f:
            f.write(str(cur_serial))
        # be done
        return cur_serial
    
    def generate_rrs(self) -> 'Iterator':
        # SOA record
        serial = self.inc_serial()
        yield RR('@', 'SOA',
                      ('{NS} {mail} {serial} {refresh} {retry} {expire} {NX_TTL}'+
                      ' ; primns mail serial refresh retry expire NX_TTL').format(
                          NS=self._NS[0], mail=self._mail, serial=serial,
                          refresh=time(self._refresh), retry=time(self._retry), expire=time(self._expire),
                          NX_TTL=time(self.getTTL(None, 'NX')))
                      )
        # NS records
        for name in self._NS:
            yield NS(name).generate_rr()
        # all the rest
        for name in sorted(self._domains.keys(), key=lambda s: list(reversed(s.split('.')))):
            if name.endswith('.'):
                raise Exception("You are trying to add a record outside of your zone. This is not supported. Use '@' for the zone root.")
            for rr in self._domains[name].generate_rrs():
                yield rr.relativize(name)
    
    def write(self) -> None:
        print(";; {} zone file, generated by zonemaker <https://www.ralfj.de/projects/zonemaker> on {}".format(self._name, datetime.datetime.now()))
        print("$ORIGIN {}".format(self._name))
        for rr in map(lambda rr: rr.mapTTL(self.getTTL), self.generate_rrs()):
            print(rr)
