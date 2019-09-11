# -*- coding: utf-8 -*-
import base64
import codecs
import contextlib
import json
import re
import zlib
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

import gevent
from gevent import socket

from lib.config import *
from portscan.RE_DATA import *

SOCKET_READ_BUFFERSIZE = 1024  # SOCKET DEFAULT READ BUFFER


def dqtoi(dq):
    """ip地址转数字."""
    octets = dq.split(".")
    if len(octets) != 4:
        raise ValueError
    for octet in octets:
        if int(octet) > 255:
            raise ValueError
    return (int(octets[0]) << 24) + \
           (int(octets[1]) << 16) + \
           (int(octets[2]) << 8) + \
           (int(octets[3]))


def itodq(intval):
    """数字转ip地址."""
    return "%u.%u.%u.%u" % ((intval >> 24) & 0x000000ff,
                            ((intval & 0x00ff0000) >> 16),
                            ((intval & 0x0000ff00) >> 8),
                            (intval & 0x000000ff))


def compile_pattern(allprobes):
    """编译re的正则表达式"""
    for probe in allprobes:
        matches = probe.get('matches')
        if isinstance(matches, list):
            for match in matches:
                try:
                    # pattern, _ = codecs.escape_decode(match.get('pattern'))
                    pattern = match.get('pattern').encode('utf-8')

                except Exception as err:
                    pass
                try:
                    match['pattern_compiled'] = re.compile(pattern, re.IGNORECASE | re.DOTALL)
                except Exception as err:
                    match['pattern_compiled'] = ''
        softmatches = probe.get('softmatches')
        if isinstance(softmatches, list):
            for match in softmatches:
                try:
                    match['pattern_compiled'] = re.compile(match.get('pattern'), re.IGNORECASE | re.DOTALL)
                except Exception as err:
                    match['pattern_compiled'] = ''
    return allprobes


class ServiceScan(object):

    def __init__(self, timeout):
        self.sd = None
        self.allprobes = compile_pattern(json.loads(zlib.decompress(base64.b64decode(ALLPROBES))))
        self.all_guess_services = json.loads(zlib.decompress(base64.b64decode(ALL_GUESS_SERVICE)))
        self.timeout = timeout

    def scan(self, host, port, protocol):
        nmap_fingerprint = {'error': 'unknowservice'}
        in_probes, ex_probes = self.filter_probes_by_port(port, self.allprobes)

        probes = self.sort_probes_by_rarity(in_probes)
        for probe in probes:
            response = self.send_probestring_request(host, port, protocol, probe)
            if response is None:  # 连接超时
                # if self.all_guess_services.get(str(port)) is not None:
                #     return self.all_guess_services.get(str(port))
                # return {'error': 'timeout'}
                continue
            else:
                nmap_service, nmap_fingerprint = self.match_probe_pattern(response, probe)
                if bool(nmap_fingerprint):
                    record = {
                        "service": nmap_service,
                        "versioninfo": nmap_fingerprint,
                    }
                    # ssl特殊处理
                    if nmap_service == "ssl" and self.all_guess_services.get(str(port)) is not None:
                        return self.all_guess_services.get(str(port))
                    return record

        for probe in ex_probes:
            response = self.send_probestring_request(host, port, protocol, probe)
            if response is None:  # 连接超时
                # if self.all_guess_services.get(str(port)) is not None:
                #     return self.all_guess_services.get(str(port))
                # return {'error': 'timeout'}
                continue
            else:
                nmap_service, nmap_fingerprint = self.match_probe_pattern(response, probe)
                if bool(nmap_fingerprint):
                    record = {
                        "service": nmap_service,
                        "versioninfo": nmap_fingerprint,
                    }
                    # ssl特殊处理
                    if nmap_service == "ssl" and self.all_guess_services.get(str(port)) is not None:
                        return self.all_guess_services.get(str(port))
                    return record
                else:
                    if self.all_guess_services.get(str(port)) is not None:
                        return self.all_guess_services.get(str(port))
        # 全部检测完成后还没有识别
        if self.all_guess_services.get(str(port)) is not None:
            return self.all_guess_services.get(str(port))
        else:
            return {'error': 'unknowservice'}

    def scan_with_probes(self, host, port, protocol, probes):
        """发送probes中的每个probe到端口."""
        for probe in probes:
            record = self.send_probestring_request(host, port, protocol, probe)
            if bool(record.get('versioninfo')):  # 如果返回了versioninfo信息,表示已匹配,直接返回
                return record
        return {}

    def send_probestring_request(self, host, port, protocol, probe):
        """根据nmap的probestring发送请求数据包"""
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)

        response = ""
        # protocol must be match nmap probe protocol
        if proto.upper() == protocol.upper():
            if protocol.upper() == "TCP":
                response = self.send_tcp_request(host, port, payload)
            elif protocol.upper() == "UDP":
                response = self.send_udp_request(host, port, payload)
        return response

    def send_tcp_request(self, host, port, payload):
        """Send tcp payloads by port number."""
        client = socket.socket(AF_INET, SOCK_STREAM)
        try:
            client.settimeout(self.timeout)
            client.connect((host, int(port)))
            client.send(payload)
            data = client.recv(SOCKET_READ_BUFFERSIZE)
            client.close()
        except Exception as err:

            return None
        finally:
            client.close()
        return data

    def send_udp_request(self, host, port, payload):
        """Send udp payloads by port number.
        """
        data = ''
        try:
            with contextlib.closing(socket.socket(AF_INET, SOCK_DGRAM)) as client:
                client.settimeout(self.timeout)
                client.sendto(payload, (host, port))
                while True:
                    _, addr = client.recvfrom(SOCKET_READ_BUFFERSIZE)
                    if not _:
                        break
                    data += _
        except Exception as err:
            return None
        return data

    def match_probe_pattern(self, data, probe):
        """Match tcp/udp response based on nmap probe pattern.
        """
        nmap_service, nmap_fingerprint = "", {}

        if not data:
            return nmap_service, nmap_fingerprint
        try:
            matches = probe['matches']
            for match in matches:

                pattern_compiled = match['pattern_compiled']

                rfind = pattern_compiled.findall(data)

                if rfind and ("versioninfo" in match):
                    nmap_service = match['service']
                    versioninfo = match['versioninfo']

                    rfind = rfind[0]
                    if isinstance(rfind, str) or isinstance(rfind, bytes):
                        rfind = [rfind]

                    if re.search('\$P\(\d\)', versioninfo) is not None:
                        for index, value in enumerate(rfind):
                            dollar_name = "$P({})".format(index + 1)

                            versioninfo = versioninfo.replace(dollar_name, value.decode('utf-8', 'ignore'))
                    elif re.search('\$\d', versioninfo) is not None:
                        for index, value in enumerate(rfind):
                            dollar_name = "${}".format(index + 1)

                            versioninfo = versioninfo.replace(dollar_name, value.decode('utf-8', 'ignore'))

                    nmap_fingerprint = self.match_versioninfo(versioninfo)
                    if nmap_fingerprint is None:
                        continue
                    else:
                        return nmap_service, nmap_fingerprint
        except Exception as err:
            return nmap_service, nmap_fingerprint
        try:
            matches = probe['softmatches']
            for match in matches:
                # pattern = match['pattern']
                pattern_compiled = match['pattern_compiled']

                # https://github.com/nmap/nmap/blob/master/service_scan.cc#L476
                # regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)

                rfind = pattern_compiled.findall(data)

                if rfind and ("versioninfo" in match):
                    nmap_service = match['service']
                    return nmap_service, nmap_fingerprint
        except Exception as err:
            return nmap_service, nmap_fingerprint
        return nmap_service, nmap_fingerprint

    def match_versioninfo(self, versioninfo):
        """Match Nmap versioninfo
        """

        record = {
            "vendorproductname": [],
            "version": [],
            "info": [],
            "hostname": [],
            "operatingsystem": [],
            "cpename": []
        }

        if "p/" in versioninfo:
            regex = re.compile(r"p/([^/]*)/")
            vendorproductname = regex.findall(versioninfo)
            record["vendorproductname"] = vendorproductname

        if "v/" in versioninfo:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(versioninfo)
            record["version"] = version

        if "i/" in versioninfo:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(versioninfo)
            record["info"] = info

        if "h/" in versioninfo:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(versioninfo)
            record["hostname"] = hostname

        if "o/" in versioninfo:
            regex = re.compile(r"o/([^/]*)/")
            operatingsystem = regex.findall(versioninfo)
            record["operatingsystem"] = operatingsystem

        if "d/" in versioninfo:
            regex = re.compile(r"d/([^/]*)/")
            devicetype = regex.findall(versioninfo)
            record["devicetype"] = devicetype

        if "cpe:/" in versioninfo:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpename = regex.findall(versioninfo)
            record["cpename"] = cpename
        if record == {"vendorproductname": [], "version": [], "info": [], "hostname": [], "operatingsystem": [],
                      "cpename": []}:
            return None
        return record

    def sort_probes_by_rarity(self, probes):
        """Sorts by rarity
        """
        newlist = sorted(probes, key=lambda k: k['rarity']['rarity'])
        return newlist

    def filter_probes_by_port(self, port, probes):
        """通过端口号进行过滤,返回强符合的probes和弱符合的probes
        """
        # {'match': {'pattern': '^LO_SERVER_VALIDATING_PIN\\n$',
        #            'service': 'impress-remote',
        #            'versioninfo': ' p/LibreOffice Impress remote/ '
        #                           'cpe:/a:libreoffice:libreoffice/'},
        #  'ports': {'ports': '1599'},
        #  'probe': {'probename': 'LibreOfficeImpressSCPair',
        #            'probestring': 'LO_SERVER_CLIENT_PAIR\\nNmap\\n0000\\n\\n',
        #            'protocol': 'TCP'},
        #  'rarity': {'rarity': '9'}}

        included = []
        excluded = []

        for probe in probes:
            if "ports" in probe:
                ports = probe['ports']['ports']
                if self.is_port_in_range(port, ports):
                    included.append(probe)
                else:  # exclude ports
                    excluded.append(probe)

            elif "sslports" in probe:
                sslports = probe['sslports']['sslports']
                if self.is_port_in_range(port, sslports):
                    included.append(probe)
                else:  # exclude sslports
                    excluded.append(probe)

            else:  # no [ports, sslports] settings
                excluded.append(probe)

        return included, excluded

    def is_port_in_range(self, port, nmap_port_rule):
        """Check port if is in nmap port range
        """
        bret = False

        ports = nmap_port_rule.split(',')  # split into serval string parts
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True

        return bret


class GeventScanner(object):
    def __init__(self, max_socket_count, timeout=0.5):
        self.serviceScan = ServiceScan(timeout)
        self.maxSocketCount = max_socket_count
        self.timeout = timeout
        self.resultList = []

    def async_scan(self, ipaddress, port):
        ipaddress = ipaddress
        port = port
        sd = socket.socket(AF_INET, SOCK_STREAM)
        try:
            sd.settimeout(self.timeout)
            sd.connect((ipaddress, port))
            data = self.serviceScan.scan(ipaddress, port, 'tcp')
            if data.get("error") is None:
                self.format_log(ipaddress, port, data)
                self.resultList.append(
                    {"ipaddress": ipaddress, "port": port, "service": data.get("service"), "data": data})
            sd.close()
        except Exception as E:
            pass
        finally:
            sd.close()

    # gevent 扫描
    def aysnc_main(self, startip, stopip, port_list, pool):
        start = dqtoi(startip)
        stop = dqtoi(stopip)
        tasks = []
        # pool = Pool(self.maxSocketCount)
        pool = pool
        for host in range(start, stop + 1):
            for port in port_list:
                ipaddress = itodq(host)
                task = pool.spawn(self.async_scan, ipaddress, port)
                tasks.append(task)
        gevent.joinall(tasks)
        return self.resultList

    def format_log(self, ipaddress, port, data):
        if data.get(u"number") is not None:
            # 根据端口猜测fingerprint
            format_str = "{:<16}{:<7}{:<20}".format(ipaddress, port, data.get("service") + "?")
        else:
            versioninfo = ""
            try:
                versioninfo = versioninfo+data.get("versioninfo").get("vendorproductname")[0] + "  "
            except Exception as E:
                pass
            try:
                versioninfo = versioninfo+data.get("versioninfo").get("version")[0] + "  "
            except Exception as E:
                pass
            try:
                versioninfo = versioninfo+data.get("versioninfo").get("operatingsystem")[0] + "  "
            except Exception as E:
                pass
            try:
                versioninfo = versioninfo+data.get("versioninfo").get("info")[0] + "  "
            except Exception as E:
                pass
            try:
                versioninfo = versioninfo+data.get("versioninfo").get("hostname")[0] + "  "
            except Exception as E:
                pass

            format_str = "{:<16}{:<7}{:<20}{}".format(ipaddress, port, data.get("service"), versioninfo)
        logger.warning(format_str)
