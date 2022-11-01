import socket as s
import netifaces as netif
from typing import Dict 

class Spoofer:

#    def __init__(self, dhcp_offer_header : Dict):
#        self.dhcp_offer_header = dhcp_offer_header

    def getIP(inBytes = False):
        hostname = s.gethostname()
        ipaddr = s.gethostbyname(hostname)

        if inBytes:
            return s.inet_aton(ipaddr)
    
        return ipaddr
    
    def getNetmask(inBytes = False): # https://stackoverflow.com/a/54074160
        for iface in netif.interfaces():
            if netif.ifaddresses(iface)[2]: 
                mask = netif.ifaddresses(iface[2])
        
        if inBytes:
            return s.inet_aton(mask)
    
        return mask

    def write_pkg(self, dhcp_offer_header : Dict): #TODO: FALTAM OUTROS CAMPOS DO HEADER ALÉM DAS OPTIONS
        print(dhcp_offer_header)
        dhcp_offer_header[1] =   {'length': 4, 'res': self.getNetmask(True)} # ok
        dhcp_offer_header[3] =   {'length': 4, 'res': self.getIP(True)}      # ok
        dhcp_offer_header[6] =   {'length': 4, 'res': self.getIP(True)}      # ok
        dhcp_offer_header[51] =  {'length': 4, 'res': 3600}                  # ok
        dhcp_offer_header[53] =  {'length': 1, 'res': 0x2}                   # ok  
        dhcp_offer_header[54] =  {'length': 4, 'res': self.getIP(True)}      # ok
        dhcp_offer_header[58] =  {'length': 4, 'res': 1800}                  # ok
        dhcp_offer_header[59] =  {'length': 4, 'res': 3150}                  # ok 
        dhcp_offer_header[0] =   {'length': 4, 'res': 0x00000}           
        dhcp_offer_header[255] = {'length': 4, 'res': 0x00}

        return dhcp_offer_header

    def spoof(self, dhcp_discover_header : Dict):
        offer_header = self.write_pkg(dhcp_discover_header)
        #TODO: ABRIR SOCKET E ENVIAR PACOTE AO SERVIDOR