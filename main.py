#!/usr/bin/python 
from socket import *
from struct import *

def format_mac(mac_addr):
    return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))

s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003)) # ETH_P_ALL = 0x0003
 
while True:
    packet = s.recvfrom(4096) # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096. 
#    print(packet, end="\n\n")

    eth_header = packet[0][0:14]
    eth = unpack('!6s6sH', eth_header)
    network_proto = ntohs(eth[2])
    print('Destination MAC: ' + format_mac(eth[0]) + ' Source MAC: ' + format_mac(eth[1]) + ' Protocol: ' + str(network_proto))

    if network_proto == 8 :
        ipv4_header = packet[0][14:34]
        ipv4 = unpack("!12s4s4s", ipv4_header)
        print("Source IP: " + inet_ntoa(ipv4[1]) + " Destination IP: " + inet_ntoa(ipv4[2]))