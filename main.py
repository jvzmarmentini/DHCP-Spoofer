#!/usr/bin/python 
from socket import *
from struct import *
from xml.dom.minidom import Identified

def format_mac(mac_addr):
    return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))

s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003)) # ETH_P_ALL = 0x0003
 
while True:
    packet = s.recvfrom(4096) # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096. 
#    print(packet, end="\n\n")

    eth_header = packet[0][0:14]
    eth = unpack('!6s6sH', eth_header)
    network_proto = eth[2]
#    print('Destination MAC: ' + format_mac(eth[0]) + ' Source MAC: ' + format_mac(eth[1]) + ' Protocol: ' + str(network_proto))

    if network_proto == 2048 :
        ipv4_header = packet[0][14:34]
        ipv4 = unpack("!BBHHHBBH4s4s", ipv4_header)
        
        version_ihl = ipv4[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        ToS = ipv4[1] # Type of service

        ipv4_length = ihl * 4

        identifier = ipv4[3]
        flags_offset = ipv4[4]

        flags = flags_offset >> 13
        offset = flags_offset & 0xF #TODO TA ERRADO
 
        ttl = ipv4[5]
        transport_protocol = ipv4[6]
        source_addr = inet_ntoa(ipv4[8]);
        dest_addr = inet_ntoa(ipv4[9]);
 
        print(f'Version: {version} IP Header Length: {ihl} ToS: {ToS} Total Lenght: {ipv4_length} Identifier: {identifier} Flags: {flags} Offset: {offset} TTL: {ttl} Protocol: {transport_protocol} Source Address: {source_addr} Destination Address: {dest_addr}')
 