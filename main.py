#!/usr/bin/python 
from socket import *
from struct import *

s = socket(AF_PACKET, SOCK_RAW, ntohs(0x0003)) # ETH_P_ALL = 0x0003
 
while True:
    packet = s.recvfrom(4096) # For best match with hardware and network realities, bufsize should be a relatively small power of 2, for example, 4096. 
    print(packet, end="\n\n")