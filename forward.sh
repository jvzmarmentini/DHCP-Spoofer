#!/usr/bin/env bash

# Adaptado de: https://superuser.com/questions/767406/how-to-forward-traffic-using-iptables-rules

EXT=enp4s0
echo 1 > /proc/sys/net/ipv4/ip_forward # Tell the system it is OK to forward IP packets
iptables -t nat -A POSTROUTING -o $EXT -j MASQUERADE
iptables -A FORWARD -s 10.32.143.253/32 -o $EXT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -s 10.32.143.253/32 -o $EXT -j ACCEPT
iptables -A FORWARD -j LOG
