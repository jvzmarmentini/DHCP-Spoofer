import ipaddress
from socket import inet_ntoa
from struct import Struct
from typing import Dict, List


class Protocols():
    '''
    The Protocols class contains each protocol decoded support

    Attributes:
        ETH_HEADER (Struct): Ethernet header struct,
        ARP_HEADER (Struct): ARP header struct,
        IPV6_HEADER (Struct): IPv6 header struct,
        IPV4_HEADER (Struct): IPv4 header struct,
        ICMP_HEADER (Struct): ICMP header struct,
        TCP_HEADER (Struct): TCP header struct,
        UDP_HEADER (Struct): UDP header struct,
        DNS_HEADER (Struct): DNS header struct,
    '''
    ETH_HEADER = Struct("!6s6sH")
    ARP_HEADER = Struct("2s2s1s1s2s6s4s6s4s")
    IPV6_HEADER = Struct("!LHBB16s16s")
    IPV4_HEADER = Struct("!2B3H2BH4s4s")
    ICMP_HEADER = Struct("!BBH")
    TCP_HEADER = Struct("!2H2I2B3H")
    UDP_HEADER = Struct("!4H")
    DNS_HEADER = Struct("!6H")

    @staticmethod
    def decode_eth(message, display: List) -> Dict:
        '''Decode ethernet packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print

        Returns:
            result (Dict): The decode result
        '''
        eth_header = Protocols.ETH_HEADER.unpack_from(message)
        dest_address, source_address, network_proto = eth_header
        dest_address = Protocols.format_mac(dest_address)
        source_address = Protocols.format_mac(source_address)

        result = {}
        if "ETH" in display:
            result.update({"Destine address": dest_address,
                           "Source address": source_address,
                           "Network protocol": network_proto})

        if network_proto == 2048:
            ipv4_header = Protocols.decode_ipv4(
                message, display, Protocols.ETH_HEADER.size)
            if ipv4_header:
                result.update({"IPv4": ipv4_header})

        if network_proto == 34525:
            ipv6_header = Protocols.decode_ipv6(
                message, display, Protocols.ETH_HEADER.size)
            if ipv6_header:
                result.update({"IPv6": ipv6_header})

        if network_proto == 2054:
            arp_header = Protocols.decode_arp(
                message, display, Protocols.ETH_HEADER.size)
            if arp_header:
                result.update({"ARP": arp_header})

        return result

    @staticmethod
    def decode_arp(message, display: List, offset: int) -> Dict:
        '''Decode ARP packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet offset

        Returns:
            result (Dict): The decode result
        '''
        arp_header = Protocols.ARP_HEADER.unpack_from(message, offset)

        hdw_type = int.from_bytes(arp_header[0], "big")
        prot_type = int.from_bytes(arp_header[1], "big")
        hdw_type_len = int.from_bytes(arp_header[2], "big")
        prot_type_len = int.from_bytes(arp_header[3], "big")
        operation = int.from_bytes(arp_header[4], "big")

        source_hdw_addr = Protocols.format_mac(arp_header[5])
        target_hdw_addr = Protocols.format_mac(arp_header[7])

        source_prot_addr = inet_ntoa(arp_header[6])
        target_prot_addr = inet_ntoa(arp_header[8])

        result = {}
        if "ARP" in display:
            result.update({"Hardware type": hdw_type,
                           "Protocol type": prot_type,
                           "Hardware type len": hdw_type_len,
                           "Protocol type len": prot_type_len,
                           "Pperation": operation,
                           "Source hardware addr": source_hdw_addr,
                           "Source protocol addr": source_prot_addr,
                           "Target hardware addr": target_hdw_addr,
                           "Target protocol addr": target_prot_addr})

        return result

    @staticmethod
    def decode_ipv6(message, display: List, offset: int) -> Dict:
        '''Decode IPv6 packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet offset

        Returns:
            result (Dict): The decode result
        '''
        ipv6_header = Protocols.IPV6_HEADER.unpack_from(message, offset)
        misc, payload_len, next_header, hop_limit, source_address, destination_address = ipv6_header

        version = misc >> 28
        traffic_class = (misc & 0x7F) >> 21
        flow_label = misc & 0x1FFFFF

        source_address = str(ipaddress.IPv6Address(source_address))
        destination_address = str(ipaddress.IPv6Address(destination_address))

        result = {}
        if "IPv6" in display:
            result.update({"Version": version,
                           "Traffic class": traffic_class,
                           "Flow label": flow_label,
                           "Payload length": payload_len,
                           "Next header": next_header,
                           "Hop limit": hop_limit,
                           "Source address": source_address,
                           "Destination address": destination_address})

        if next_header == 58:
            icmpv6_header = Protocols.decode_icmp(
                message, display, offset+Protocols.IPV6_HEADER.size)
            if icmpv6_header:
                result.update({"ICMPv6": icmpv6_header})

        if next_header == 6:
            tcp_header = Protocols.decode_tcp(
                message, display, offset+Protocols.IPV6_HEADER.size)
            if tcp_header:
                result.update({"TCP": tcp_header})

        if next_header == 17:
            udp_header = Protocols.decode_udp(
                message, display, offset+Protocols.IPV6_HEADER.size)
            if udp_header:
                result.update({"UDP": udp_header})

        return result

    @staticmethod
    def decode_ipv4(message, display: List, offset: int) -> Dict:
        '''Decode IPv4 packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet offset

        Returns:
            result (Dict): The decode result
        '''
        ipv4_header = Protocols.IPV4_HEADER.unpack_from(message, offset)
        version_ihl, type_of_service, total_lenght, identifier, flags_offset, ttl, protocol, checksum, source_addr, dest_addr = ipv4_header

        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        flags = flags_offset >> 13
        off_set = flags_offset & 0x7FF

        source_addr = inet_ntoa(source_addr)
        dest_addr = inet_ntoa(dest_addr)

        result = {}
        if "IPv4" in display:
            result.update({"Version": version,
                           "Ihl": ihl,
                           "ToS": type_of_service,
                           "Total lenght": total_lenght,
                           "Identifier": identifier,
                           "Flags": flags,
                           "Offset": off_set,
                           "Ttl": ttl,
                           "Protocol": protocol,
                           "Checksum": checksum,
                           "Source address": source_addr,
                           "Destination address": dest_addr})

        if protocol == 1:
            icmp_header = Protocols.decode_icmp(
                message, display, offset+Protocols.IPV4_HEADER.size)
            if icmp_header:
                result.update({"ICMP": icmp_header})

        if protocol == 6:
            tcp_header = Protocols.decode_tcp(
                message, display, offset+Protocols.IPV4_HEADER.size)
            if tcp_header:
                result.update({"TCP": tcp_header})

        if protocol == 17:
            udp_header = Protocols.decode_udp(
                message, display, offset+Protocols.IPV4_HEADER.size)
            if udp_header:
                result.update({"UDP": udp_header})

        return result

    @staticmethod
    def decode_icmp(message, display: List, offset: int) -> Dict:
        '''Decode ICMP packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet + IPv4 offset

        Returns:
            result (Dict): The decode result
        '''
        icmp_header = Protocols.ICMP_HEADER.unpack_from(message, offset)
        icmp_type, code, checksum = icmp_header

        result = {}
        if "ICMP" in display or "ICMPv6" in display:
            result.update({"Type": icmp_type,
                           "Code": code,
                           "Checksum": checksum})
        return result

    @staticmethod
    def decode_tcp(message, display: List, offset: int) -> Dict:
        '''Decode TCP packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet + IPv4 offset

        Returns:
            result (Dict): The decode result
        '''
        tcp_header = Protocols.TCP_HEADER.unpack_from(message, offset)
        s_port, d_port, seq, ack, header_len, flags, window, checksum, urgent_pointer = tcp_header
        header_len = header_len >> 4

        result = {}
        if "TCP" in display:
            result.update({"Source port": s_port,
                           "Destination port": d_port,
                           "Seq": seq,
                           "Ack": ack,
                           "Header length": header_len,
                           "Flags": flags,
                           "Window": window,
                           "Checksum": checksum,
                           "Urgent pointer": urgent_pointer})

        return result

    @staticmethod
    def decode_udp(message, display: List, offset: int) -> Dict:
        '''Decode UDP packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet + IPv4 offset

        Returns:
            result (Dict): The decode result
        '''
        udp_header = Protocols.UDP_HEADER.unpack_from(message, offset)
        source_port, dest_port, length, chekcsum = udp_header

        result = {}
        if "UDP" in display:
            result.update({"Source port": source_port,
                           "Destination port": dest_port,
                           "Length": length,
                           "Checksum": chekcsum})

        if source_port == 53:
            dns_header = Protocols.decode_dns(
                message, display, offset+Protocols.UDP_HEADER.size)
            if dns_header:
                result.update({"DNS": dns_header})

        return result

    @staticmethod
    def decode_dns(message, display: List, offset: int) -> Dict:
        '''Decode ICMP packet

        Args:
            message (bytes): The recieved data from the socket
            display (List): Protocols whitelist to print
            offset (int): Ethernet + IPv4 + DNS offset

        Returns:
            result (Dict): The decode result
        '''
        dns_header = Protocols.DNS_HEADER.unpack_from(message, offset)

        dnsid, misc, qdcount, ancount, nscount, arcount = dns_header

        qr = (misc & 0x8000) != 0
        opcode = (misc & 0x7800) >> 11
        aa = (misc & 0x400) != 0
        tc = (misc & 0x200) != 0
        rd = (misc & 0x100) != 0
        ra = (misc & 0x80) != 0
        z = (misc & 0x70) >> 4
        rcode = misc & 0xF

        result = {}
        if "DNS" in display:
            result.update({"Id": dnsid,
                           "Is response": qr,
                           "Opcode": opcode,
                           "Is authoritative": aa,
                           "Is truncated": tc,
                           "Recursion desired": rd,
                           "Recursion available": ra,
                           "Reserved": z,
                           "Response code": rcode,
                           "Question count": qdcount,
                           "Answer count": ancount,
                           "Authority count": nscount,
                           "Additional count": arcount,
                           "Questions": None})

        return result

    @staticmethod
    def format_mac(mac_addr):
        return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))
