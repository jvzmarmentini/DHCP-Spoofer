from socket import inet_ntoa
from struct import Struct
from typing import Dict


class Protocols():
    ETH_HEADER = Struct("!6s6sH")
    IPV6_HEADER = Struct("!4sHBB16s16s")
    IPV4_HEADER = Struct("!2B3H2BH4s4s")
    ICMP_HEADER = Struct("!2BH4s")
    TCP_HEADER = Struct("!2H2I2B3H")
    UDP_HEADER = Struct("!4H")
    DNS_HEADER = Struct("!6H")

    @staticmethod
    def decode_eth(message, display=[]) -> Dict:
        eth_header = Protocols.ETH_HEADER.unpack_from(message)
        dest_address, source_address, network_proto = eth_header
        dest_address = Protocols.format_mac(dest_address)
        source_address = Protocols.format_mac(source_address)

        result = {}
        if "ETH" in display:
            result.update({"dest_address": dest_address,
                           "source_address": source_address,
                           "network_proto": network_proto})

        if network_proto == 2048:
            ipv4_header = Protocols.decode_ipv4(
                message, display, Protocols.ETH_HEADER.size)
            if ipv4_header:
                result.update({"IPV4": ipv4_header})

        if network_proto == 34525:
            ipv6_header = Protocols.decode_ipv6(
                message, display, Protocols.ETH_HEADER.size)
            if ipv6_header:
                result.update({"IPV6": ipv6_header})
                
        return result

    @staticmethod
    def decode_ipv6(message, display=[], offset: int = 0) -> Dict:
        ipv6_header = Protocols.IPV6_HEADER.unpack_from(message, offset)
        misc, payload_len, next_header, hop_limit, source_address, destination_address = ipv6_header

        version = misc >> 28
        traffic_class = (misc >> 21) & 0x7F
        flow_label = misc & 0x1FFFFF

        result = {}
        if "IPV6" in display:
            result.update({"version": version,
                           "traffic_class": traffic_class,
                           "flow_label": flow_label,
                           "payload_len": payload_len,
                           "next_header": next_header,
                           "hop_limit": hop_limit,
                           "source_address": source_address,
                           "destination_address": destination_address})

        return result

    @staticmethod
    def decode_ipv4(message, display=[], offset: int = 0) -> Dict:
        ipv4_header = Protocols.IPV4_HEADER.unpack_from(message, offset)
        version_ihl, type_of_service, total_lenght, identifier, flags_offset, ttl, protocol, checksum, source_addr, dest_addr = ipv4_header
        
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        flags = flags_offset >> 13
        offset = flags_offset & 0x7FF

        source_addr = inet_ntoa(source_addr)
        dest_addr = inet_ntoa(dest_addr)

        result = {}
        if "IPV4" in display:
            result.update({"version": version,
                           "ihl": ihl,
                           "ToS": type_of_service,
                           "total_lenght": total_lenght,
                           "identifier": identifier,
                           "flags": flags,
                           "offset": offset,
                           "ttl": ttl,
                           "protocol": protocol,
                           "checksum": checksum,
                           "source_addr": source_addr,
                           "dest_addr": dest_addr})

        if protocol == 1:
            icmp_header = Protocols.decode_icmp(
                message, display, Protocols.IPV4_HEADER.size)
            if icmp_header:
                result.update({"ICMP": icmp_header})

        if protocol == 6:
            tcp_header = Protocols.decode_tcp(
                message, display, Protocols.IPV4_HEADER.size)
            if tcp_header:
                result.update({"TCP": tcp_header})

        if protocol == 17:
            udp_header = Protocols.decode_udp(
                message, display, Protocols.IPV4_HEADER.size)
            if udp_header:
                result.update({"UDP": udp_header})

        return result

    @staticmethod
    def decode_icmp(message, display=[], offset: int = 0) -> Dict:
        icmp_header = Protocols.ICMP_HEADER.unpack_from(message, offset)
        type, code, checksum = icmp_header

        result = {}
        if "ICMP" in display:
            result.update({"type": type,
                           "code": code,
                           "checksum": checksum})
        return result

    @staticmethod
    def decode_tcp(message, display=[], offset: int = 0) -> Dict:
        tcp_header = Protocols.TCP_HEADER.unpack_from(message, offset)
        source_port, dest_port, seq, ack, header_len, flags, window, checksum, urgent_pointer = tcp_header
        header_len = header_len >> 4

        result = {}
        if "TCP" in display:
            result.update({"source_port": source_port,
                           "dest_port": dest_port,
                           "seq": seq,
                           "ack": ack,
                           "header_len": header_len,
                           "flags": flags,
                           "window": window,
                           "checksum": checksum,
                           "urgent_pointer": urgent_pointer})

        return result

    @staticmethod
    def decode_udp(message, display=[], offset: int = 0) -> Dict:
        udp_header = Protocols.UDP_HEADER.unpack_from(message, offset)
        source_port, dest_port, length, chekcsum = udp_header

        result = {}
        if "UDP" in display:
            result.update({"source_port": source_port,
                           "dest_port": dest_port,
                           "length": length,
                           "checksum": chekcsum})

        if source_port == 53:
            dns_header = Protocols.decode_dns(
                message, display, Protocols.UDP_HEADER.size)
            if dns_header:
                result.update({"DNS": dns_header})

        return result

    @staticmethod
    def decode_dns(message, display=[], offset: int = 0) -> Dict:
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
            result.update({"id": dnsid,
                           "is_response": qr,
                           "opcode": opcode,
                           "is_authoritative": aa,
                           "is_truncated": tc,
                           "recursion_desired": rd,
                           "recursion_available": ra,
                           "reserved": z,
                           "response_code": rcode,
                           "question_count": qdcount,
                           "answer_count": ancount,
                           "authority_count": nscount,
                           "additional_count": arcount,
                           "questions": "not supported"})

        return result

    @staticmethod
    def format_mac(mac_addr):
        return ':'.join(mac_addr.hex()[i:i+2] for i in range(0, len(mac_addr.hex()), 2))
