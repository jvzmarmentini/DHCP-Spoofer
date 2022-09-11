from struct import Struct
from typing import Dict


class Protocols():
    TCP_HEADER = Struct("!2H2I2B3H")
    UDP_HEADER = Struct("!4H")
    DNS_HEADER = Struct("!6H")

    @staticmethod
    def decode_tcp(message, offset: int) -> Dict:
        tcp_header = Protocols.TCP_HEADER.unpack_from(message)
        source_port, dest_port, seq, ack, header_len, flags, window, checksum, urgent_pointer = tcp_header
        header_len = header_len >> 4
        
        result = {"source_port": source_port,
                  "dest_port": dest_port,
                  "seq": seq,
                  "ack": ack,
                  "header_len": header_len,
                  "flags": flags,
                  "window": window,
                  "checksum": checksum,
                  "urgent_pointer": urgent_pointer}
        
        return result

    @staticmethod
    def decode_udp(message, offset: int) -> Dict:
        udp_header = Protocols.UDP_HEADER.unpack_from(message)
        source_port, dest_port, length, chekcsum = udp_header
        result = {"source_port": source_port,
                  "dest_port": dest_port,
                  "length": length,
                  "checksum": chekcsum}

        offset = Protocols.UDP_HEADER.size
        if source_port == 53:
            result.update({"DNS": Protocols.decode_dns(message, offset)})

        return result

    @staticmethod
    def decode_dns(message, offset: int) -> Dict:
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

        result = {"id": dnsid,
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
                  "questions": "not supported"}

        return result
