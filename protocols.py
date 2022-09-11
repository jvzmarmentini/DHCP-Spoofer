from base64 import decode
import struct
from typing import Dict


class Protocols():
    UDP_HEADER = struct.Struct("!4H")
    DNS_HEADER = struct.Struct("!6H")

    @staticmethod
    def decode_udp(message) -> Dict:
        udp_header = Protocols.UDP_HEADER.unpack_from(message)
        source_port, dest_port, length, chekcsum = udp_header
        result = {"source_port": source_port,
                  "dest_port": dest_port,
                  "length": length,
                  "checksum": chekcsum}
        
        offset = Protocols.UDP_HEADER.size
        if source_port == 53:
            result.update({"DNS":Protocols.decode_dns(message, offset)})
            
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

        return {"id": dnsid,
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
