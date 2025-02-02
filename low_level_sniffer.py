#!/usr/bin/env python3
"""Low Level Network Sniffer"""
import argparse
import ipaddress
import socket
import struct
import sys

parser = argparse.ArgumentParser(description='Network packet sniffer')
parser.add_argument('--ip', help='IP address to sniff on', required=True)
opts = parser.parse_args()


class Packet:
    """Packet Class"""
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('<BBHHHBBH4s4s', self.packet[0:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.off = header[4]
        self.ttl = header[5]
        self.pro = header[6]
        self.num = header[7]
        self.src = ipaddress.ip_address(header[8])
        self.dst = ipaddress.ip_address(header[9])

        #  self.src_addr = ipaddress.ip_address(self.src)
        #  self.dst_addr = ipaddress.ip_address(self.dst)

        #  self.protocol_map = {1: "ICMP"}
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        try:
            self.protocol = self.protocol_map[self.pro]
        except Exception as e:
            print(f'{e} No protocol for {self.pro}')
            self.protocol = str(self.pro)

    def print_header_short(self):
        """Print header"""
        print(f'Protocol: {self.protocol} {self.src} -> {self.dst}')


def sniff(host):
    """Sniffer Function"""
    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        while True:
            raw_data = sniffer.recv(65535)
            packet = Packet(raw_data)
            packet.print_header_short()
    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    sniff(opts.ip)
