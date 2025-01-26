#!/usr/bin/env python3
"""Sniffer de Pacotes de Rede (ICMP) com Melhorias"""

import argparse
import ipaddress
import socket
import struct
import sys
import os

# Verifica se o script está sendo executado como root/administrador
if os.geteuid() != 0:
    print("Este script precisa ser executado com privilégios de root/administrador (sudo).")
    sys.exit(1)

parser = argparse.ArgumentParser(description='Sniffer de pacotes de rede (ICMP)')
parser.add_argument('--interface', '-i', help='Interface de rede para snifar (ex: eth0, wlan0)', required=True)
opts = parser.parse_args()

class Packet:
    """Classe para representar um pacote IP."""

    def __init__(self, raw_data):
        try:
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)  # ! para network byte order (big-endian)
            self.version = iph[0] >> 4
            self.ihl = iph[0] & 0xF
            self.tos = iph[1]
            self.length = iph[2]
            self.id = iph[3]
            self.offset = iph[4]
            self.ttl = iph[5]
            self.protocol_num = iph[6]
            self.checksum = iph[7]
            self.src_addr = ipaddress.ip_address(iph[8])
            self.dst_addr = ipaddress.ip_address(iph[9])

            self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"} # Adicionado TCP e UDP
            self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num)) # Usando .get() para evitar KeyError

        except struct.error as e:
            print(f"Erro ao decodificar o cabeçalho IP: {e}")
            return None # Retorna None em caso de erro

    def print_header(self):
        if self is None: # Verifica se o pacote foi inicializado corretamente
            return
        print(f'Protocolo: {self.protocol} | {self.src_addr} -> {self.dst_addr} | TTL: {self.ttl}')

def sniff(interface):
    """Função principal para snifar pacotes."""
    try:
        sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) # Usando AF_PACKET para snifar em nível de enlace
    except socket.error as e:
        print(f"Erro ao criar o socket: {e}")
        sys.exit(1)

    try:
        sniffer.bind((interface, 0)) # Vincula à interface especificada
    except OSError as e:
        print(f"Erro ao vincular o socket à interface {interface}: {e}. Verifique se a interface existe e se você tem permissões.")
        sys.exit(1)

    print(f"Sniffando na interface {interface}...")
    try:
        while True:
            raw_data, addr = sniffer.recvfrom(65535)
            packet = Packet(raw_data[14:]) # Remove o cabeçalho Ethernet (14 bytes)

            if packet: # Verifica se o pacote foi criado corretamente
                packet.print_header()

    except KeyboardInterrupt:
        print("Sniffer encerrado.")
        sys.exit(0)
    except socket.error as e:
        print(f"Erro no socket durante a captura: {e}")
        sys.exit(1)

if __name__ == "__main__":
    sniff(opts.interface)
