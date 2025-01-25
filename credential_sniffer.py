#!/usr/bin/env python3
""" Capture Credential """

import argparse
import re

from colorama import Fore, Style
from scapy.all import Raw, sniff

parser = argparse.ArgumentParser(description='Credential sniffer using scapy')
parser.add_argument('--iface', help='Interface to sniff on', required=True)
parser.add_argument('--filter', help='BPF filter', required=True)
parser.add_argument('--keywords', help='File contains list of secret keywords\
                    to detect', required=True)

opts = parser.parse_args()

with open(opts.keywords, 'r', encoding='utf-8') as f:
    KEYWORDS = [i.strip() for i in f.readlines()]


def print_match(pattern, data):
    """Metodo print match"""
    print(f'{Fore.GREEN}!!! Possible secret found !!!{Style.RESET_ALL}')
    re_pattern = re.compile('(' + pattern + ')')
    values = re_pattern.split(data)
    for i in values:
        if re_pattern.match(i):
            print(f'{Fore.RED}{i}{Style.RESET_ALL}', end='')
        else:
            print(i, end='')
    print()


def process_packet(packet):
    """Processa o pacote"""
    try:
        data = str(packet[Raw].load)
        for keyword in KEYWORDS:
            if keyword in data:
                print_match(keyword, data)
    except IndexError:
        pass


if __name__ == "__main__":
    sniff(iface=opts.iface, prn=process_packet, filter=opts.filter)
