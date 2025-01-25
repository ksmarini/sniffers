#!/usr/bin/env python3
""" Capture Credential """

import argparse
import re

from colorama import Fore, Style
from scapy.all import IP, TCP, Raw, sniff

parser = argparse.ArgumentParser(description='Credential sniffer using scapy')
parser.add_argument('--iface', help='Interface to sniff on', required=True)
parser.add_argument('--filter', help='BPF filter', required=True)
parser.add_argument('--keywords', help='File contains list of secret keywords\
                    to detect', required=True)

opts = parser.parse_args()
