#!/usr/bin/env python3

import argparse
import re
from colorama import Fore, Style
from scapy.all import sniff, TCP, IP, Raw


parser = argparse.ArgumentParser(description='Credential sniffer using scapy')
