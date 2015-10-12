#! /bin/env python
# -*- coding: utf-8 -*-

"""

Ethernet Bridge

Description: Ethernet bridge for man-in-the-middle attacks.

Markus Mahrla, Jon Barg
GAI NetConsult GmbH

"""

import sys
import signal
import os
import argparse
import struct
import fcntl
from threading import *
from ConfigParser import *
from pdb import *
from scapy.all import *
from socket import *

from libmitmbox.parse_config import Parse_MitmConfig
from libmitmbox.bridging.bridge import sniffer


thread1 = None
thread2 = None
thread3 = None

still_running_lock = Lock()


def signal_handler(signal, frame):
    still_running_lock.release()
    thread1.join()
    thread2.join()
    thread3.join()
    sys.exit(0)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        description='mitmbox ethernet intercepter')

    parser.add_argument("-c", nargs=1, dest="config_file", type=str, action='store',
                        help='config file to intercept traffic', default='mitm.conf')

    parser.add_argument("-r", dest="rewrite", action='store_true',
                        help='rewrite mac address on second interface (taken from first interface)')

    args = parser.parse_args()
    config = Parse_MitmConfig(args.config_file[0])

    bridge0_interface = config.bridge0_interface
    bridge1_interface = config.bridge1_interface
    mitm_interface = config.mitm_interface

    if args.file_name:
        file = open(args.file_name[0]).readline()
        mac, ip, port = file.split(" ")

    os.system("ifconfig " + bridge0_interface + " promisc")
    os.system("ifconfig " + bridge1_interface + " promisc")
    os.system("ip tuntap add dev tap0 mode tap")
    os.system("ifconfig tap0 down")
    os.system("ifconfig tap0 hw ether 0e:33:7e:2f:19:61")
    os.system("ifconfig tap0 up")
    os.system("ifconfig tap0 1.2.3.4")
    os.system("route add -net 192.168.0.0 netmask 255.255.0.0 tap0")
    # todo: ARP request for source IP must answered

    tap_device = os.open('/dev/net/tun', os.O_RDWR)
    flags = struct.pack('16sH', "tap0", IFF_TAP | IFF_NO_IP)
    fcntl.ioctl(tap_device, TUNSETIFF, flags)

    sniffer1 = sniffer(bridge0_interface, bridge1_interface, mitm_interface, 0)
    sniffer2 = sniffer(bridge1_interface, bridge0_interface, mitm_interface, 0)
    sniffer3 = sniffer(bridge0_interface, bridge1_interface, 0, mitm_interface)

    thread1 = Thread(target=sniffer1.recv_send_loop)
    thread2 = Thread(target=sniffer2.recv_send_loop)
    thread3 = Thread(target=sniffer3.recv_send_loop)

    still_running_lock.acquire()

    thread1.start()
    thread2.start()
    thread3.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()
