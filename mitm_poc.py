#! /usr/bin/env python
# -*- coding: ASCII -*-

"""

Ethernet Bridge

Description: Ethernet bridge for man-in-the-middle attacks.

Markus Mahrla, Jon Barg
GAI NetConsult GmbH

"""

import sys
import signal
import os
import struct
from pdb import *
from scapy.all import *
from socket import *
from argparse import *
from threading import *
from ConfigParser import *
from fcntl import ioctl

MTU = 32676             # read from socket without bothering on MTU
ETH_P_ALL = 0x03        # capture all bytes of packet including ethernet layer

TUNSETIFF = 0x400454ca  # attach to tun/tap device
IFF_TUN = 0x0001        # utilize tap device, i.e. including ethernet layer
IFF_NO_IP = 0x1000      # omit packet information that is added by kernel

SRC_IP_POS = 0x1a           # position of ip source address in packet
DST_IP_POS = 0x1e           # position of ip destination address in packet
SRC_PORT_POS = 0x22         # position of source port address in packet
DST_PORT_POS = 0x24         # position of destination port address in packet

BUFFERSIZE_DEV = 65000  # read from tap device without bothering on MTU


class MITMBridge():

    def __init__(self, iface0, iface1, mitm_in):

        # bridge traffic between ethernet interfaces and intercept to tun0
        if mitm_in:
            self.s_iface0 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
            self.s_iface0.bind((iface0, ETH_P_ALL))

            self.s_iface1 = socket(AF_PACKET, SOCK_RAW)
            self.s_iface1.bind((iface1, ETH_P_ALL))

            self.receive = self.socket_receive
            self.send = lambda pkt: self.s_iface1.send(pkt)
            self.intercept = self.device_send

        # send traffic from tun device back to ethernet interfaces
        else:
            self.s_iface0 = socket(AF_PACKET, SOCK_RAW)
            self.s_iface0.bind((iface0, ETH_P_ALL))

            self.s_iface1 = socket(AF_PACKET, SOCK_RAW)
            self.s_iface1.bind((iface1, ETH_P_ALL))

            self.receive = self.device_receive
            self.send = lambda pkt: self.s_iface1.send(pkt)
            self.intercept = lambda pkt: self.s_iface0.send(pkt)

    def lock_check(self):
        return not still_running_lock.locked()

    # traffic is intercepted based on server's ip address and network port
    def filter(self, pkt_ip, pkt_port):
        if inet_aton(server_ip) == pkt_ip:
            if pkt_port:
                if struct.pack(">H", int(server_port[:-1])) == pkt_port:
                    return True
            else:
                return True
        return False

    def source_is_server(self, pkt):
        return self.filter(pkt[SRC_IP_POS:SRC_IP_POS+4], pkt[SRC_PORT_POS:SRC_PORT_POS+2])

    def destination_is_server(self, pkt):
        return self.filter(pkt[DST_IP_POS:DST_IP_POS+4], pkt[DST_PORT_POS:DST_PORT_POS+2])

    # traffic leaving mitm interface is written back to original addresses
    def device_receive(self):
        try:
            # read and interpret packet
            p = os.read(tun_device, BUFFERSIZE_DEV)
            pkt_scapy = IP(p)

            # delete checksums
            if pkt_scapy.getlayer("IP"):
                del pkt_scapy[IP].chksum
            if pkt_scapy.getlayer("TCP"):
                del pkt_scapy[TCP].chksum

            # adjust packet if it is going to server
            if pkt_scapy[IP].dst == server_ip:
                pkt_scapy[IP].src = client_ip
                return str(Ether(dst=server_mac, src=client_mac) / pkt_scapy)

            # adjust packet if it is going to client
            if pkt_scapy[IP].dst == client_ip:
                pkt_scapy[IP].src = server_ip
                return str(Ether(dst=client_mac, src=server_mac) / pkt_scapy)

        except error:
            pass

    # traffic to mitm interface is modified to be recognised by tcp/ip stack
    def device_send(self, pkt):
        try:
            pkt_scapy = IP(pkt[14:])
            del pkt_scapy[IP].chksum
            del pkt_scapy[TCP].chksum
            pkt_scapy[IP].dst = "1.2.3.4"
            os.write(tun_device, str(pkt_scapy))
        except error:
            pass

    def socket_receive(self):
        pkt, sa = self.s_iface0.recvfrom(MTU)
        if sa[2] != PACKET_OUTGOING:
            return pkt

    def run_bridge(self):
        pkt = ""
        while True:
            try:
                pkt = self.receive()
            except error:
                pass
            if pkt:

                # packets can be manipulated before sending, e.g. via Scapy
                if mode == 0:
                    self.send(pkt)

                # mode to impersonate client
                if mode == 1:
                    # traffic from server to client is diverted to mitm
                    if self.source_is_server(pkt):
                        self.intercept(pkt)
                    # drop requests from original client to server
                    elif self.destination_is_server(pkt) and \
                            self.receive == self.socket_receive:
                        pass
                    else:
                        self.send(pkt)

                # mode to impersonate server and respond to client directly
                if mode == 2:
                    # traffic from client is diverted to mitm and sent back
                    if self.destination_is_server(pkt) or\
                            self.source_is_server(pkt):
                        self.intercept(pkt)
                    else:
                        self.send(pkt)

                # mode to manipulate traffic on the fly (transparent tcp proxy)
                if mode == 3:
                    # handle traffic coming from bridged interfaces
                    if self.receive == self.socket_receive:
                        # traffic from client and server is diverted to mitm
                        if self.destination_is_server(pkt) or\
                           self.source_is_server(pkt):
                            self.intercept(pkt)
                        else:
                            self.send(pkt)
                    # handle traffic coming from mitm interface
                    if self.receive == self.device_receive:
                        # traffic from mitm interface to client is diverted
                        # back to client
                        if self.source_is_server(pkt):
                            self.intercept(pkt)
                        else:
                            self.send(pkt)

                if self.lock_check() == True:
                    break

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

    parser = ArgumentParser(description='Man-in-the-Middle Ethernet Bridge',
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument("-f", nargs=1, dest="file_name", type=str,
                        action='store',
                        help='config file to run different modes (interfaces' +
                        ' are bridged in each mode)\nsyntax of first line: ' +
                        '<mode> <client mac> <client ip> <server/gateway ' +
                        'mac> ' +
                        '<server ip> <server port>\nmode 0: bridge mode (' +
                        'client and server addresses are ignored)\n' +
                        'mode 1: impersonate a client while connecting to ' +
                        'a server\nmode 2: impersonate a server and wait' +
                        'for client requests\nmode 3: manipulate traffic' +
                        ' on the fly, i.e. as transparent tcp proxy\n')
    parser.add_argument("-r", dest="rewrite", action='store_true',
                        help='rewrite mac address in case of ' +
                        'point-to-point protocols, e.g. if Wifi or 3G is ' +
                        'used on one of the interfaces')
    parser.add_argument("interface1", nargs=1, type=str, action='store',
                        help='first interface to bridge')
    parser.add_argument("interface2", nargs=1, type=str, action='store',
                        help='second interface to bridge')

    args = parser.parse_args()

    interface1 = args.interface1[0]
    interface2 = args.interface2[0]

    # read config file if present (default is bridge mode)
    if args.file_name:
        file = open(args.file_name[0]).readline()
        mode = file.split(" ")[0]
        if mode != "0":
            client_mac, client_ip = file.split(" ")[1:3]
            server_mac, server_ip, server_port = file.split(" ")[3:]
    else:
        mode = "0"
    mode = int(mode)

    # set bridged interface in promiscuous mode
    os.system("ifconfig " + interface1 + " promisc")
    os.system("ifconfig " + interface2 + " promisc")
    # add tun device and assign IP address
    os.system("ip tuntap add dev tun0 mode tun")
    os.system("ifconfig tun0 1.2.3.4")
    # network routes are added so kernel sends traffic via tun device
    if mode != 0:
        os.system("route add -host " + client_ip + " tun0")
        os.system("route add -host " + server_ip + " tun0")

    # create file descriptor for tun device to read from and write to
    tun_device = os.open('/dev/net/tun', os.O_RDWR)
    flags = struct.pack('16sH', "tun0", IFF_TUN | IFF_NO_IP)
    ioctl(tun_device, TUNSETIFF, flags)

    # create three threads that receive, intercept and sent traffic

    bridge1 = MITMBridge(interface1, interface2, True)
    bridge2 = MITMBridge(interface2, interface1, True)
    bridge3 = MITMBridge(interface1, interface2, False)

    thread1 = Thread(target=bridge1.run_bridge)
    thread2 = Thread(target=bridge2.run_bridge)
    thread3 = Thread(target=bridge3.run_bridge)

    still_running_lock.acquire()

    thread1.start()
    thread2.start()
    thread3.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()
