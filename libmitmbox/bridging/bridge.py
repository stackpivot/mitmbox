import os
import struct
from threading import *
from ConfigParser import *
from pdb import *
from scapy.all import *
from socket import *
import fcntl
from ..global_vars import CONFIG, MODE, QUIT, LOG_QUEUE, LOGGING

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


# create file descriptor for tun device to read from and write to
tun_device = os.open('/dev/net/tun', os.O_RDWR)
flags = struct.pack('16sH', "tun0", IFF_TUN | IFF_NO_IP)
ioctl(tun_device, TUNSETIFF, flags)


class MITMBridge():

    def __init__(self, socket_client, socket_server, tun_device):

        self.tun_device = tun_device
        self.socket_client = socket_client
        # bridge traffic between ethernet interfaces and intercept to tun0
        if tun_device:
            self.s_socket_client = socket(
                AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
            self.s_socket_client.bind((socket_client, ETH_P_ALL))

            self.s_socket_server = socket(AF_PACKET, SOCK_RAW)
            self.s_socket_server.bind((socket_server, ETH_P_ALL))

            self.receive = self.socket_receive
            self.send = lambda pkt: self.s_socket_server.send(pkt)
            self.intercept = self.device_send

        # send traffic from tun device back to ethernet interfaces
        else:
            self.s_socket_client = socket(AF_PACKET, SOCK_RAW)
            self.s_socket_client.bind((socket_client, ETH_P_ALL))

            self.s_socket_server = socket(AF_PACKET, SOCK_RAW)
            self.s_socket_server.bind((socket_server, ETH_P_ALL))

            self.receive = self.device_receive
            self.send = lambda pkt: self.s_socket_server.send(pkt)
            self.intercept = lambda pkt: self.s_socket_client.send(pkt)

    # traffic is intercepted based on ip address and network port
    def filterTraffic(self, server_ip_list, pkt_ip, pkt_port):
        for ip_port_tuple in server_ip_list:
            if ip_port_tuple[0] == pkt_ip or ip_port_tuple[0] == "\x00\x00\x00\x00":
                if ip_port_tuple[1] == pkt_port:
                    return True
                # Does not work yet...
                elif ip_port_tuple[1] == 0:
                    return True
        return False

    def source_is_server(self, pkt):
        return self.filterTraffic(CONFIG.server_ip_port_list, pkt[SRC_IP_POS:SRC_IP_POS + 4], pkt[SRC_PORT_POS:SRC_PORT_POS + 2])

    def destination_is_server(self, pkt):
        return self.filterTraffic(CONFIG.server_ip_port_list, pkt[DST_IP_POS:DST_IP_POS + 4], pkt[DST_PORT_POS:DST_PORT_POS + 2])

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
            if pkt_scapy[IP].dst == CONFIG.client_ip:

                if LOGGING is True:
                    if pkt_scapy.getlayer("IP"):
                        if pkt_scapy.getlayer("TCP"):
                            pkt = str(Ether(
                                dst=CONFIG.client_mac, src=CONFIG.server_mac) / pkt_scapy)
                            LOG_QUEUE.put(['m_to_c', pkt])

                return str(Ether(dst=CONFIG.client_mac, src=CONFIG.server_mac) / pkt_scapy)
            # adjust packet to any other destination
            else:
                pkt_scapy[IP].src = CONFIG.client_ip

                if LOGGING is True:
                    if pkt_scapy.getlayer("IP"):
                        if pkt_scapy.getlayer("TCP"):
                            pkt = str(Ether(
                                dst=CONFIG.server_mac, src=CONFIG.client_mac) / pkt_scapy)
                            LOG_QUEUE.put(['m_to_s', pkt])

                return str(Ether(dst=CONFIG.server_mac, src=CONFIG.client_mac) / pkt_scapy)

        except error:
            pass

    # traffic to mitm interface is modified to be recognised by tcp/ip stack
    def device_send(self, pkt):
        try:
            pkt_scapy = IP(pkt[14:])
            del pkt_scapy[IP].chksum
            del pkt_scapy[TCP].chksum
            os.write(tun_device, str(pkt_scapy))

            if LOGGING is True:
                LOG_QUEUE.put(['to_m', pkt])
        except error:
            pass

    def socket_receive(self):
        pkt, sa = self.s_socket_client.recvfrom(MTU)
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
                if CONFIG.mode == MODE.BRIDGE:
                    self.send(pkt)

                # mode to impersonate client
                elif CONFIG.mode == MODE.IMPERSONATE_CLIENT:
                    # traffic from server to client is diverted to mitm
                    if self.source_is_server(pkt):
                        self.intercept(pkt)
                    # drop requests from original client to server
                    elif self.destination_is_server(pkt) and \
                            self.receive == self.socket_receive:
                        continue
                    else:
                        self.send(pkt)

                # mode to impersonate server and respond to client directly
                elif CONFIG.mode == MODE.IMPERSONATE_SERVER:
                    # traffic from client is diverted to mitm and sent back

                    if self.destination_is_server(pkt) or \
                            self.source_is_server(pkt):
                        self.intercept(pkt)
                    else:
                        self.send(pkt)

                # mode to manipulate traffic on the fly (transparent tcp proxy)
                elif CONFIG.mode == MODE.MANIPULATE:
                    # handle traffic coming from bridged interfaces
                    if self.receive == self.socket_receive:
                        # traffic from client and server is diverted to mitm
                        if self.destination_is_server(pkt) or \
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

                if LOGGING is True:
                    if self.socket_client is CONFIG.bridge0_interface and self.tun_device is True:
                        LOG_QUEUE.put(['c_to_s', pkt])
                    elif self.socket_client is CONFIG.bridge1_interface and self.tun_device is True:
                        LOG_QUEUE.put(['s_to_c', pkt])

                if QUIT is True:
                    break
