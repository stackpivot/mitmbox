import os
import struct
from threading import *
from ConfigParser import *
from pdb import *
from scapy.all import *
from socket import *
import fcntl
from ..global_vars import CONFIG

MTU = 32676     # read from socket without bothering maximum transfer unit
ETH_P_ALL = 0x03  # capture all bytes of packet including ethernet layer

ip_src = 0x1a       # position of ip source address in packet
ip_dst = 0x1e       # position of ip destination address in packet
port_dst = 0x24     # position of destination port address in packet

# read from tap device without bothering maximum transfer unit
BUFFERSIZE_DEV = 65000

TUNSETIFF = 0x400454ca  # attach to tun/tap device
IFF_TAP = 0x0002    # utilize tap device, i.e. including ethernet layer
IFF_NO_IP = 0x1000  # omit packet information that is added by kernel


tap_device = os.open('/dev/net/tun', os.O_RDWR)
flags = struct.pack('16sH', "tap0", IFF_TAP | IFF_NO_IP)
fcntl.ioctl(tap_device, TUNSETIFF, flags)


class MITMBridge():

    def __init__(self, iface0, iface1, mitm_in):

        self.control_queue = control_queue
        # traffic going from bridged interfaces to man-in-the-middle interface
        if mitm_in:
            self.s_iface0 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
            self.s_iface0.bind((iface0, ETH_P_ALL))

            self.s_iface1 = socket(AF_PACKET, SOCK_RAW)
            self.s_iface1.bind((iface1, ETH_P_ALL))

            self.receive = self.socket_receive
            self.send = lambda pkt: self.s_iface1.send(pkt)
            self.redirect = self.device_send

        # traffic going from man-in-the-middle interface to bridged interfaces
        if mitm_out:
            self.s_iface0 = socket(AF_PACKET, SOCK_RAW)
            self.s_iface0.bind((iface0, ETH_P_ALL))

            self.s_iface1 = socket(AF_PACKET, SOCK_RAW)
            self.s_iface1.bind((iface1, ETH_P_ALL))

            self.receive = self.device_receive
            self.send = lambda pkt: self.s_iface0.send(pkt)
            self.redirect = lambda pkt: self.s_iface1.send(pkt)

    # traffic is intercepted based on ip address and network port
    def filter(self, ip, port, pkt_ip, pkt_port):
        if inet_aton(ip) == pkt_ip:
            if pkt_port:
                if struct.pack(">H", int(port[:-1])) == pkt_port:
                    return True
            else:
                return True
        return False

    def source_is_server(self, pkt):
        return self.filter(CONFIG.server_ip, Config.server_port, pkt[SRC_IP_POS:SRC_IP_POS + 4], pkt[SRC_PORT_POS:SRC_PORT_POS + 2])

    def destination_is_server(self, pkt):
        return self.filter(CONFIG.server_ip, Config.server_port, pkt[DST_IP_POS:DST_IP_POS + 4], pkt[DST_PORT_POS:DST_PORT_POS + 2])

    def destination_is_mitm(self, pkt):
        return self.filter(CONFIG.client_ip, Config.server_port, pkt[DST_IP_POS:DST_IP_POS + 4], pkt[SRC_PORT_POS:SRC_PORT_POS + 2])

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
                pkt_scapy[IP].src = CONFIG.server_ip
                return str(Ether(dst=CONFIG.client_mac, src=CONFIG.server_mac) / pkt_scapy)
            # adjust packet to any other destination
            else:
                pkt_scapy[IP].src = CONFIG.client_ip
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
                           self.destination_is_mitm(pkt):
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
