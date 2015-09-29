import sys, signal, os, argparse, struct, fcntl 
from fcntl import ioctl
from threading import *
from socket import *
from ConfigParser import *
import pdb8


#TODO: set environment variable



#GLOBAL DEFINES
MTU = 32676
ETH_P_ALL = 0x03

TUNSETIFF = 0x400454ca
IFF_TAP   = 0x0002
IFF_NO_IP = 0x1000

BUFFERSIZE_DEV = 65000



#Global variables
dst_ip   = ''
dst_mac  = ''
dst_port = 0

src_ip   = ''
src_mac  = ''
src_port = 0



def main():
	
	config = ConfigParser()
	config.readfp(open('mitm.conf'))

	dst_ip   = config.get('Destination','ip')
	dst_mac  = config.get('Destination','mac')
	dst_port = config.get('Destination','port')

	src_ip   = config.get('Source','ip')
	src_mac  = config.get('Source','mac')
	src_port = config.get('Source','port')


	#assigning interface names
	list_bridge_interfaces = []
	for bridge_interface in config.get('Interfaces','bridge interfaces').split(','):
		list_bridge_interfaces.append(bridge_interface)
		os.system('ifconfig '+ bridge_interface +' promisc')
	mitm_interface = config.get('Interfaces','MITM interface')

	#TODO: rename variable tap_devidce to tun_device?
	#initialise tun device
	tap_device = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
	flags = struct.pack('16sH', "tap0", IFF_TAP | IFF_NO_PI)
	fcntl.ioctl(tap_device, TUNSETIFF, flags)

	#initialise sniffer threads
	sniffer1 = sniffer(host1_interface, host2_interface, mitm_interface, 0, filter)
	sniffer2 = sniffer(host2_interface, host1_interface, mitm_interface, 0, filter)
	sniffer3 = sniffer(host1_in8erface, host2_interface, 0, mitm_interface, filter)





if __name__ == '__main__':
    main()
