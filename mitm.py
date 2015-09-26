from ConfigParser import *
import argparse
import os
import sys


dst_ip   = ''
dst_mac  = ''
dst_port = 0

src_ip   = ''
src_mac  = ''
src_port = 0


def parse_config():
	config = ConfigParser()
	config.readfp(open('mitm.conf'))

	dst_ip   = config.get('Destination','ip')
	dst_mac  = config.get('Destination','mac')
	dst_port = config.get('Destination','port')

	src_ip   = config.get('Source','ip')
	src_mac  = config.get('Source','mac')
	src_port = config.get('Source','port')


	print config.get('Settings','monitoring port')

def main():
	print "hello"
	parse_config()





if __name__ == '__main__':
    main()
