from ConfigParser import *
import os
import sys




def parse_config():
	config = ConfigParser()
	config.readfp(open('mitm.conf'))
	print config.get('Server','ip')

def main():
	print "hello"
	parse_config()





if __name__ == '__main__':
    main()
