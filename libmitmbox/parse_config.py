from ConfigParser import *
import pdb


class Parse_MitmConfig():

    def __init__(self, configFile):

        # pdb.set_trace()
        # TODO Check if file exists
        config = ConfigParser()
        config.readfp(open(configFile))

        self.dsp_ip = config.get('Destination', 'ip')
        self.dst_mac = config.get('Destination', 'mac')
        self.dst_port = config.get('Destination', 'port')

        self.src_ip = config.get('Source', 'ip')
        self.src_mac = config.get('Source', 'mac')
        self.src_port = config.get('Source', 'port')

        self.bridge0_interface = config.get('Interfaces', 'bridge0')
        self.bridge1_interface = config.get('Interfaces', 'bridge1')
        self.mitm_interface = config.get('Interfaces', 'mitm')
        # TODO: add interfaces to bridge
