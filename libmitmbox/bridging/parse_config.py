from ConfigParser import *


class Parse_MitmConfig():

    def __init__(self, configFile):
        self.config = ConfigParser()
        self.configFile = configFile
        self.trigger_parsing()

    '''
    trigger_parsing is a seperate function, to reread the configuration file if needed. This feature might be implemented in the future
    '''

    def trigger_parsing(self):

        # TODO Check if file exists
        self.config.readfp(open(self.configFile))

        self.dst_ip = self.config.get('Destination', 'ip')
        self.dst_mac = self.config.get('Destination', 'mac')
        self.dst_port = self.config.get('Destination', 'port')

        self.src_ip = self.config.get('Source', 'ip')
        self.src_mac = self.config.get('Source', 'mac')
        self.src_port = self.config.get('Source', 'port')

        self.bridge0_interface = self.config.get('Interfaces', 'bridge0')
        self.bridge1_interface = self.config.get('Interfaces', 'bridge1')
        self.mitm_interface = self.config.get('Interfaces', 'mitm')
