from ConfigParser import *
import Queue
CONFIG_FILE = "/root/mitmbox/mitm.conf"

CTRL_QUEUE = Queue()

class MODE:
    BRIDGE = 0
    IMPERSONATE_CLIENT = 1
    IMPERSONATE_SERVER = 2
    MANIPULATE = 3

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Conf():

    def __init__(self, configFile):
        self.config = ConfigParser()
        self.configFile = configFile
        self.trigger_parsing()

    def trigger_parsing(self):

        # TODO Check if file exists
        self.config.readfp(open(self.configFile))

        self.server_ip = self.config.get('Destination', 'ip')
        self.server_mac = self.config.get('Destination', 'mac')
        self.server_port = self.config.get('Destination', 'port')

        self.client_ip = self.config.get('Source', 'ip')
        self.client_mac = self.config.get('Source', 'mac')
        self.client_port = self.config.get('Source', 'port')

        self.bridge0_interface = self.config.get('Interfaces', 'bridge0')
        self.bridge1_interface = self.config.get('Interfaces', 'bridge1')
        self.mitm_interface = self.config.get('Interfaces', 'mitm')


CONFIG = Conf(CONFIG_FILE)
