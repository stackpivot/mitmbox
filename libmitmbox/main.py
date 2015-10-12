"""

Ethernet Bridge

Description: Ethernet bridge for man-in-the-middle attacks.

Markus Mahrla, Jon Barg
GAI NetConsult GmbH

"""

import sys
import signal
import argparse
from threading import *
from ConfigParser import *
from pdb import *
from scapy.all import *
from socket import *

from .bridging.parse_config import Parse_MitmConfig
from .bridging.bridge import sniffer
from .bridging.tapDevice import init_tapDevices


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


def mitmbox():

    parser = argparse.ArgumentParser(
        description='mitmbox ethernet intercepter')

    parser.add_argument("-c", nargs=1, dest="config_file", type=str, action='store',
                        help='config file to intercept traffic', default='mitm.conf')

    parser.add_argument("-r", dest="rewrite", action='store_true',
                        help='rewrite mac address on second interface (taken from first interface)')

    args = parser.parse_args()
    mitm_config = Parse_MitmConfig(args.config_file[0])

    bridge0_interface = mitm_config.bridge0_interface
    bridge1_interface = mitm_config.bridge1_interface
    mitm_interface = mitm_config.mitm_interface

    init_tapDevices(bridge0_interface, bridge1_interface)

    sniffer1 = sniffer(bridge0_interface, bridge1_interface,
                       mitm_interface, 0, mitm_config.dst_ip, mitm_config.dst_mac)
    sniffer2 = sniffer(bridge1_interface, bridge0_interface,
                       mitm_interface, 0, mitm_config.dst_ip, mitm_config.dst_mac)
    sniffer3 = sniffer(bridge0_interface, bridge1_interface, 0,
                       mitm_interface, mitm_config.dst_ip, mitm_config.dst_mac)

    thread1 = Thread(target=sniffer1.recv_send_loop)
    thread2 = Thread(target=sniffer2.recv_send_loop)
    thread3 = Thread(target=sniffer3.recv_send_loop)

    # still_running_lock.acquire()

    thread1.start()
    thread2.start()
    thread3.start()

    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()

    sys.exit(0)
