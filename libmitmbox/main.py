import sys
import argparse
from threading import *
from ConfigParser import *
from pdb import *
from scapy.all import *
from socket import *
import time
import pdb

from .bridging.bridge import MITMBridge
from .bridging.tunDevice import init_tunDevices
from .global_vars import bcolors, CONFIG, CONFIG_FILE, CTRL_QUEUE, QUIT


thread1 = None
thread2 = None
thread3 = None


def mitmbox():

    parser = argparse.ArgumentParser(
        description='mitmbox ethernet intercepter')

    parser.add_argument("-c", nargs=1, dest="config_file", type=str, action='store',
                        help='config file to intercept traffic', default='/root/mitmbox/mitm.conf')

    args = parser.parse_args()
    CONFIG_FILE = args.config_file[0]

    bridge0_interface = CONFIG.bridge0_interface
    bridge1_interface = CONFIG.bridge1_interface

    init_tunDevices()

    bridge1 = MITMBridge(bridge0_interface, bridge1_interface, True)
    bridge2 = MITMBridge(bridge1_interface, bridge0_interface, True)
    bridge3 = MITMBridge(bridge0_interface, bridge1_interface, False)

    thread1 = Thread(target=bridge1.run_bridge)
    thread2 = Thread(target=bridge2.run_bridge)
    thread3 = Thread(target=bridge3.run_bridge)

    thread1.start()
    thread2.start()
    thread3.start()

    finish = False
    os.system('clear')
    try:
        while not finish:
            time.sleep(1)  # delay is a quick hack to kind of sync output

            command = raw_input('mitmbox> ').split()
            if command:
                cmd = command[0].lower().strip()
                if cmd in ['help', '?']:
                    print "rld: reload configuration file\n" + \
                          "exit: stop mitmbox and exit"

                elif cmd in ['quit', 'exit', 'stop', 'leave']:
                    finish = True
                    QUIT = True

                elif cmd in ['rld', 'refresh', 'reload']:
                    print bcolors.WARNING + "reloading configuration file" + bcolors.ENDC
                    CONFIG.update()
                elif cmd in ['debug', 'dbg']:
                    pdb.set_trace()

    except KeyboardInterrupt:
        # Ctrl+C detected, so let's finish the poison thread and exit
        finish = True
        QUIT = True
    print bcolors.FAIL + "\n\nEXITING" + bcolors.ENDC + " ... cleaning up"

    time.sleep(2)
    sys.exit(0)
