import sys
import argparse
from threading import *
from ConfigParser import *
from pdb import *
from scapy.all import *
from socket import *
import Queue
import time

from .bridging.parse_config import Parse_MitmConfig
from .bridging.bridge import sniffer
from .bridging.tapDevice import init_tapDevices
from .common import bcolors

thread1 = None
thread2 = None
thread3 = None

still_running_lock = Lock()

# currently this Queue is used to tell the Bridging Threads to quit.
# int the future this feature could be used, to trigger a reread of the config
control_queue = Queue.Queue()


def mitmbox():

    parser = argparse.ArgumentParser(
        description='mitmbox ethernet intercepter')

    parser.add_argument("-c", nargs=1, dest="config_file", type=str, action='store',
                        help='config file to intercept traffic', default='/root/mitmbox/mitm.conf')

    args = parser.parse_args()
    mitm_config = Parse_MitmConfig(args.config_file)

    bridge0_interface = mitm_config.bridge0_interface
    bridge1_interface = mitm_config.bridge1_interface
    mitm_interface = mitm_config.mitm_interface

    init_tapDevices(bridge0_interface, bridge1_interface)

    bridge1 = MITMBridge(bridge0_interface, bridge1_interface, True)
    bridge2 = MITMBridge(bridge1_interface, bridge0_interface, True)
    bridge3 = MITMBridge(bridge0_interface, bridge1_interface, False)

    thread1 = Thread(target=bridge1.run_bridge)
    thread2 = Thread(target=bridge2.run_bridge)
    thread3 = Thread(target=bridge3.run_bridge)

    # still_running_lock.acquire()

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

                elif cmd in ['rld', 'refresh', 'reload']:
                    print bcolors.WARNING + "reloading configuration file" + bcolors.ENDC
                    mitm_config.trigger_parsing()
                    sniffer1.update_config(mitm_config)
                    sniffer2.update_config(mitm_config)
                    sniffer3.update_config(mitm_config)

    except KeyboardInterrupt:
        # Ctrl+C detected, so let's finish the poison thread and exit
        finish = True
    print bcolors.FAIL + "\n\nEXITING" + bcolors.ENDC + " ... cleaning up"
    control_queue.put(('endThread1',))
    control_queue.put(('endThread2',))
    control_queue.put(('endThread3',))
    sys.exit(0)
