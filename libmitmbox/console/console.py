from ..global_vars import LOGGING, LOG_QUEUE, CONFIG
import time
import pdb
from scapy.all import *


SRC_IP_POS = 0x1a       # position of ip source address in packet
DST_IP_POS = 0x1e       # position of ip destination address in packet
SRC_PORT_POS = 0x22     # position of source port address in packet
DST_PORT_POS = 0x24     # position of destination port address in packet


def printLogs():
    while True:
        try:

            logEntry = LOG_QUEUE.get()

            direction = logEntry[0]
            pkt = logEntry[1]

            pkt_scapy = Ether(pkt)

            if pkt_scapy.getlayer("IP"):
                ip_src = pkt_scapy[IP].src
                ip_dst = pkt_scapy[IP].dst

                if pkt_scapy.getlayer("TCP"):
                    tcp_sport = pkt_scapy[TCP].sport
                    tcp_dport = pkt_scapy[TCP].dport

                    if ip_src == CONFIG.client_ip:
                        if direction is 'c_to_s':
                            print str(ip_src) + ":" + str(tcp_sport) + " --> " + str(ip_dst) + ":" + str(tcp_dport)
                        elif direction is 's_to_c':
                            print str(ip_dst) + ":" + str(tcp_dport) + " <-- " + str(ip_src) + ":" + str(tcp_sport)
                    elif ip_dst == CONFIG.client_ip:
                        if direction is 'c_to_s':
                            print str(ip_src) + ":" + str(tcp_sport) + " --> " + str(ip_dst) + ":" + str(tcp_dport)
                        elif direction is 's_to_c':
                            print str(ip_dst) + ":" + str(tcp_dport) + " <-- " + str(ip_src) + ":" + str(tcp_sport)
                    else:
                        if direction is 'c_to_s':
                            print str(ip_src) + ":" + str(tcp_sport) + " --> " + str(ip_dst) + ":" + str(tcp_dport)
                        elif direction is 's_to_c':
                            print str(ip_dst) + ":" + str(tcp_dport) + " <-- " + str(ip_src) + ":" + str(tcp_sport)

        except KeyboardInterrupt:
            return -1


def consoleOutput():

    finished = False
    time.sleep(0.5)
    while not finished:

        try:
            command = raw_input('mitmbox> ').split()
            if command:
                cmd = command[0].lower().strip()
                if cmd in ['help', '?']:
                    print "rld: reload configuration file\n" + \
                          "exit: stop mitmbox and exit" + \
                          "debug: pdb debugger"

                elif cmd in ['quit', 'exit', 'stop', 'leave']:
                    finished = True
                    QUIT = True

                elif cmd in ['rld', 'refresh', 'reload']:
                    print bcolors.WARNING + "reloading configuration file" + bcolors.ENDC
                    CONFIG.update()
                elif cmd in ['debug', 'dbg']:
                    pdb.set_trace()
                elif cmd in ['log']:
                    printLogs()

        except KeyboardInterrupt:
            # Ctrl+C detected, so let's finish the poison thread and exit
            finished = True
            QUIT = True
    print bcolors.FAIL + "\n\nEXITING" + bcolors.ENDC + " ... cleaning up"
