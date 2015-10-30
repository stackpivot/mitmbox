from ..global_vars import LOGGING, LOG_QUEUE, CONFIG, bcolors
import time
import pdb
from scapy.all import *


SRC_IP_POS = 0x1a       # position of ip source address in packet
DST_IP_POS = 0x1e       # position of ip destination address in packet
SRC_PORT_POS = 0x22     # position of source port address in packet
DST_PORT_POS = 0x24     # position of destination port address in packet

# TCP FLAGS
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80



def formatOutput(sender, receiver, direction, flags, color):
    out = ''
    out += sender + ' '*(21 - len(sender))
    out += ' ' + direction + ' '
    out += receiver + ' '*(21 - len(receiver))

    out += '   ' + flags
    if color == 'WARNING':
        return bcolors.WARNING + out + bcolors.ENDC
    if 'SYN' in flags:
        return bcolors.OKGREEN + out + bcolors.ENDC
    return out

def getFlags(pkt):

    flagString = '  ('
    F = pkt['TCP'].flags
    if F & SYN:
        flagString += 'SYN'
        if F & ACK:
            flagString += '/ACK'
    elif F & ACK:
        flagString += 'data'
    elif F & FIN:
        flagString += 'FIN'
    return flagString + ')'


def printLogs():
    while True:
        try:

            logEntry = LOG_QUEUE.get()

            traf_direction = logEntry[0]
            pkt = logEntry[1]

            pkt_scapy = Ether(pkt)

            if pkt_scapy.getlayer("IP"):
                ip_src = str(pkt_scapy[IP].src)
                ip_dst = str(pkt_scapy[IP].dst)

                if pkt_scapy.getlayer("TCP"):
                    tcp_sport = str(pkt_scapy[TCP].sport)
                    tcp_dport = str(pkt_scapy[TCP].dport)

                    sender = ip_src + ':' + tcp_sport
                    receiver = ip_dst + ':' + tcp_dport
                    print traf_direction
                    if ip_src == CONFIG.client_ip and traf_direction is 'c_to_s':
                            direction = ' --> '
                    elif ip_dst == CONFIG.client_ip and traf_direction is 's_to_c':
                            direction = ' <-- '
                            receiver = ip_src + ':' + tcp_sport
                            sender = ip_dst + ':' + tcp_dport
                    elif traf_direction is 'c_to_s':
                        direction = ' --> '
                    elif traf_direction is 'to_m':
                        direction = ' ^^^ '
                    elif traf_direction is 'm_to_c':
                        direction = ' <--v '
                    elif traf_direction is 'm_to_s':
                        direction = ' v--> '
                    else:
                        direction = ' <-- '

                    color = None
                    if 'm' in traf_direction:
                        color = 'WARNING'
                    print formatOutput(sender, receiver, direction, getFlags(pkt_scapy), color)


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
