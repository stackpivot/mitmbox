import os
import struct


def init_tapDevices(bridge0_interface, bridge1_interface):

    # os.system("ip link delete tap0")
    os.system("ifconfig " + bridge0_interface + " promisc")
    os.system("ifconfig " + bridge1_interface + " promisc")
    os.system("ip tuntap add dev tap0 mode tap")
    os.system("ifconfig tap0 down")
    os.system("ifconfig tap0 hw ether 0e:33:7e:2f:19:61")
    os.system("ifconfig tap0 up")
    os.system("ifconfig tap0 1.2.3.4")
    os.system("route add -net 192.168.0.0 netmask 255.255.0.0 tap0")
    # todo: ARP request for source IP must answered
