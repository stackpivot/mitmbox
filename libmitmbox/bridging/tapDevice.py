import os
import struct


def init_tapDevices(bridge0_interface, bridge1_interface):

    # os.system("ip link delete tap0")
    os.system("ifconfig " + bridge0_interface + " promisc")
    os.system("ifconfig " + bridge1_interface + " promisc")
    # add tun device and assign IP address
    os.system("ip tuntap add dev tun0 mode tun")
    os.system("ifconfig tun0 1.2.3.4")
    # add network route so kernel sends traffic via tun device by default
    os.system("route add -net 0.0.0.0 netmask 0.0.0.0 tun0")
    # rewrite ip address of tun device via iptables which also
    # facilitates transparent proxying for user-space applications
    os.system("iptables -t nat -F")
    os.system("iptables -t nat -A PREROUTING -i tun0 -p tcp -j REDIRECT")
    os.system(
        "iptables -t nat -A POSTROUTING -s 1.2.3.4 -j SNAT --to-source " + client_ip)
