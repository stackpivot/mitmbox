import fcntl
import os
import struct

TUNSETIFF = 0x400454ca  # attach to tun/tap device
IFF_TAP = 0x0002    # utilize tap device, i.e. including ethernet layer
IFF_NO_IP = 0x1000  # omit packet information that is added by kernel


def init_tapDevices(bridge0_interface, bridge1_interface):
    os.system("ifconfig " + bridge0_interface + " promisc")
    os.system("ifconfig " + bridge1_interface + " promisc")
    os.system("ip tuntap add dev tap0 mode tap")
    os.system("ifconfig tap0 down")
    os.system("ifconfig tap0 hw ether 0e:33:7e:2f:19:61")
    os.system("ifconfig tap0 up")
    os.system("ifconfig tap0 1.2.3.4")
    os.system("route add -net 192.168.0.0 netmask 255.255.0.0 tap0")
    # todo: ARP request for source IP must answered

    tap_device = os.open('/dev/net/tun', os.O_RDWR)
    flags = struct.pack('16sH', "tap0", IFF_TAP | IFF_NO_IP)
    fcntl.ioctl(tap_device, TUNSETIFF, flags)
