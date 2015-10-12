#!/bin/sh
/bin/ln -s /root/mitmbox/os_configuration/config/interfaces /etc/network/interfaces
/bin/ln -s /root/mitmbox/os_configuration/config/swconfig /etc/network/if-pre-up.d/swconfig
/bin/ln -s /root/mitmbox/os_configuration/config/renameInterfaces /etc/network/if-up.d/renameInterfaces
/bin/ln -f -s /root/mitmbox/os_configuration/config/wifiAP/hostapd /usr/sbin/hostapd
/bin/ln -f -s /root/mitmbox/os_configuration/config/wifiAP/hostapd_cli /usr/sbin/hostapd_cli
/bin/ln -s /root/mitmbox/os_configuration/config/wifiAP/hostapd.conf /etc/hostapd.conf
/bin/ln -f -s /root/mitmbox/os_configuration/config/wifiAP/default/hostapd /etc/default/hostapd
