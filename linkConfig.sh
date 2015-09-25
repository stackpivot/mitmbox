#!/bin/sh
/bin/ln -s /root/mitmbox/config/interfaces /etc/network/interfaces
/bin/ln -s /root/mitmbox/config/swconfig /etc/network/if-pre-up.d/swconfig
/bin/ln -s /root/mitmbox/config/renameInterfaces /etc/network/if-up.d/renameInterfaces
