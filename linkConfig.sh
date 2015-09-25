#!/bin/sh
/bin/ln -s /root/mitmbox/config/interfaces /etc/network/interfaces
/bin/ln -l /root/mitmbox/config/swconfig /etc/network/if-pre-up.d/swconfig
