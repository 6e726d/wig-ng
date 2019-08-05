#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# wig-ng - Wireless Information Gathering New Generation
# Copyright (C) 2019 - Andrés Blanco (6e726d) <6e726d@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os

# SYSFS related constants
SYS_CLASS_NET = "/sys/class/net/"
SYS_WIRELESS = "wireless"
SYS_PHY80211 = "phy80211"

# IEEE 802.11 related device types
ARPHRD_IEEE80211 = 801
ARPHRD_IEEE80211_RADIOTAP = 803

# LINK-LAYER HEADER TYPES
# https://www.tcpdump.org/linktypes.html
DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127

# Pcap Constants
PCAP_SNAPLEN = 65535
PCAP_PROMISC = False
PCAP_TIMEOUT = 100  # in miliseconds


def get_ieee80211_network_interfaces():
    """
    Returns a list of IEEE 802.11 network interface names.

    Each of the entries in /sys/class/net/ is a symbolic link representing one
    of the real or virtual networking devices that are visible in the network
    namespace of the process that is accessing the directory. Each of these
    symbolic links refers to entries in the /sys/devices directory.

    References:
     - http://man7.org/linux/man-pages/man5/sysfs.5.html
     - https://www.kernel.org/doc/html/v4.16/admin-guide/sysfs-rules.html
    """
    ifaces = list()
    for iface in os.listdir(SYS_CLASS_NET):
        iface_sys_path = os.path.join(SYS_CLASS_NET, iface)
        iface_sys_list_dir = os.listdir(iface_sys_path)
        if (SYS_WIRELESS in iface_sys_list_dir) and \
           (SYS_PHY80211 in iface_sys_list_dir):
            ifaces.append(iface)
    return ifaces


def is_monitor_mode_set(network_interface):
    """
    Returns True if the IEEE 802.11 network interface is in monitor mode.

    References:
     - https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_arp.h
    """
    path = os.path.join(SYS_CLASS_NET, network_interface, "type")
    if not os.path.exists(path):
        raise Exception("Invalid network interface.")
    fd = open(path, "rb")
    value = int(fd.read().strip())
    fd.close()
    if value == ARPHRD_IEEE80211 or value == ARPHRD_IEEE80211_RADIOTAP:
        return True
    return False
