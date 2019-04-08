#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2018 Andrés Blanco <6e726d@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for
# any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
# AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import os

# SYSFS related constants
SYS_CLASS_NET = "/sys/class/net/"
SYS_WIRELESS = "wireless"
SYS_PHY80211 = "phy80211"

# IEEE 802.11 related device types
ARPHRD_IEEE80211 = 801
ARPHRD_IEEE80211_RADIOTAP = 803

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
    value = fd.read()
    fd.close()
    if value == ARPHRD_IEEE80211 or value == ARPHRD_IEEE80211_RADIOTAP:
        return True
    return False
