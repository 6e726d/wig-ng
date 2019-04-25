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
# Radiotap helper functions.
#
# References:
# - https://www.radiotap.org/

import struct

# Present Flags
PF_TSFT_MASK  = 0b00000000000000000000000000000001
PF_FLAGS_MASK = 0b00000000000000000000000000000010

# Flags
F_FCS_AT_END_MASK = 0b00010000


def get_version(buff):
    """
    Returns header version.
    The version field indicates which major version of the radiotap header is
    in use. Currently, this is always 0.
    """
    version = ord(buff)[0]
    if version != 0:
        raise ValueError("Invalid Radiotap version.")
    return version

def get_length(buff):
    """
    Returns header length.
    The len field indicates the entire length of the radiotap data, including
    the radiotap header. This is valuable for the developer so they can
    consistently locate the beginning of the 802.11 frame that follows the
    radiotap data, even if their parser doesn’t understand all of the data
    fields specified.
    """
    length = struct.unpack("<H", buff[2:4])[0]
    return length

def get_present_flags(buff):
    """
    Returns present flags.
    The present flags field is a bitmask of the radiotap data fields that
    follows the radiotap header.
    """
    present_flags = struct.unpack("<I", buff[4:8])[0]
    return present_flags

def has_FCS(buff):
    """
    Returns a True if the FCS_AT_END bit flag is set.
    """
    present_flags = get_present_flags(buff)
    if (present_flags & PF_FLAGS_MASK) != 0:
        if (present_flags & PF_TSFT_MASK) != 0:
            offset = 16
        else:
            offset = 8
        flags = ord(buff[offset])
        return (flags & F_FCS_AT_END_MASK) >> 4
    raise ValueError("No Radiotap Flags!")
