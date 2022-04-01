#!/usr/bin/env python3
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

# Structures Size
VERSION_SIZE = 1
PADDING_SIZE = 1
LENGTH_SIZE = 2
PRESENT_FLAGS_SIZE = 4
MAC_TIMESTAMP_SIZE = 8

# Present Flags
PF_TSFT_MASK  = 0b00000000000000000000000000000001
PF_FLAGS_MASK = 0b00000000000000000000000000000010
EF_FLAGS_MASK = 0b10000000000000000000000000000000  # Extended presence masks

# Flags
F_FCS_AT_END_MASK = 0b00010000

# Version Constant
SUPPORTED_VERSION = 0


class InvalidRadiotap(Exception):
    pass


def get_version(buff):
    """
    Returns header version.
    The version field indicates which major version of the radiotap header is
    in use. Currently, this is always 0.
    """
    idx = 0
    version = buff[idx]
    if version != SUPPORTED_VERSION:
        raise InvalidRadiotap("Invalid Radiotap version.")
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
    idx = 2
    size = LENGTH_SIZE
    length = struct.unpack("<H", buff[idx:idx+size])[0]
    return length

def get_present_flags(buff):
    """
    Returns a list of present flags.
    The present flags field is a bitmask of the radiotap data fields that
    follows the radiotap header.
    """
    idx = 4
    size = PRESENT_FLAGS_SIZE
    result = list()
    while True:
        present_flags = struct.unpack("<I", buff[idx:idx+size])[0]
        result.append(present_flags)
        if (present_flags & EF_FLAGS_MASK) == 0:
            break
        idx += size
    return result

def has_FCS(buff):
    """
    Returns a True if the FCS_AT_END bit flag is set.
    """
    present_flags_list = get_present_flags(buff)
    # To check for FCS we only need the first present flags.
    present_flags = present_flags_list[0]
    present_flags_end = len(present_flags_list) * PRESENT_FLAGS_SIZE
    offset = VERSION_SIZE + PADDING_SIZE + LENGTH_SIZE + present_flags_end
    # Alignment?
    if offset % 8 != 0:
        offset += offset % 8
    if (present_flags & PF_FLAGS_MASK) != 0:
        if (present_flags & PF_TSFT_MASK) != 0:
            offset += MAC_TIMESTAMP_SIZE
        flags = buff[offset]
        return (flags & F_FCS_AT_END_MASK) >> 4
    raise InvalidRadiotap("Invalid Radiotap Header.")
