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

import struct

FRAME_CONTROL_HEADER_LENGTH = 2

TYPE_MGMT = 0b00
TYPE_CTRL = 0b01
TYPE_DATA = 0b10

TYPE_MGMT_SUBTYPE_ASSOCIATION_REQUEST = 0b0000
TYPE_MGMT_SUBTYPE_ASSOCIATION_RESPONSE = 0b0001
TYPE_MGMT_SUBTYPE_REASSOCIATION_REQUEST = 0b0010
TYPE_MGMT_SUBTYPE_REASSOCIATION_RESPONSE = 0b0011
TYPE_MGMT_SUBTYPE_PROBE_REQUEST = 0b0100
TYPE_MGMT_SUBTYPE_PROBE_RESPONSE = 0b0101
TYPE_MGMT_SUBTYPE_BEACON = 0b1000
TYPE_MGMT_SUBTYPE_ATIM = 0b1001
TYPE_MGMT_SUBTYPE_DISASSOCIATION = 0b1010
TYPE_MGMT_SUBTYPE_AUTHENTICATION = 0b1011
TYPE_MGMT_SUBTYPE_DEAUTHENTICATION = 0b1100
TYPE_MGMT_SUBTYPE_ACTION = 0b1101
TYPE_MGMT_SUBTYPE_ACTION_NO_ACK = 0b1110


def get_frame_type(frame_control):
    """
    Returns frame type.
    """
    return (ord(frame_control[0]) & 0b00001100) >> 2


def get_frame_subtype(frame_control):
    """
    Returns frame subtype.
    """
    return (ord(frame_control[0]) & 0b11110000) >> 4
