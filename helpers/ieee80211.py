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

TYPE_MANAGEMENT = 0b00  # 0
TYPE_CONTROL = 0b01  # 1
TYPE_DATA = 0b10  # 2


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
