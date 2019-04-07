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
