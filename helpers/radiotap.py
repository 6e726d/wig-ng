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
#
# Radiotap helper functions.
#
# References:
# - https://www.radiotap.org/

import struct


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
