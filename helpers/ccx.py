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
import socket


CISCO_CCX_IE_DEVICE_NAME_ID = 0x85
CISCO_CCX_IE_IP_ADDRESS_ID = 0x95


class InvalidCCXInformationElement(Exception):
    """Invalid CCX Information Element Exception."""
    pass


class CiscoCCX85InformationElement(object):

    TLV_HEADER_SIZE = 2
    DEVICE_NAME_OFFSET = 10 + TLV_HEADER_SIZE
    DEVICE_NAME_VALUE_SIZE = 16
    ASSOCIATED_CLIENTS_OFFSET = 26 + TLV_HEADER_SIZE

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__device_name__ = str()
        self.__associated_clients__ = int()
        self.__do_basic_verification__()
        self.__process_buffer__()

    def get_device_name(self):
        """Return the device name value in the information element."""
        return self.__device_name__

    def get_associated_clients(self):
        """Return the associated clients value in the information element."""
        return self.__associated_clients__

    def __do_basic_verification__(self):
        """Verify if the buffer has the minimal length necessary."""
        tlv_id = struct.unpack("B", self.buffer[0])[0]
        tlv_size = struct.unpack("B", self.buffer[1])[0]
        if not tlv_id == CISCO_CCX_IE_DEVICE_NAME_ID:
            raise InvalidCCXInformationElement()
        if tlv_size < self.ASSOCIATED_CLIENTS_OFFSET or self.buffer_length < self.ASSOCIATED_CLIENTS_OFFSET:
            raise InvalidCCXInformationElement()

    def __process_buffer__(self):
        """Process data buffer and get device name and associated clients."""
        aux_buff = self.buffer[self.DEVICE_NAME_OFFSET:self.DEVICE_NAME_OFFSET+self.DEVICE_NAME_VALUE_SIZE]
        self.__device_name__ = struct.unpack("16s", aux_buff)[0].replace("\x00", "")
        self.__associated_clients__ = struct.unpack("B", self.buffer[self.ASSOCIATED_CLIENTS_OFFSET])[0]


class CiscoCCX95InformationElement(object):

    TLV_HEADER_SIZE = 2
    TLV_MIN_SIZE = 10
    IP_ADDRESS_OFFSET = 4 + TLV_HEADER_SIZE
    IP_ADDRESS_SIZE = 4

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__ip_address__ = str()
        self.__do_basic_verification__()
        self.__process_buffer__()

    def get_ip_address(self):
        """Return the IP address value in the information element."""
        return self.__ip_address__

    def __do_basic_verification__(self):
        """Verify if the buffer has the minimal length necessary."""
        tlv_id = struct.unpack("B", self.buffer[0])[0]
        tlv_size = struct.unpack("B", self.buffer[1])[0]
        if not tlv_id == CISCO_CCX_IE_IP_ADDRESS_ID:
            raise InvalidCCXInformationElement()
        if tlv_size < self.TLV_MIN_SIZE:
            raise InvalidCCXInformationElement()

    def __process_buffer__(self):
        """Process data buffer and get ip address."""
        buff = self.buffer[self.IP_ADDRESS_OFFSET:self.IP_ADDRESS_OFFSET+self.IP_ADDRESS_SIZE]
        self.__ip_address__ = socket.inet_ntoa(buff)
