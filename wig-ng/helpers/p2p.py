#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# wig-ng - Wireless Information Gathering New Generation
# Copyright (C) 2022 - Andrés Blanco (6e726d) <6e726d@gmail.com>
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

from collections import OrderedDict

from helpers import wps
from helpers import ieee80211


class InvalidP2PInformationElement(Exception):
    """Invalid P2P Information Element Exception."""
    pass


class P2PElements(object):
    """Contains all P2P data elements constants."""

    ID_STATUS = 0x00
    ID_MINOR_REASON_CODE = 0x01
    ID_P2P_CAPABILITY = 0x02
    ID_P2P_DEVICE_ID = 0x03
    ID_GROUP_OWNER_INTENT = 0x04
    ID_CONFIGURATION_TIMEOUT = 0x05
    ID_LISTEN_CHANNEL = 0x06
    ID_P2P_GROUP_BSSID = 0x07
    ID_EXTENDED_LISTEN_TIMING = 0x08
    ID_INTENDED_P2P_INTERFACE_ADDRESS = 0x09
    ID_P2P_MANAGEABILITY = 0x0A
    ID_CHANNEL_LIST = 0x0B
    ID_NOTICE_OF_ABSENCE = 0x0C
    ID_P2P_DEVICE_INFO = 0x0D
    ID_P2P_GROUP_INFO = 0x0E
    ID_P2P_GROUP_ID = 0x0F
    ID_P2P_INTERFACE = 0x10
    ID_OPERATING_CHANNEL = 0x11
    ID_INVITATION_FLAGS = 0x12
    ID_OUT_OF_BAND_GROUP_OWNER_NEGOTIATION_CHANNEL = 0x13
    ID_UNUSED = 0x14
    ID_SERVICE_HASH = 0x15
    ID_SESSION_INFORMATION_DATA_INFO = 0x16
    ID_CONNECTION_CAPABILITY_INFO = 0x17
    ID_ADVERTISEMENT_ID_INFO = 0x18
    ID_ADVERTISED_SERVICE_INFO = 0x19
    ID_SESSION_ID_INFO = 0x1A
    ID_FEATURE_CAPABILITY = 0x1B
    ID_PERSISTENG_GROUP_INFO = 0x1C
    ID_VENDOR_SPECIFIC = 0xDD

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for p2p_item in P2PElements.__dict__.items():
            k, v = p2p_item
            if v == value:
                return k.replace("_", " ").capitalize()[3:].replace("P2p", "P2P")
        return None


class P2PDeviceCapability(object):
    """Contains P2P Device Capabilities constants."""

    DEVICE_CAPABILITY_SERVICE_DISCOVERY          = 0b00000001
    DEVICE_CAPABILITY_P2P_CLIENT_DISCOVERABILITY = 0b00000010
    DEVICE_CAPABILITY_CONCURRENT_OPERATION       = 0b00000100
    DEVICE_CAPABILITY_P2P_INFRASTRUCTURE_MANAGED = 0b00001000
    DEVICE_CAPABILITY_P2P_DEVICE_LIMIT           = 0b00010000
    DEVICE_CAPABILITY_P2P_INVITATION_PROCEDURE   = 0b00100000

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for p2p_item in P2PDeviceCapability.__dict__.items():
            k, v = p2p_item
            if v == value:
                return k.replace("_", " ").lower()[len("DEVICE_CAPABILITY_"):]
        return None


class P2PGroupCapability(object):
    """Contains P2P Group Capabilities constants."""

    GROUP_CAPABILITY_P2P_GROUP_OWNER        = 0b00000001
    GROUP_CAPABILITY_PERSISTENT_P2P_GROUP   = 0b00000010
    GROUP_CAPABILITY_P2P_GROUP_LIMIT        = 0b00000100
    GROUP_CAPABILITY_INTRA_BSS_DISTRIBUTION = 0b00001000
    GROUP_CAPABILITY_CROSS_CONNECTION       = 0b00010000
    GROUP_CAPABILITY_PERSISTENT_RECONNECT   = 0b00100000
    GROUP_CAPABILITY_GROUP_FORMATION        = 0b01000000
    GROUP_CAPABILITY_IP_ADDRESS_ALLOCATION  = 0b10000000

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for p2p_item in P2PGroupCapability.__dict__.items():
            k, v = p2p_item
            if v == value:
                return k.replace("_", " ").lower()[len("GROUP_CAPABILITY_"):]
        return None


class P2PInformationElement(object):

    TLV_ID_LENGTH = 1
    TLV_SIZE_LENGTH = 2
    P2P_IE_SIZE_LENGTH = 1

    VENDOR_SPECIFIC_IE_ID = b"\xdd"  # Vendor Specific ID
    P2P_OUI = b"\x50\x6f\x9a"  # WFA specific OUI
    P2P_OUI_TYPE = b"\x09"  # P2P type
    FIXED_DATA_LENGTH = len(VENDOR_SPECIFIC_IE_ID) + P2P_IE_SIZE_LENGTH + len(P2P_OUI) + len(P2P_OUI_TYPE)

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__elements__ = OrderedDict()
        self.__do_basic_verification__()
        self.__process_buffer__()

    def get_elements(self):
        """Returns a dictionary with the WPS information."""
        return self.__elements__.items()

    def __do_basic_verification__(self):
        """
        Verify if the buffer has the minimal length necessary, the correct OUI and OUI type.
        """
        idx = 0
        if self.buffer_length <= self.FIXED_DATA_LENGTH:
            raise InvalidP2PInformationElement("Invalid buffer length.")
        if not struct.pack("B", self.buffer[idx]) == self.VENDOR_SPECIFIC_IE_ID:
            raise InvalidP2PInformationElement("Invalid P2P information element id.")
        idx += len(self.VENDOR_SPECIFIC_IE_ID) + self.P2P_IE_SIZE_LENGTH
        if not self.buffer[idx:self.FIXED_DATA_LENGTH] == self.P2P_OUI + self.P2P_OUI_TYPE:
            raise InvalidP2PInformationElement("Invalid P2P information element id.")

    def __process_buffer__(self):
        """
        Process data buffer, walkthrough all elements to verify the buffer boundaries and populate the __elements__
        attribute.
        """
        index = 0
        buff = self.buffer[self.FIXED_DATA_LENGTH:]
        while index < len(buff):
            if not len(buff[index:]) >= self.TLV_ID_LENGTH + self.TLV_SIZE_LENGTH:
                raise InvalidP2PInformationElement("TLV invalid data.")
            tlv_id = struct.unpack("B", buff[index:index+self.TLV_ID_LENGTH])[0]
            index += self.TLV_ID_LENGTH
            tlv_size = struct.unpack("H", buff[index:index + self.TLV_SIZE_LENGTH])[0]
            index += self.TLV_SIZE_LENGTH
            tlv_name = P2PElements.get_element_key(tlv_id)
            tlv_data = buff[index:index + tlv_size]
            if tlv_name:
                if tlv_id == P2PElements.ID_P2P_CAPABILITY:
                    self.__elements__.update(self.get_capability_attribute_string(tlv_data))
                    # self.__elements__[tlv_name] = self.get_capability_attribute_string(tlv_data)
                elif tlv_id == P2PElements.ID_P2P_DEVICE_INFO:
                    self.__elements__.update(self.get_device_information_attribute_string(tlv_data))
                    # self.__elements__[tlv_name] = self.get_device_information_attribute_string(tlv_data)
                else:
                    self.__elements__[tlv_name] = tlv_data
            index += tlv_size

    @staticmethod
    def get_capability_attribute_string(data):
        """Returns a string with the P2P device and group capabilities."""
        result = OrderedDict()
        dev_cap = data[0]
        grp_cap = data[1]
        dev_cap_lst = list()
        grp_cap_lst = list()
        # Device Capabilities
        if bool(P2PDeviceCapability.DEVICE_CAPABILITY_SERVICE_DISCOVERY & dev_cap):
            aux = P2PDeviceCapability.get_element_key(P2PDeviceCapability.DEVICE_CAPABILITY_SERVICE_DISCOVERY)
            dev_cap_lst.append(aux)
        if bool(P2PDeviceCapability.DEVICE_CAPABILITY_P2P_CLIENT_DISCOVERABILITY & dev_cap):
            aux = P2PDeviceCapability.get_element_key(
                P2PDeviceCapability.DEVICE_CAPABILITY_P2P_CLIENT_DISCOVERABILITY)
            dev_cap_lst.append(aux)
        if bool(P2PDeviceCapability.DEVICE_CAPABILITY_CONCURRENT_OPERATION & dev_cap):
            aux = P2PDeviceCapability.get_element_key(P2PDeviceCapability.DEVICE_CAPABILITY_CONCURRENT_OPERATION)
            dev_cap_lst.append(aux)
        if bool(P2PDeviceCapability.DEVICE_CAPABILITY_P2P_INFRASTRUCTURE_MANAGED & dev_cap):
            aux = P2PDeviceCapability.get_element_key(
                P2PDeviceCapability.DEVICE_CAPABILITY_P2P_INFRASTRUCTURE_MANAGED)
            dev_cap_lst.append(aux)
        if bool(P2PDeviceCapability.DEVICE_CAPABILITY_P2P_DEVICE_LIMIT & dev_cap):
            aux = P2PDeviceCapability.get_element_key(P2PDeviceCapability.DEVICE_CAPABILITY_P2P_DEVICE_LIMIT)
            dev_cap_lst.append(aux)
        if bool(P2PDeviceCapability.DEVICE_CAPABILITY_P2P_INVITATION_PROCEDURE & dev_cap):
            aux = P2PDeviceCapability.get_element_key(
                P2PDeviceCapability.DEVICE_CAPABILITY_P2P_INVITATION_PROCEDURE)
            dev_cap_lst.append(aux)
        # Group Capabilities
        if bool(P2PGroupCapability.GROUP_CAPABILITY_P2P_GROUP_OWNER & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_P2P_GROUP_OWNER)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_PERSISTENT_P2P_GROUP & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_PERSISTENT_P2P_GROUP)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_P2P_GROUP_LIMIT & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_P2P_GROUP_LIMIT)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_INTRA_BSS_DISTRIBUTION & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_INTRA_BSS_DISTRIBUTION)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_CROSS_CONNECTION & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_CROSS_CONNECTION)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_PERSISTENT_RECONNECT & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_PERSISTENT_RECONNECT)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_GROUP_FORMATION & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_GROUP_FORMATION)
            grp_cap_lst.append(aux)
        if bool(P2PGroupCapability.GROUP_CAPABILITY_IP_ADDRESS_ALLOCATION & grp_cap):
            aux = P2PGroupCapability.get_element_key(P2PGroupCapability.GROUP_CAPABILITY_IP_ADDRESS_ALLOCATION)
            grp_cap_lst.append(aux)
        result['P2P Device Capabilities'] = ", ".join(dev_cap_lst)
        result['P2P Group Capabilities'] = ", ".join(grp_cap_lst)
        return result

    @staticmethod
    def get_device_information_attribute_string(data):
        """Returns a string with the P2P device information."""
        result = OrderedDict()
        min_size = 21
        if len(data) < min_size:
            return "Invalid device information attribute."
        offset = 0
        mac_address = ieee80211.get_string_mac_address_from_buffer(data[offset:offset+6])
        offset += 6
        config_methods_raw = data[offset:offset+2]
        config_methods_str = wps.WPSInformationElement.get_config_methods_string(config_methods_raw).decode("ascii")
        offset += 2
        primary_dev_type_raw = data[offset:offset+8]
        primary_dev_type_str = wps.WPSInformationElement.get_primary_device_type_string(primary_dev_type_raw).decode("ascii")
        offset += 8
        number_secondary_dev_types = data[offset]
        offset += 1
        # TODO: Process Secondary Device Types List
        for idx in range(number_secondary_dev_types):
            aux = data[offset:offset+8]
            offset += 8
        offset += 2
        device_name_length = struct.unpack(">H", data[offset:offset + 2])[0]
        offset += 2
        device_name_str = data[offset:offset+device_name_length].decode("ascii")
        result['P2P Device Address'] = mac_address
        result['P2P Config Methods'] = config_methods_str
        result['P2P Primary Device Type'] = primary_dev_type_str
        result['P2P Number of Secondary Device Types'] = str(number_secondary_dev_types)
        result['P2P Device Name'] = device_name_str
        return result
