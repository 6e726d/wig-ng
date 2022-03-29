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


class InvalidWPSInformationElement(Exception):
    """Invalid WPS Information Element Exception."""
    pass


class WPSElements(object):
    """Contains all WPS data elements constants."""

    ID_AP_CHANNEL = 0x1001
    ID_ASSOCIATION_STATE = 0x1002
    ID_AUTHENTICATION_TYPE = 0x1003
    ID_AUTHENTICATION_TYPE_FLAGS = 0x1004
    ID_AUTHENTICATOR = 0x1005
    ID_CONFIG_METHODS = 0x1008
    ID_CONFIGURATION_ERROR = 0x1009
    ID_CONFIRMATION_URL4 = 0x100A
    ID_CONFIRMATION_URL6 = 0x100B
    ID_CONNECTION_TYPE = 0x100C
    ID_CONNECTION_TYPE_FLAGS = 0x100D
    ID_CREDENTIAL = 0x100E
    ID_DEVICE_NAME = 0x1011
    ID_DEVICE_PASSWORD_ID = 0x1012
    ID_E_HASH1 = 0x1014
    ID_E_HASH2 = 0x1015
    ID_E_SNONCE1 = 0x1016
    ID_E_SNONCE2 = 0x1017
    ID_ENCRYPTED_SETTINGS = 0x1018
    ID_ENCRYPTED_TYPE = 0x100F
    ID_ENCRYPTED_TYPE_FLAGS = 0x1010
    ID_ENROLLEE_NONCE = 0x101A
    ID_FEATURE_ID = 0x101B
    ID_IDENTITY = 0x101C
    ID_IDENTITY_PROOF = 0x101D
    ID_KEY_WRAP_AUTHENTICATOR = 0x101E
    ID_KEY_IDENTIFIER = 0x101F
    ID_MAC_ADDRESS = 0x1020
    ID_MANUFACTURER = 0x1021
    ID_MESSAGE_TYPE = 0x1022
    ID_MODEL_NAME = 0x1023
    ID_MODEL_NUMBER = 0x1024
    ID_NETWORK_INDEX = 0x1026
    ID_NETWORK_KEY = 0x1027
    ID_NETWORK_KEY_INDEX = 0x1028
    ID_NEW_DEVICE_NAME = 0x1029
    ID_NEW_PASSWORD = 0x102A
    ID_OOB_DEVICE_PASSWORD = 0x102C
    ID_OS_VERSION = 0x102D
    ID_POWER_LEVEL = 0x102F
    ID_PSK_CURRENT = 0x1030
    ID_PSK_MAX = 0x1031
    ID_PUBLIC_KEY = 0x1032
    ID_RADIO_ENABLED = 0x1033
    ID_REBOOT = 0x1034
    ID_REGISTRAR_CURRENT = 0x1035
    ID_REGISTRAR_ESTABLISHED = 0x1036
    ID_REGISTRAR_LIST = 0x1037
    ID_REGISTRAR_MAX = 0x1038
    ID_REGISTRAR_NONCE = 0x1039
    ID_REQUEST_TYPE = 0x103A
    ID_RESPONSE_TYPE = 0x103B
    ID_RF_BANDS = 0x103C
    ID_R_HASH1 = 0x103D
    ID_R_HASH2 = 0x103E
    ID_R_SNONCE1 = 0x103F
    ID_R_SNONCE2 = 0x1040
    ID_SELECT_REGISTRAR = 0x1041
    ID_SERIAL_NUMBER = 0x1042
    ID_WIFI_PROTECTED_SETUP_STATE = 0x1044
    ID_SSID = 0x1045
    ID_TOTAL_NETWORKS = 0x1046
    ID_UUID_E = 0x1047
    ID_UUID_R = 0x1048
    ID_VENDOR_EXTENSION = 0x1049
    ID_VERSION = 0x104A
    ID_X509_CERTIFICATE_REQUEST = 0x104B
    ID_X509_CERTIFICATE = 0x104C
    ID_EAP_IDENTITY = 0x104D
    ID_MESSAGE_COUNTER = 0x104E
    ID_PUBLIC_KEY_HASH = 0x104F
    ID_REKEY_KEY = 0x1050
    ID_KEY_LIFETIME = 0x1051
    ID_PERMITED_CONFIG_METHODS = 0x1052
    ID_SELECTED_REGISTRAR_CONFIG_METHODS = 0x1053
    ID_PRIMARY_DEVICE_TYPE = 0x1054
    ID_SECONDARY_DEVICE_TYPE_LIST = 0x1055
    ID_PORTABLE_DEVICE = 0x1056
    ID_AP_SETUP_LOCKED = 0x1057
    ID_APPLICATION_EXTENSION = 0x1058
    ID_EAP_TYPE = 0x1059
    ID_INITIALIZATION_VECTOR = 0x1060
    ID_PROVIDED_AUTOMATICALLY = 0x1061
    ID_8021X_ENABLED = 0x1062
    ID_APP_SESSION_KEY = 0x1063
    ID_WEP_TRANSMIT_KEY = 0x1064

    ID_CONFIG_METHODS_SIZE = 2
    ID_VERSION_SIZE = 1
    ID_WIFI_PROTECTED_SETUP_STATE_SIZE = 1
    ID_UUID_SIZE = 16
    ID_PRIMARY_DEVICE_TYPE_SIZE = 8

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for wps_item in WPSElements.__dict__.items():
            k, v = wps_item
            if v == value:
                return k.replace("_", " ").lower()[len("ID_"):]
        return None


class WPSConfigurationMethods(object):
    CONFIG_METHOD_USB = 0x0001
    CONFIG_METHOD_ETHERNET = 0x0002
    CONFIG_METHOD_LABEL = 0x0004
    CONFIG_METHOD_DISPLAY = 0x0008
    CONFIG_METHOD_EXTERNAL_NFC_TOKEN = 0x0010
    CONFIG_METHOD_INTEGRATED_NFC_TOKEN = 0x0020
    CONFIG_NFC_INTERFACE = 0x0040
    CONFIG_METHOD_PUSH_BUTTON = 0x0080
    CONFIG_METHOD_KEYPAD = 0x0100

    @staticmethod
    def get_element_key(value):
        """Returns string based on the value parameter."""
        for wps_item in WPSElements.__dict__.items():
            k, v = wps_item
            if v == value:
                return k.replace("_", " ").lower()[len("CONFIG_METHOD_"):]
        return None


class WPSInformationElement(object):
    """TODO"""

    TLV_ID_LENGTH = 2
    TLV_SIZE_LENGTH = 2
    WPS_IE_SIZE_LENGTH = 1

    VENDOR_SPECIFIC_IE_ID = b"\xdd"  # Vendor Specific ID
    WPS_OUI = b"\x00\x50\xf2"  # Microsoft OUI (WiFi Alliance)
    WPS_OUI_TYPE = b"\x04"  # WPS type
    FIXED_DATA_LENGTH = len(VENDOR_SPECIFIC_IE_ID) + WPS_IE_SIZE_LENGTH + len(WPS_OUI) + len(WPS_OUI_TYPE)

    def __init__(self, buff):
        self.buffer = buff
        self.buffer_length = len(buff)
        self.__elements__ = dict()
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
            raise InvalidWPSInformationElement("Invalid buffer length.")
        if not struct.pack("B", self.buffer[idx]) == self.VENDOR_SPECIFIC_IE_ID:
            raise InvalidWPSInformationElement("Invalid WPS information element id.")
        idx += len(self.VENDOR_SPECIFIC_IE_ID) + self.WPS_IE_SIZE_LENGTH
        if not self.buffer[idx:self.FIXED_DATA_LENGTH] == self.WPS_OUI + self.WPS_OUI_TYPE:
            raise InvalidWPSInformationElement("Invalid WPS information element id.")

    @staticmethod
    def get_config_methods_string(data):
        """Returns a string with the WPS configuration methods based on the data parameter."""
        config_methods_list = list()
        config_method_value = struct.unpack("!H", data)[0]
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_USB:
            config_methods_list.append("USB")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_ETHERNET:
            config_methods_list.append("Ethernet")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_LABEL:
            config_methods_list.append("Label")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_DISPLAY:
            config_methods_list.append("Display")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_EXTERNAL_NFC_TOKEN:
            config_methods_list.append("External NFC Token")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_INTEGRATED_NFC_TOKEN:
            config_methods_list.append("Integrated NFC Token")
        if config_method_value & WPSConfigurationMethods.CONFIG_NFC_INTERFACE:
            config_methods_list.append("NFC Interface")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_PUSH_BUTTON:
            config_methods_list.append("Push Button")
        if config_method_value & WPSConfigurationMethods.CONFIG_METHOD_KEYPAD:
            config_methods_list.append("Keypad")
        return bytes(", ".join(config_methods_list), 'ascii')

    def get_version_string(self, data):
        """Returns a string with the WPS version based on the data parameter."""
        value = "%02X" % struct.unpack("B", data)[0]
        return bytes("%s.%s" % (value[0], value[1]), 'ascii')

    def get_setup_state_string(self, data):
        """Returns a string with the WPS version based on the data parameter."""
        value = struct.unpack("B", data)[0]
        if value == 1:
            return b"Not-Configured"
        elif value == 2:
            return b"Configured"
        else:
            return b"Invalid Value"

    def get_uuid_string(self, data):
        """Returns a string with the WPS UUID based on the data parameter."""
        uuid = str()
        for char in data:
            uuid += "%02X" % char
        return bytes(uuid, 'ascii')

    @staticmethod
    def get_primary_device_type_string(data):
        """Returns a string with the WPS primary device type based on the data parameter."""
        primary_device_type = str()
        category = struct.unpack("!H", data[:2])[0]
        # subcategory = struct.unpack("!H", data[6:8])[0]
        if category == 1:
            primary_device_type = b"Computer"
        elif category == 2:
            primary_device_type = b"Input Device"
        elif category == 3:
            primary_device_type = b"Printers, Scanners, Faxes and Copiers"
        elif category == 4:
            primary_device_type = b"Camera"
        elif category == 5:
            primary_device_type = b"Storage"
        elif category == 6:
            primary_device_type = b"Network Infrastructure"
        elif category == 7:
            primary_device_type = b"Displays"
        elif category == 8:
            primary_device_type = b"Multimedia Devices"
        elif category == 9:
            primary_device_type = b"Gaming Devices"
        elif category == 10:
            primary_device_type = b"Telephone"
        return primary_device_type

    def __process_buffer__(self):
        """
        Process data buffer, walkthrough all elements to verify the buffer boundaries and populate the __elements__
        attribute.
        """
        index = 0
        buff = self.buffer[self.FIXED_DATA_LENGTH:]
        while index < len(buff):
            if not len(buff[index:]) > self.TLV_ID_LENGTH + self.TLV_SIZE_LENGTH:
                raise InvalidWPSInformationElement("TLV invalid data.")
            tlv_id = struct.unpack("!H", buff[index:index + self.TLV_ID_LENGTH])[0]
            index += self.TLV_ID_LENGTH
            tlv_size = struct.unpack("!H", buff[index:index + self.TLV_SIZE_LENGTH])[0]
            index += self.TLV_SIZE_LENGTH
            tlv_name = WPSElements.get_element_key(tlv_id)
            tlv_data = buff[index:index + tlv_size]
            if tlv_name:
                if tlv_id == WPSElements.ID_CONFIG_METHODS and tlv_size == WPSElements.ID_CONFIG_METHODS_SIZE:
                    self.__elements__[tlv_name] = self.get_config_methods_string(tlv_data)
                elif tlv_id == WPSElements.ID_VERSION and tlv_size == WPSElements.ID_VERSION_SIZE:
                    self.__elements__[tlv_name] = self.get_version_string(tlv_data)
                elif tlv_id == WPSElements.ID_WIFI_PROTECTED_SETUP_STATE and \
                        tlv_size == WPSElements.ID_WIFI_PROTECTED_SETUP_STATE_SIZE:
                    self.__elements__[tlv_name] = self.get_setup_state_string(tlv_data)
                elif (tlv_id == WPSElements.ID_UUID_E or tlv_id == WPSElements.ID_UUID_R) and \
                        tlv_size == WPSElements.ID_UUID_SIZE:
                    self.__elements__[tlv_name] = self.get_uuid_string(tlv_data)
                elif tlv_id == WPSElements.ID_PRIMARY_DEVICE_TYPE and \
                        tlv_size == WPSElements.ID_PRIMARY_DEVICE_TYPE_SIZE:
                    self.__elements__[tlv_name] = self.get_primary_device_type_string(tlv_data)
                else:
                    self.__elements__[tlv_name] = tlv_data
            index += tlv_size
