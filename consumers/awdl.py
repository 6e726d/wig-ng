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

import struct
import traceback

from queue import Empty
from multiprocessing import Event

from helpers import ieee80211
from helpers.output import writer
from helpers.Processes import WigProcess

from impacket import ImpactDecoder
from impacket import dot11


class AppleWirelessDirectLink(WigProcess):
    """
    TODO: Documentation
    """

    __module_name__ = "Apple Wireless Direct Link"

    VENDOR_SPECIFIC = 0x7f
    APPLE_OUI = b"\x00\x17\xf2"

    SUBTYPE_MASTER_INDICATION_FRAME = 0x03

    TLV_SERVICE_REQUEST = 0x01
    TLV_SERVICE_RESPONSE = 0x02
    TLV_DATA_PATH_STATE = 0x0c
    TLV_ARPA = 0x10
    TLV_VERSION = 0x15

    TLV_TYPES = {
        0x00: "SSTH Request",
        TLV_SERVICE_REQUEST: "Service Request",
        TLV_SERVICE_RESPONSE: "Service Response",
        0x03: "Unknown",
        0x04: "Synchronization Parameters",
        0x05: "Election Parameters",
        0x06: "Service Parameters",
        0x07: "HT Capabilities (IEEE 802.11 subset)",
        0x08: "Enhanced Data Rate Operation",
        0x09: "Infra",
        0x0a: "Invite",
        0x0b: "Debug String",
        TLV_DATA_PATH_STATE: "Data Path State",
        0x0d: "Encapsulated IP",
        0x0e: "Datapath Debug Packet Live",
        0x0f: "Datapath Debug AF Live",
        TLV_ARPA: "Arpa",
        0x11: "IEEE 802.11 Container",
        0x12: "Channel Sequence",
        0x13: "Unknown",
        0x14: "Synchronization Tree",
        TLV_VERSION: "Version",
        0x15: "Bloom Filter",
        0x16: "NAN Sync",
        0x17: "Election Parameters v2",
    }

    DEVICE_CLASS = {
        0x01: "macOS",
        0x02: "iOS",
        0x08: "tvOS",
    }

    country_label = 'country'
    name_label = 'name'
    class_label = 'class'
    service_request_label = 'service request'
    service_response_label = 'service response'

    def __init__(self, frames_queue, output_queue, injection_queue=None):
        WigProcess.__init__(self)
        self.__stop__ = Event()

        self.__queue__ = frames_queue
        self.__output__ = output_queue

        self.decoder = ImpactDecoder.Dot11Decoder()
        self.decoder.FCS_at_end(False)

        self.__devices__ = dict()

    def get_frame_type_filter(self):
        """
        Returns a list of IEEE 802.11 frame types supported by the module.
        """
        return [ieee80211.TYPE_MGMT]

    def get_frame_subtype_filter(self):
        """
        Returns a list of IEEE 802.11 frame subtypes supported by the module.
        """
        return [ieee80211.TYPE_MGMT_SUBTYPE_ACTION]

    def run(self):
        """
        TODO: Documentation
        """
        self.set_process_title()

        try:
            self.malformed = 0
            while not self.__stop__.is_set():
                try:
                    frame = self.__queue__.get(timeout=5)
                    try:
                        self.decoder.decode(frame)
                    except Exception as e:
                        self.__output__.put({'Exception': traceback.format_exc()})
                        self.malformed +=1
                        continue
                    frame_control = self.decoder.get_protocol(dot11.Dot11)
                    if frame_control.get_subtype() in self.get_frame_subtype_filter():
                        mgt_frame = self.decoder.get_protocol(dot11.Dot11ManagementFrame)
                        # Management frames shouldn't be fragmented.
                        # At least the ones we are processing.
                        seq_ctl = mgt_frame.get_sequence_control()
                        fragment_number = seq_ctl & 0x000F
                        if fragment_number == 0:
                            data = mgt_frame.get_body_as_string()
                            self.process_body(mgt_frame, data)
                except Empty:
                    pass
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

    def process_body(self, mgt_frame, data):
        """
        TODO: Documentation
        """
        device_mac = ieee80211.get_string_mac_address_from_array(mgt_frame.get_source_address())
        __data = self.process_airplay_data(data)
        if __data:
            if device_mac not in self.__devices__.keys():
                if self.name_label in __data:
                    info_items = dict()
                    info_items['Name'] = __data[self.name_label]
                    if self.class_label in __data:
                        info_items['Class'] = __data[self.class_label]
                    if self.country_label in __data:
                        info_items['Country'] = __data[self.country_label]
                    if self.service_request_label in __data:
                        idx = 0
                        for item in __data[self.service_request_label]:
                            info_items['Service Request %d' % idx] = repr(item)
                            idx += 1
                    if self.service_response_label in __data:
                        idx = 0
                        for item in __data[self.service_response_label]:
                            info_items['Service Response %d' % idx] = repr(item)
                            idx += 1
                    aux = writer.get_device_information_dict(device_mac.upper(), self.__module_name__, info_items)
                    self.__output__.put(aux)

                    # Apple Devices has MAC randomization, so we should use the device name to identify them.
                    self.__devices__[device_mac] = __data[self.name_label]

    def process_airplay_data(self, data):
        """Process AirPlay Data."""
        idx = 0

        try:
            # Verify Vendor Specific
            if data[0] != self.VENDOR_SPECIFIC:
                return 0
            idx += 1

            # Verify Apple OUI
            if data[idx:idx+len(self.APPLE_OUI)] != self.APPLE_OUI:
                return None
            idx += len(self.APPLE_OUI)

            # AWDL Fixed Parameters
            # awdl_type = struct.unpack("B", data[idx])[0]
            idx += 1

            awdl_version = data[idx]
            idx += 1
            # Verify AWDL Version
            if awdl_version != 0x10:
                return

            awdl_subtype = data[idx]
            # Verify AWDL Subtype
            if awdl_subtype != self.SUBTYPE_MASTER_INDICATION_FRAME:
                return
            idx += 10

            result = {}
            raw_data = data[idx:]
            remaining_data = raw_data
            while len(remaining_data) > 4:
                tlv_type = remaining_data[0]
                tlv_length = struct.unpack("H", remaining_data[1:3])[0]
                tlv_data = remaining_data[3:tlv_length+3]

                if tlv_type == self.TLV_DATA_PATH_STATE:
                    if tlv_length > 5:
                        country_code = tlv_data[2:4]
                        result[self.country_label] = country_code
                elif tlv_type == self.TLV_ARPA:
                    str_length = tlv_data[1]
                    result[self.name_label] = tlv_data[2:2+str_length]
                elif tlv_type == self.TLV_VERSION:
                    device_class = tlv_data[1]
                    if device_class in self.DEVICE_CLASS:
                        result[self.class_label] = self.DEVICE_CLASS[device_class]
                elif tlv_type == self.TLV_SERVICE_REQUEST:
                    if not self.service_request_label in result:
                        result[self.service_request_label] = []
                    result[self.service_request_label].append(tlv_data)
                elif tlv_type == self.TLV_SERVICE_RESPONSE:
                    if not self.service_response_label in result:
                        result[self.service_response_label] = []
                    result[self.service_response_label].append(tlv_data)

                remaining_data = remaining_data[tlv_length+3:]
            return result
        except Exception as e:
            self.__output__.put({'Exception': traceback.format_exc()})

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
