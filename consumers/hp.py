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

from queue import Empty
from multiprocessing import Event
from collections import OrderedDict

from helpers import ieee80211
from helpers.output import writer
from helpers.Processes import WigProcess

from impacket import ImpactDecoder
from impacket import dot11


class HewlettPackardVendorSpecificTypeZero(WigProcess):
    """
    TODO: Documentation
    """

    __module_name__ = "HP Printer Vendor Specific"

    hp_ie_oui = "\x08\x00\x09"

    regex_list = ["^HP-Print-[0-9A-Fa-f][0-9A-Fa-f]-(.*)$",
                  "^DIRECT-[0-9A-Fa-f][0-9A-Fa-f]-HP (.*)$"]

    HP_TLV_TYPES = {
        'Status BitField': 0,
        'AWC Version': 1,
        'AWC Minutes Remaining': 2,
        'Model Name String': 3,
        'Product SKU': 4,
        'Device Serial Number': 5,
        'Device UUID': 6,
        'Device Station IPv4 Address': 7,
        'IPP Capabilities': 8,
        'IPP PDLS': 9,
        'IPP Change ID': 10,
        '5GHz Channels': 11,
    }

    STATUS_BITFIELD = {
        'Station is on':         0b00000000000000000000000000000001,
        'Station is configured': 0b00000000000000000000000000000010,
        'Station is connected':  0b00000000000000000000000000000100,
        'Station supports 5GHz': 0b00000000000000000000000000001000,
        'USB connected to host': 0b00000000000000000000000000010000,
    }

    def __init__(self, frames_queue, output_queue, injection_queue=None):
        WigProcess.__init__(self)
        self.__stop__ = Event()

        self.__queue__ = frames_queue
        self.__output__ = output_queue

        self.decoder = ImpactDecoder.Dot11Decoder()
        self.decoder.FCS_at_end(False)

        self.__tag_stats__ = dict()

    def get_frame_type_filter(self):
        """
        Returns a list of IEEE 802.11 frame types supported by the module.
        """
        return [ieee80211.TYPE_MGMT]

    def get_frame_subtype_filter(self):
        """
        Returns a list of IEEE 802.11 frame subtypes supported by the module.
        """
        return [ieee80211.TYPE_MGMT_SUBTYPE_BEACON,
                ieee80211.TYPE_MGMT_SUBTYPE_PROBE_RESPONSE]

    def run(self):
        """
        TODO: Documentation
        """

        self.set_process_title()

        try:
            self.devices = dict()
            self.malformed = 0
            while not self.__stop__.is_set():
                try:
                    frame = self.__queue__.get(timeout=5)
                    try:
                        self.decoder.decode(frame)
                    except Exception:
                        self.malformed +=1
                        continue
                    frame_control = self.decoder.get_protocol(dot11.Dot11)
                    if frame_control.get_type() in self.get_frame_type_filter():
                        if frame_control.get_subtype() in self.get_frame_subtype_filter():
                            mgt_frame = self.decoder.get_protocol(dot11.Dot11ManagementFrame)
                            # Management frames shouldn't be fragmented.
                            # At least the ones we are processing.
                            seq_ctl = mgt_frame.get_sequence_control()
                            fragment_number = seq_ctl & 0x000F
                            if fragment_number == 0:
                                self.process_frame(frame_control, mgt_frame)
                except Empty:
                    pass
                except Exception as e:
                    self.__output__.put({"Exception": str(e)})
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

    def process_hp_ie(self, data, info_dict):
        """Process HP wireless printers information element."""
        index = 0
        while index < len(data):
            tag_id = struct.unpack("B", data[index])[0]
            tag_length = struct.unpack("B", data[index + 1])[0]
            index += 2

            if tag_length > len(data) - index:
                continue

            if tag_id == self.HP_TLV_TYPES['Status BitField']:
                if tag_length != 4:
                    continue
                aux = data[index:index + 4]
                bitfield = struct.unpack(">I", aux)[0]
                if (bitfield & self.STATUS_BITFIELD['Station is on']) != 0:
                    info_dict['Station State'] = "On"
                else:
                    info_dict['Station State'] = "Off"
                if (bitfield & self.STATUS_BITFIELD['Station is configured']) != 0:
                    info_dict['Station Configured'] = "True"
                else:
                    info_dict['Station Configured'] = "False"
                if (bitfield & self.STATUS_BITFIELD['Station is connected']) != 0:
                    info_dict['Station is Connected'] = "True"
                else:
                    info_dict['Station is Connected'] = "False"
                if (bitfield & self.STATUS_BITFIELD['Station supports 5GHz']) != 0:
                    info_dict['Station Supports 5GHz'] = "True"
                else:
                    info_dict['Station Supports 5GHz'] = "False"
                if (bitfield & self.STATUS_BITFIELD['USB connected to host']) != 0:
                    info_dict['USB Connected'] = "True"
                else:
                    info_dict['USB Connected'] = "False"
                index += 4
            elif tag_id == self.HP_TLV_TYPES['AWC Version']:
                if tag_length != 2:
                    continue
                awc_major = struct.unpack("B", data[index])[0]
                awc_minor = struct.unpack("B", data[index + 1])[0]
                info_dict['AWC version'] = "%d.%d" % (awc_major, awc_minor)
                index += 2
            elif tag_id == self.HP_TLV_TYPES['Model Name String']:
                model_name = str(data[index:index+tag_length])
                index += tag_length
                info_dict['Model Name'] = model_name.replace("\x00", "")
            elif tag_id == self.HP_TLV_TYPES['Product SKU']:
                product_sku = str(data[index:index + tag_length])
                index += tag_length
                info_dict['Product SKU'] = product_sku.replace("\x00", "")
            elif tag_id == self.HP_TLV_TYPES['Device Serial Number']:
                serial_number = str(data[index:index + tag_length])
                index += tag_length
                info_dict['Serial Number'] = serial_number.replace("\x00", "")
            elif tag_id == self.HP_TLV_TYPES['Device UUID']:
                if tag_length != 16:
                    continue
                uuid = list()
                for byte in data[index:index + tag_length]:
                    uuid.append("%02X" % ord(byte))
                info_dict['UUID'] = "".join(uuid)
                index += tag_length
            elif tag_id == self.HP_TLV_TYPES['Device Station IPv4 Address']:
                if tag_length != 4:
                    continue
                octets = list()
                for byte in data[index:index + tag_length]:
                    octets.append("%d" % ord(byte))
                info_dict['IPv4 Address'] = ".".join(octets)
                index += tag_length
            else:
                index += tag_length

    def process_frame(self, frame_ctl, mgt_frame):
        """
        Process Beacon and Probe Response frames searching for HP IE and storing
        information.
        """

        device_mac = ieee80211.get_string_mac_address_from_array(
                                                 mgt_frame.get_source_address())
        if device_mac not in self.devices.keys():
            self.devices[device_mac] = list()
            if frame_ctl.get_subtype() == ieee80211.TYPE_MGMT_SUBTYPE_PROBE_RESPONSE:
                _frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)
            elif frame_ctl.get_subtype() == ieee80211.TYPE_MGMT_SUBTYPE_BEACON:
                _frame = self.decoder.get_protocol(dot11.Dot11ManagementBeacon)

            if _frame:
                ssid = _frame.get_ssid()
                channel = _frame.get_ds_parameter_set()
                security = ieee80211.get_security(_frame)

                for item in _frame.get_vendor_specific():
                    oui = item[0]
                    if oui == self.hp_ie_oui:
                        ie_data = item[1]
                        info_items = OrderedDict()
                        info_items['SSID'] = ssid
                        info_items['Channel'] = channel
                        info_items['Security'] = security
                        self.process_hp_ie(ie_data, info_items)
                        aux = writer.get_device_information_dict(device_mac.upper(), self.__module_name__, info_items)
                        self.__output__.put(aux)

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
