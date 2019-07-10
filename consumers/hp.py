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

from Queue import Empty
from multiprocessing import Event

from helpers import ieee80211
from helpers.Processes import WigProcess

from impacket import ImpactDecoder
from impacket import dot11


class HewlettPackardVendorSpecificTypeZero(WigProcess):
    """
    TODO: Documentation
    """

    SUBTYPE_WHITELIST = [
        dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE,  # 00 - 05
        dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON,  # 00 - 08
    ]

    HDR_SIZE = {
        dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON: 12,
        dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE: 12,
    }

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

    def __init__(self, frames_queue):
        WigProcess.__init__(self)
        self.__stop__ = Event()

        self.__queue__ = frames_queue

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
                except Exception, e:
                    print(str(e))
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

        # for tag_id, count in self.__tag_stats__.items():
            # if tag_id in ieee80211.tag_strings.keys():
                # print("TAG: %02X [%s] - %d" % (tag_id,
                                               # ieee80211.tag_strings[tag_id],
                                               # count))
            # else:
                # print("TAG: %02X - %d" % (tag_id, count))
        # print("Malformed frames: %d" % self.malformed)

    def process_hp_ie(self, data, debug=False):
        """Process HP wireless printers information element."""
        index = 0
        while index < len(data):
            tag_id = struct.unpack("B", data[index])[0]
            tag_length = struct.unpack("B", data[index + 1])[0]
            index += 2

            if tag_length > len(data) - index:
                if debug:
                    print("Invalid Tag.")
                continue

            if tag_id == self.HP_TLV_TYPES['Status BitField']:
                if tag_length != 4:
                    if debug:
                        print("Invalid Status BitField.")
                    continue
                aux = data[index:index + 4]
                bitfield = struct.unpack(">I", aux)[0]
                print("Status Bitfield: %r - %d" % (aux, bitfield))
                if (bitfield & self.STATUS_BITFIELD['Station is on']) != 0:
                    print(" - Station is on.")
                else:
                    print(" - Station is off.")
                if (bitfield & self.STATUS_BITFIELD['Station is configured']) != 0:
                    print(" - Station is configured.")
                else:
                    print(" - Station is not configured.")
                if (bitfield & self.STATUS_BITFIELD['Station is connected']) != 0:
                    print(" - Station is connected.")
                else:
                    print(" - Station is not connected.")
                if (bitfield & self.STATUS_BITFIELD['Station supports 5GHz']) != 0:
                    print(" - Station supports 5GHz.")
                else:
                    print(" - Station doesn't support 5GHz.")
                if (bitfield & self.STATUS_BITFIELD['USB connected to host']) != 0:
                    print(" - USB connected to host.")
                else:
                    print(" - USB is not connected to host.")
                index += 4
            elif tag_id == self.HP_TLV_TYPES['AWC Version']:
                if tag_length != 2:
                    if debug:
                        print("Invalid AWC Version.")
                    continue
                awc_major = struct.unpack("B", data[index])[0]
                awc_minor = struct.unpack("B", data[index + 1])[0]
                print("AWC version: %d.%d" % (awc_major, awc_minor))
                index += 2
            elif tag_id == self.HP_TLV_TYPES['Model Name String']:
                model_name = str(data[index:index+tag_length])
                index += tag_length
                print("Model Name: %s" % model_name.replace("\x00", ""))
            elif tag_id == self.HP_TLV_TYPES['Product SKU']:
                product_sku = str(data[index:index + tag_length])
                index += tag_length
                print("Product SKU: %s" % product_sku.replace("\x00", ""))
            elif tag_id == self.HP_TLV_TYPES['Device Serial Number']:
                serial_number = str(data[index:index + tag_length])
                index += tag_length
                print("Serial Number: %s" % serial_number.replace("\x00", ""))
            elif tag_id == self.HP_TLV_TYPES['Device UUID']:
                if tag_length != 16:
                    if debug:
                        print("Invalid Device UUID.")
                    continue
                uuid = list()
                for byte in data[index:index + tag_length]:
                    uuid.append("%02X" % ord(byte))
                print("UUID: %s" % "".join(uuid))
                index += tag_length
            elif tag_id == self.HP_TLV_TYPES['Device Station IPv4 Address']:
                if tag_length != 4:
                    if debug:
                        print("Print Invalid Device Station IPv4 Address")
                    continue
                octets = list()
                for byte in data[index:index + tag_length]:
                    octets.append("%d" % ord(byte))
                print("IPv4 Address: %s" % ".".join(octets))
                index += tag_length
            else:
                if debug:
                    print("Tag ID: %02X" % tag_id)
                    print("Tag Length: %d" % tag_length)
                    print("Tag Value: %s" % repr(data[index:index + tag_length]))
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
                        print "BSSID: %s" % device_mac
                        print "SSID: %s" % ssid
                        print "Channel: %d" % channel
                        print "Security: %s" % security
                        print "-" * 20
                        self.process_hp_ie(ie_data)
                        print "-" * 70

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
