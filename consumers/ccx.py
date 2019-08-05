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

import time
import struct
import string
import random

from Queue import Empty
from collections import OrderedDict
from multiprocessing import Event

from helpers import ieee80211
from helpers import ccx
from helpers.output import writer
from helpers.Processes import WigProcess

from impacket import ImpactDecoder
from impacket import dot11


class CiscoClientExtensions(WigProcess):
    """
    TODO: Documentation
    """

    __module_name__ = "CCX (Cisco Client Extensions)"

    BSSID_KEY = "BSSID"
    SSID_KEY = "SSID"
    CTRL_IP_ADDR_KEY = "Controller IP Address"
    AP_NAME_KEY = "Access Point Name"
    ASSOCIATED_CLIENTS_KEY = "Associated Clients"
    CHANNEL_KEY = "Channel"
    SECURITY_KEY = "Security"
    TIMESTAMP_KEY = "Timestamp"

    def __init__(self, frames_queue, output_queue, injection_queue=None):
        WigProcess.__init__(self)
        self.__stop__ = Event()

        self.__queue__ = frames_queue
        self.__output__ = output_queue

        self.decoder = ImpactDecoder.Dot11Decoder()
        self.decoder.FCS_at_end(False)

        self.__injection_queue__ = injection_queue
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
        return [ieee80211.TYPE_MGMT_SUBTYPE_PROBE_RESPONSE,
                ieee80211.TYPE_MGMT_SUBTYPE_REASSOCIATION_RESPONSE]

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
                    except Exception:
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
                            self.process_body(frame_control, mgt_frame, data)
                except Empty:
                    pass
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

    def process_body(self, frame_ctrl, mgt_frame, data):
        """
        Process Probe Response and Reassociation Response frames searching for
        CCX IEs.
        """
        bssid = ieee80211.get_string_mac_address_from_array(mgt_frame.get_bssid())

        if frame_ctrl.get_subtype() == ieee80211.TYPE_MGMT_SUBTYPE_REASSOCIATION_RESPONSE:
            reassociation_response = self.decoder.get_protocol(dot11.Dot11ManagementReassociationResponse)
            data = reassociation_response._get_element(ccx.CISCO_CCX_IE_IP_ADDRESS_ID)
            if data:
                if bssid not in self.__devices__:
                    self.__devices__[bssid] = OrderedDict()
                ssid = reassociation_response._get_element(dot11.DOT11_MANAGEMENT_ELEMENTS.SSID)
                if ssid and self.SSID_KEY not in self.__devices__[bssid]:
                    self.__devices__[bssid][self.SSID_KEY] = ssid
                    aux = writer.get_device_information_dict(bssid.upper(), self.__module_name__, self.__devices__[bssid])
                    self.__output__.put(aux)
                if self.CTRL_IP_ADDR_KEY not in self.__devices__[bssid]:
                    ccx95 = chr(ccx.CISCO_CCX_IE_IP_ADDRESS_ID) + chr(len(data)) + data
                    self.__devices__[bssid][self.CTRL_IP_ADDR_KEY] = ccx.CiscoCCX95InformationElement(ccx95).get_ip_address()
                    aux = writer.get_device_information_dict(bssid.upper(), self.__module_name__, self.__devices__[bssid])
                    self.__output__.put(aux)
        else:
            if frame_ctrl.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_BEACON:
                frame = self.decoder.get_protocol(dot11.Dot11ManagementBeacon)
            elif frame_ctrl.get_subtype() == dot11.Dot11Types.DOT11_SUBTYPE_MANAGEMENT_PROBE_RESPONSE:
                frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)
            else:
                return

            security = ieee80211.get_security(frame)

            data = frame._get_element(ccx.CISCO_CCX_IE_DEVICE_NAME_ID)
            if bssid not in self.__devices__ and data:
                self.__devices__[bssid] = OrderedDict()
                ssid = frame.get_ssid().replace("\x00", "")
                self.__devices__[bssid][self.SSID_KEY] = ssid
                channel = frame.get_ds_parameter_set()
                if channel:
                    self.__devices__[bssid][self.CHANNEL_KEY] = channel
                ccx85 = chr(ccx.CISCO_CCX_IE_DEVICE_NAME_ID) + chr(len(data)) + data
                device_name = ccx.CiscoCCX85InformationElement(ccx85).get_device_name()
                associated_clients = ccx.CiscoCCX85InformationElement(ccx85).get_associated_clients()
                self.__devices__[bssid][self.AP_NAME_KEY] = device_name
                self.__devices__[bssid][self.ASSOCIATED_CLIENTS_KEY] = associated_clients
                self.__devices__[bssid][self.SECURITY_KEY] = security
                aux = writer.get_device_information_dict(bssid.upper(), self.__module_name__, self.__devices__[bssid])
                self.__output__.put(aux)
                if self.CTRL_IP_ADDR_KEY not in self.__devices__[bssid]:
                    data = str()
                    data += struct.pack("H", frame.get_capabilities())  # capabilities
                    data += "\x5a\x00"  # listen intervals
                    data += ieee80211.get_buffer_from_string_mac_address(bssid)
                    data += frame.get_header_as_string()[12:]
                    self.transmit_reassociation_request(ieee80211.get_buffer_from_string_mac_address(bssid), data)
            elif bssid in self.__devices__ and data:
                if self.CTRL_IP_ADDR_KEY not in self.__devices__[bssid]:
                    data = str()
                    data += struct.pack("H", frame.get_capabilities())  # capabilities
                    data += "\x5a\x00"  # listen intervals
                    data += ieee80211.get_buffer_from_string_mac_address(bssid)
                    data += frame.get_header_as_string()[12:]
                    self.transmit_reassociation_request(ieee80211.get_buffer_from_string_mac_address(bssid), data)

    def get_radiotap_header(self):
        """Returns a radiotap header buffer for frame injection."""
        buff = str()
        buff += "\x00\x00"  # Version
        buff += "\x0b\x00"  # Header length
        buff += "\x04\x0c\x00\x00"  # Bitmap
        buff += "\x6c"  # Rate
        buff += "\x0c"  # TX Power
        buff += "\x01"  # Antenna
        return buff

    def get_reassociation_request_frame(self, destination, seq, data):
        """Returns management reassociation request frame header."""
        buff = str()
        buff += self.get_radiotap_header()
        buff += "\x20\x00"  # Frame Control - Management - Reassociation Request
        buff += "\x28\x00"  # Duration
        buff += destination  # Destination Address- Broadcast
        buff += '\x00\x00\xde\xad\xbe\xef'  # Source Address
        buff += destination  # BSSID Address - Broadcast
        buff += "\x00" + struct.pack("B", seq)[0]  # Sequence Control
        # Capabilities
        buff += data
        return buff

    def transmit_reassociation_request(self, bssid, data):
        """Transmit reassociation request frame."""
        if self.__injection_queue__:
            seq = random.randint(1, 254)  # TODO: Fix how we are handling sequence numbers
            frame = self.get_reassociation_request_frame(bssid, seq, data)
            self.__injection_queue__.put(frame)

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
