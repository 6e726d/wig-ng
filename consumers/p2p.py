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
import string

from Queue import Empty
from collections import OrderedDict
from multiprocessing import Event

from helpers import ieee80211
from helpers import p2p
from helpers import wps
from helpers.output import writer
from helpers.Processes import WigProcess

from impacket import ImpactDecoder
from impacket import dot11


class WiFiDirect(WigProcess):
    """
    TODO: Documentation
    """

    __module_name__ = "P2P (Wi-Fi Direct)"

    WIFI_DIRECT_SSID = "DIRECT-"

    def __init__(self, frames_queue, output_queue):
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
        return [ieee80211.TYPE_MGMT_SUBTYPE_PROBE_RESPONSE]

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
                            self.process_body(mgt_frame, data)
                except Empty:
                    pass
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

    def process_body(self, mgt_frame, data):
        """
        Process Probe Response frame searching for WPS and P2P IEs and storing information.
        """
        device_mac = ieee80211.get_string_mac_address_from_array(mgt_frame.get_source_address())

        probe_response_frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)
        ssid = probe_response_frame.get_ssid()

        if not ssid:
            return

        if not ssid.startswith(self.WIFI_DIRECT_SSID):
            return

        if device_mac not in self.__devices__.keys():
            self.__devices__[device_mac] = list()
            vs_list = probe_response_frame.get_vendor_specific()
            wps_ie_info = dict()
            p2p_ie_info = dict()
            channel = probe_response_frame.get_ds_parameter_set()
            for vs_element in vs_list:
                oui, data = vs_element
                vs_type = data[0]
                length = struct.pack("B", len(oui + data))
                raw_data = wps.WPSInformationElement.VENDOR_SPECIFIC_IE_ID + length + oui + data
                if oui == wps.WPSInformationElement.WPS_OUI and vs_type == wps.WPSInformationElement.WPS_OUI_TYPE:
                    ie = wps.WPSInformationElement(raw_data)
                    for wps_element in ie.get_elements():
                        k, v = wps_element
                        if all(c in string.printable for c in v):
                            wps_ie_info[string.capwords(k)] = v
                        else:
                            wps_ie_info[string.capwords(k)] = repr(v)
                elif oui == p2p.P2PInformationElement.P2P_OUI and vs_type == p2p.P2PInformationElement.P2P_OUI_TYPE:
                    ie = p2p.P2PInformationElement(raw_data)
                    for p2p_element in ie.get_elements():
                        k, v = p2p_element
                        if all(c in string.printable for c in v):
                            p2p_ie_info[k] = v
                        else:
                            p2p_ie_info[k] = repr(v)

            if not p2p_ie_info:
                return

            info_items = OrderedDict()
            info_items['SSID'] = ssid
            if channel:
                info_items['Channel'] = channel
            for key, value in p2p_ie_info.items():
                info_items['%s' % key] = value
            for key, value in wps_ie_info.items():
                info_items['WPS %s' % key] = value

            aux = writer.get_device_information_dict(device_mac.upper(), self.__module_name__, info_items)
            self.__output__.put(aux)

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
