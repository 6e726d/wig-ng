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

import string
import struct

from queue import Empty
from multiprocessing import Event

from helpers import wps
from helpers import ieee80211
from helpers.output import writer
from helpers.Processes import WigProcess

from impacket import ImpactDecoder
from impacket import dot11


class WiFiProtectedSetup(WigProcess):
    """
    TODO: Documentation
    """

    __module_name__ = "WPS (WiFi Protected Setup)"

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
        return [ieee80211.TYPE_MGMT_SUBTYPE_PROBE_RESPONSE]

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
                    self.__output__.put({'Exception': str(e)})
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

    def process_frame(self, frame_ctl, mgt_frame):
        """
        Process Probe Response frame searching for WPS IEs and printing the
        information.
        """
        device_mac = ieee80211.get_string_mac_address_from_array(
                                                 mgt_frame.get_source_address())

        if device_mac not in self.devices.keys():
            self.devices[device_mac] = list()
            if frame_ctl.get_subtype() == ieee80211.TYPE_MGMT_SUBTYPE_PROBE_RESPONSE:
                _frame = self.decoder.get_protocol(dot11.Dot11ManagementProbeResponse)

            if _frame:
                ssid = _frame.get_ssid()
                channel = _frame.get_ds_parameter_set()
                security = ieee80211.get_security(_frame)

                vs_list = _frame.get_vendor_specific()
                for item in vs_list:
                    oui, data = item
                    vs_type = data[0]
                    length = struct.pack("B", len(oui + data))
                    raw_data = wps.WPSInformationElement.VENDOR_SPECIFIC_IE_ID + length + oui + data
                    if oui == wps.WPSInformationElement.WPS_OUI and vs_type == wps.WPSInformationElement.WPS_OUI_TYPE:
                        info_items = dict()
                        if ssid:
                            info_items['SSID'] = ssid
                        if channel:
                            info_items['Channel'] = channel
                        info_items['Security'] = security
                        ie = wps.WPSInformationElement(raw_data)
                        for element in ie.get_elements():
                            k, v = element
                            if all(c in string.printable for c in v):
                                info_items[string.capwords(k)] = v
                            else:
                                info_items[string.capwords(k)] = repr(v)
                        aux = writer.get_device_information_dict(device_mac.upper(), self.__module_name__, info_items)
                        self.__output__.put(aux)

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
