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

from Queue import Empty
from multiprocessing import Process, Event

from helpers import ieee80211


class ConsumerProofOfConcept(Process):
    """
    None
    """

    def __init__(self, frames_queue):
        Process.__init__(self)
        self.__management_count__ = 0
        self.__control_count__ = 0
        self.__data_count__ = 0
        self.__wtf_count__ = 0
        self.__stop__ = Event()
        self.__queue__ = frames_queue

    def run(self):
        """
        This method reads frames from the pcap file descriptor and put them
        into the frame queue.
        """
        fd = open("wtf.txt", "wb")
        while not self.__stop__.is_set():
            try:
                frame = self.__queue__.get(timeout=5)
            except Empty:
                break
            frame_type = ieee80211.get_frame_type(frame)
            if frame_type == 0:
                self.__management_count__ += 1
            elif frame_type == 1:
                self.__control_count__ += 1
            elif frame_type == 2:
                self.__data_count__ += 1
            else:
                self.__wtf_count__ += 1
                fd.write("%r" % frame)
                fd.write("\n------------------------------\n")

        print("Management Frames: %d" % self.__management_count__)
        print("Control Frames: %d" % self.__control_count__)
        print("Data Frames: %d" % self.__data_count__)
        print("WTF: %d" % self.__wtf_count__)

        fd.close()

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
