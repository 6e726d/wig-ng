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
from multiprocessing import Process, Event, Queue

from helpers import ieee80211


class Mediator(Process):
    """
    The objective of the intermediary consumer class is to push specific
    type/subtype IEEE 802.11 frames to different frame processing classes.
    """

    def __init__(self, frames_queue):
        Process.__init__(self)
        self.__queue__ = frames_queue
        self.__stop__ = Event()

        # self.__frames_stats_queue__ = Queue()
        # self.__frames_stats__ = FramesStats(self.__frames_stats_queue__)
        # self.__frames_stats__.start()

    def run(self):
        """
        Process data from the frames queue and write them to specific queues.
        """

        self.__frames_stats_queue__ = Queue()
        self.__frames_stats__ = FramesStats(self.__frames_stats_queue__)
        self.__frames_stats__.start()

        try:
            while not self.__stop__.is_set():
                try:
                    frame = self.__queue__.get(timeout=5)
                    self.__frames_stats_queue__.put(frame)
                except Empty:
                    pass
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

        self.__frames_stats__.shutdown()
        self.__frames_stats__.join()

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()


class FramesStats(Process):
    """
    TODO: Documentation
    """

    def __init__(self, frames_queue):
        Process.__init__(self)
        self.__stop__ = Event()

        self.__queue__ = frames_queue

        self.__total_frames_count__ = 0
        self.__type_management_count__ = 0
        self.__type_control_count__ = 0
        self.__type_data_count__ = 0
        self.__type_unknown_count__ = 0

    def run(self):
        """
        TODO: Documentation
        """
        try:
            while not self.__stop__.is_set():
                try:
                    frame = self.__queue__.get(timeout=5)
                    self.__total_frames_count__ += 1

                    frame_type = ieee80211.get_frame_type(frame)
                    # frame_subtype = ieee80211.get_frame_subtype(frame)

                    if frame_type == 0:
                        self.__type_management_count__ += 1
                    elif frame_type == 1:
                        self.__type_control_count__ += 1
                    elif frame_type == 2:
                        self.__type_data_count__ += 1
                    else:
                        self.__type_unknown_count__ += 1
                except Empty:
                    pass
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass
        
        print("Frames: %d" % self.__total_frames_count__)
        print("Management Frames: %d" % self.__type_management_count__)
        print("Control Frames: %d" % self.__type_control_count__)
        print("Data Frames: %d" % self.__type_data_count__)
        print("Unknown Frames: %d" % self.__type_unknown_count__)

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
