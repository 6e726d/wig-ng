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
import datetime
import traceback

from Queue import Empty
from collections import OrderedDict
from multiprocessing import Event, Queue, Value, TimeoutError

from helpers import ieee80211
from helpers.output import writer
from helpers.Processes import WigProcess
from producers.base import FINITE_TYPE, INFINITE_TYPE

from wps import WiFiProtectedSetup
from uncommon import InformationElementsStats
from hp import HewlettPackardVendorSpecificTypeZero
from awdl import AppleWirelessDirectLink
from p2p import WiFiDirect


class Mediator(WigProcess):
    """
    The objective of the intermediary consumer class is to push specific
    type/subtype IEEE 802.11 frames to different frame processing classes.
    """

    def __init__(self, frames_queue, producer_type, passive=True):
        WigProcess.__init__(self)
        self.__queue__ = frames_queue
        self.__stop__ = Event()
        self.__producer_type__ = producer_type
        self.__passive__ = passive
        self.__timeout_event__ = Event()
        self.consumers_list = [FramesStats,
                              InformationElementsStats,
                              WiFiProtectedSetup,
                              WiFiDirect,
                              HewlettPackardVendorSpecificTypeZero,
                              AppleWirelessDirectLink]

    def run(self):
        """
        Process data from the frames queue and write them to specific queues.
        """
        self.set_process_title()

        # Initialize Output Manager
        self.__output_queue__ = Queue()
        self.__output_manager__ = OutputManager(self.__output_queue__)
        self.__output_manager__.start()

        if self.__producer_type__ == INFINITE_TYPE:
            self.run_from_infinite_producers()
        else:
            self.run_from_finite_producers()

        # Wait for Output Manager
        while True:
            if self.__output_manager__.is_alive() and self.__output_queue__.empty():
               self.__output_manager__.shutdown()
               self.__output_manager__.join()
               break
            time.sleep(1)

    def run_from_finite_producers(self):
        """
        This method handles the state when processing data from finite
        producers.
        """
        # Consumers initialization
        consumer_list = list()
        for consumer in self.consumers_list:
            consumer_queue = Queue()
            consumer_instance = consumer(consumer_queue, self.__output_queue__)
            consumer_instance.start()
            consumer_list.append((consumer_instance, consumer_queue))

        try:
            while not self.__stop__.is_set():
                try:
                    if self.__timeout_event__.is_set():
                        # We are working with a finite producer, such as pcap
                        # file, we wait for a couple of seconds if the queue is
                        # empty we assume producers have finish and we stop
                        # processing.
                        frame = self.__queue__.get(timeout=30)
                    else:
                        # The timeout_event is not set, we still have producers
                        # pending to start. We need to wait.
                        frame = self.__queue__.get(timeout=300)
                except Empty:
                    break
                for item in consumer_list:
                    consumer = item[0]
                    consumer_queue = item[1]
                    # Check consumer filters
                    frame_type = ieee80211.get_frame_type(frame)
                    if frame_type in consumer.get_frame_type_filter():
                        frame_subtype = ieee80211.get_frame_subtype(frame)
                        if frame_subtype in consumer.get_frame_subtype_filter():
                            consumer_queue.put(frame)
                    # If filters are empty we put the frame into the queue.
                    if not consumer.get_frame_type_filter() and \
                       not consumer.get_frame_subtype_filter():
                       consumer_queue.put(frame)
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass
        except Exception, e:
            self.__output_queue__.put({'Exception': str(e)})
        finally:
            # We need to wait for consumers to finish.
            self.__output_queue__.put({' ': 'Waiting for modules to finish. Please wait...'})
            while True:
                try:
                    if consumer_list:
                        for item in consumer_list:
                            consumer = item[0]
                            consumer_queue = item[1]
                            if consumer_queue.empty():
                                consumer.shutdown()
                                consumer_list.remove(item)
                    else:
                        break
                    # Wait between checks to avoid high cpu consumption.
                    time.sleep(5)
                # except KeyboardInterrupt:
                    # traceback.print_stack()
                except Exception, e:
                    self.__output_queue__.put({'Exception': str(e)})

    def run_from_infinite_producers(self):
        """
        This method handles the state when processing data from infinite
        producers.
        """
        # Consumers initialization
        consumer_list = list()
        for consumer in self.consumers_list:
            consumer_queue = Queue()
            consumer_instance = consumer(consumer_queue, self.__output_queue__)
            consumer_instance.start()
            consumer_list.append((consumer_instance, consumer_queue))

        try:
            while not self.__stop__.is_set():
                # We are working with a infinite producer, such as network
                # interface cards, we wait until a frame is put from the
                # producers.
                frame = self.__queue__.get()
                for item in consumer_list:
                    consumer = item[0]
                    consumer_queue = item[1]
                    # Check consumer filters
                    frame_type = ieee80211.get_frame_type(frame)
                    if frame_type in consumer.get_frame_type_filter():
                        frame_subtype = ieee80211.get_frame_subtype(frame)
                        if frame_subtype in consumer.get_frame_subtype_filter():
                            consumer_queue.put(frame)
                    # If filters are empty we put the frame into the queue.
                    if not consumer.get_frame_type_filter() and \
                       not consumer.get_frame_subtype_filter():
                       consumer_queue.put(frame)
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass
        except Exception, e:
            self.__output_queue__.put({'Exception': str(e)})
        finally:
            for item in consumer_list:
                consumer = item[0]
                if consumer.is_alive():
                    consumer.shutdown()
                    try:
                        # Wait for 30 seconds for consumer to shutdown and join.
                        consumer.join(30)
                    except TimeoutError:
                        # Force consumer to terminate.
                        self.__output_queue__.put({'Timeout Error':
                              'Forcing %s to terminate.' % consumer.__class__.__name__})
                        consumer.terminate()

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()

    def timeout_event(self):
        """
        This method sets the __timeout_event__ to change the queue timeout.
        This was added to fix the race condition that happends between a new
        producer starts and the queue timeout monitoring in the mediator.
        """
        self.__timeout_event__.set()


class OutputManager(WigProcess):
    """
    TODO: Documentation
    """

    def __init__(self, output_queue):
        WigProcess.__init__(self)
        self.__stop__ = Event()
        self.__queue__ = output_queue

    def run(self):
        """
        TODO: Documentation
        """
        self.set_process_title()

        try:
            while not self.__stop__.is_set():
                try:
                    output = self.__queue__.get(timeout=5)
                    self.print_item(output)
                except Empty:
                    pass
        # Ignore SIGINT signal, this is handled by parent.
        except KeyboardInterrupt:
            pass

    def print_item(self, output_items):
        """
        TODO: Documentation
        """
        print("")  # Add empty line on top of item output.
        for k, v in output_items.items():
            if len(k.strip()) == 0:
                print("%s" % v)
            else:
                print("%s: %s" % (k, v))

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()


class FramesStats(WigProcess):
    """
    TODO: Documentation
    """

    __module_name__ = "Frame Stats"

    def __init__(self, frames_queue, output_queue):
        WigProcess.__init__(self)
        self.__stop__ = Event()

        self.__queue__ = frames_queue
        self.__output__ = output_queue
        self.__total_frames_count__ = 0
        self.__type_management_count__ = 0
        self.__type_control_count__ = 0
        self.__type_data_count__ = 0
        self.__type_unknown_count__ = 0

    def run(self):
        """
        TODO: Documentation
        """
        self.set_process_title()

        try:
            while not self.__stop__.is_set():
                try:
                    frame = self.__queue__.get(timeout=5)
                    self.__total_frames_count__ += 1

                    frame_type = ieee80211.get_frame_type(frame)

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

        aux =  OrderedDict()
        aux['Module'] = self.__module_name__
        aux['Frames'] = self.__total_frames_count__
        aux['Management Frames'] = self.__type_management_count__
        aux['Control Frames'] = self.__type_control_count__
        aux['Data Frames'] = self.__type_data_count__
        aux['Unknown Frames'] = self.__type_unknown_count__
        self.__output__.put(aux)

    def get_frame_type_filter(self):
        """
        Returns a list of IEEE 802.11 frame types supported by the module.
        """
        # Empty filter means all frames
        return []

    def get_frame_subtype_filter(self):
        """
        Returns a list of IEEE 802.11 frame subtypes supported by the module.
        """
        # Empty filter means all frames
        return []

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        self.__stop__.set()
