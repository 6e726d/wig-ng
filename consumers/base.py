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
from multiprocessing import Event, Queue, TimeoutError

from helpers import ieee80211
from helpers.Processes import WigProcess
from producers.base import FINITE_TYPE, INFINITE_TYPE

from uncommon import InformationElementsStats
from hp import HewlettPackardVendorSpecificTypeZero


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

    def run(self):
        """
        Process data from the frames queue and write them to specific queues.
        """
        self.set_process_title()

        if self.__producer_type__ == INFINITE_TYPE:
            self.run_from_infinite_producers()
        else:
            self.run_from_finite_producers()

    def run_from_finite_producers(self):
        """
        This method handles the state when processing data from finite
        producers.
        """
        # Consumers initialization
        consumer_list = list()
        for consumer in [FramesStats,
                         InformationElementsStats,
                         HewlettPackardVendorSpecificTypeZero]:
            consumer_queue = Queue()
            consumer_instance = consumer(consumer_queue)
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
                    print("Empty Queue.")
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
            print(str(e))
        finally:
            # We need to wait for consumers to finish.
            print("Mediator Finally")
            print("Consumer List: %r" % consumer_list)
            while True:
                try:
                    if consumer_list:
                        print("%r" % consumer_list)
                        for item in consumer_list:
                            consumer = item[0]
                            consumer_queue = item[1]
                            print(consumer.__class__.__name__)
                            print(consumer_queue.qsize())
                            if consumer_queue.empty():
                                consumer.shutdown()
                                consumer_list.remove(item)
                    else:
                        print("break")
                        print(datetime.datetime.now())
                        break
                    # for item in consumer_list:
                        # print("Item: %r" % item)
                        # consumer = item[0]
                        # consumer_queue = item[1]
                        # If consumer queue is empty we assume the consumer has
                        # finished. This could be false in some cases. This needs
                        # a fix.
                        # if consumer_queue.empty():
                            # consumer.shutdown()
                        # if not consumer.is_alive():
                            # print("Consumer %s ended." %
                                # consumer.__class__.__name__),
                            # print(datetime.datetime.now())
                            # consumer_list.remove(item)
                    # Wait one second between checks to avoid high cpu consumption.
                    time.sleep(5)
                # except KeyboardInterrupt:
                    # traceback.print_stack()
                except Exception, e:
                    print("%s" % str(e))

    def run_from_infinite_producers(self):
        """
        This method handles the state when processing data from infinite
        producers.
        """
        # Consumers initialization
        consumer_list = list()
        for consumer in [FramesStats,
                         InformationElementsStats]:
            consumer_queue = Queue()
            consumer_instance = consumer(consumer_queue)
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
            print(str(e))
        finally:
            print("Mediator Finally")
            for item in consumer_list:
                consumer = item[0]
                if consumer.is_alive():
                    consumer.shutdown()
                    try:
                        # Wait for 30 seconds for consumer to shutdown and join.
                        consumer.join(30)
                    except TimeoutError:
                        # Force consumer to terminate.
                        print("Forcing %s to terminate." % \
                              consumer.__class__.__name__)
                        consumer.terminate()

    def shutdown(self):
        """
        This method sets the __stop__ event to stop the process.
        """
        print("Mediator - shutdown.")
        self.__stop__.set()

    def timeout_event(self):
        """
        This method sets the __timeout_event__ to change the queue timeout.
        This was added to fix the race condition that happends between a new
        producer starts and the queue timeout monitoring in the mediator.
        """
        print("Mediator timeout event!!!")
        self.__timeout_event__.set()


class FramesStats(WigProcess):
    """
    TODO: Documentation
    """

    def __init__(self, frames_queue):
        WigProcess.__init__(self)
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
        
        print("Frames: %d" % self.__total_frames_count__)
        print("Management Frames: %d" % self.__type_management_count__)
        print("Control Frames: %d" % self.__type_control_count__)
        print("Data Frames: %d" % self.__type_data_count__)
        print("Unknown Frames: %d" % self.__type_unknown_count__)

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
