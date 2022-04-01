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

import os
import time
import argparse

from multiprocessing import Queue, Array, TimeoutError
from multiprocessing import Array as mpArray

from consumers.base import Mediator
from consumers.base import FrameInjectionManager
from consumers.base import OutputManager
from producers.base import LiveNetworkCapture
from producers.base import OfflineNetworkCapture

from helpers.network import interfaces
from helpers.output import writer

import pcapy


APP_NAME = "Wig-ng"
VERSION_MAJOR = 0
VERSION_MINOR = 1
DESCRIPTION = ""  # TODO: Add application description

SUPPORTED_EXTENSIONS = ["cap", "pcap"]


def check_input_network_interfaces(interfaces_list):
    """
    Check if interfaces support IEEE 802.11 and are on monitor mode.
    """
    for interface in interfaces_list:
        if interface not in interfaces.get_ieee80211_network_interfaces():
            print("Error: %s is not a valid IEEE 802.11 interface." % interface)
            raise Exception("Network Interface Error.")
        if not interfaces.is_monitor_mode_set(interface):
            print("Error: %s is not on monitor mode." % interface)
            raise Exception("Network Interface Error.")


def check_input_pcap_capture_files(files_list):
    """
    Check if pcap capture files exist and are valid for the application.
    """
    for file in files_list:
        if not os.path.exists(file):
            print("Error: %s does not exists." % file)
            raise Exception("PCAP Capture File Error.")
        if not os.path.isfile(file):
            print("Error: %s is not a file." % file)
            raise Exception("PCAP Capture File Error.")
        pd = pcapy.open_offline(file)
        datalink = pd.datalink()
        if datalink not in [interfaces.DLT_IEEE802_11,
                            interfaces.DLT_IEEE802_11_RADIO]:
            print("Error: %s is not a valid IEEE 802.11 network capture file." % file)
            raise Exception("PCAP Capture File Error.")


def doit_pcap_files(files_list, concurrent_files, verbose_level):
    """
    TODO: Add documentation.
    """
    try:
        frame_queue = Queue()
        output_queue = Queue()

        output_manager = OutputManager(output_queue)
        output_manager.start()

        mediator = Mediator(frame_queue, output_queue, OfflineNetworkCapture.PRODUCER_TYPE)

        producers_list = list()
        while files_list:
            _file = files_list[0]

            if len(producers_list) < concurrent_files:
                producer = OfflineNetworkCapture(_file, frame_queue)
                if verbose_level > writer.OUTPUT_INFO:
                    output_queue.put({'': 'Producer: %s - %s' % (producer, _file)})
                producers_list.append(producer)
                producer.start()
                files_list.remove(_file)

            # Start mediator as soon as we have one or more producers
            if not mediator.is_alive():
                mediator.start()

            for producer in producers_list:
                if not producer.is_alive():
                    output_queue.put({'': 'Producer: %s has finished.' % producer})
                    producers_list.remove(producer)

            # To avoid 100% CPU usage
            time.sleep(1)

        # We started all producers, we can flag the timeout event.
        mediator.timeout_event()

        while True:
            if not producers_list:
                output_queue.put({'': 'All producers ended.'})
                break

            for producer in producers_list:
                if not producer.is_alive():
                    output_queue.put({'': '%s finished.' % producer})
                    producers_list.remove(producer)
                time.sleep(1)

        # Wait for Output Manager
        while True:
            if output_manager.is_alive() and output_queue.empty():
               output_manager.shutdown()
               output_manager.join()
               break
            time.sleep(1)

        if mediator.is_alive():
            # Give mediator 15 minutes to join.
            mediator.join(60 * 15)
            if mediator.is_alive():
                mediator.terminate()
    except KeyboardInterrupt:
        print("\nCaugth Ctrl+C...")
        # Graceful shutdown on all producers and consumers.
        for producer in producers_list:
            print("\nStoping %s" % producer)
            producer.shutdown()
            producer.join(10)
            producer.terminate()
        mediator.shutdown()
        mediator.join(10)
        mediator.terminate()
        # Wait for Output Manager
        while True:
            if output_manager.is_alive() and output_queue.empty():
               output_manager.shutdown()
               output_manager.join()
               break
            time.sleep(1)


def doit_live_capture(interfaces_list, verbose_level, active_mode):
    """
    TODO: Add documentation.
    """
    try:
        frame_queue = Queue()
        output_queue = Queue()
        injection_queue = Queue()

        output_manager = OutputManager(output_queue)
        output_manager.start()

        frame_injection_manager = FrameInjectionManager(injection_queue, interfaces_list)
        frame_injection_manager.start()

        producers_list = list()
        for interface in interfaces_list:
            producer = LiveNetworkCapture(interface, frame_queue, bpf_filter="type mgt")
            if verbose_level > writer.OUTPUT_INFO:
                output_queue.put({'': 'Producer: %s - %s' % (producer, interface)})
            producers_list.append(producer)
            producer.start()

        if active_mode:
            mediator = Mediator(frame_queue, output_queue, LiveNetworkCapture.PRODUCER_TYPE, injection_queue)
        else:
            mediator = Mediator(frame_queue, output_queue, LiveNetworkCapture.PRODUCER_TYPE)
        mediator.start()

        for producer in producers_list:
            if verbose_level > writer.OUTPUT_INFO:
                output_queue.put({'': 'Waiting for producer %s...' % producer})
            producer.join()

        mediator.shutdown()
    except KeyboardInterrupt:
        print("\nCaugth Ctrl+C...\n")
        # Graceful shutdown on all producers and consumers.
        for producer in producers_list:
            producer.shutdown()
            producer.join(30)
            if producer.is_alive():
                producer.terminate()

        print("Waiting for mediator...")
        mediator.shutdown()
        mediator.join(90)
        mediator.terminate()

        # Wait for Output Manager
        while True:
            if output_manager.is_alive() and output_queue.empty():
               output_manager.shutdown()
               output_manager.join()
               break
            time.sleep(1)

        frame_injection_manager.terminate()


class PcapCatureDir(argparse.Action):
    """
    ArgParse Action that checks for a valid directory containing at leats one
    pcap capture file.
    """
    def __call__(self, parser, namespace, values, option_string=None):
        _dir = values
        if not os.path.isdir(_dir):
            parser.error("%s is not a valid path" % _dir)

        if os.access(_dir, os.R_OK):
            setattr(namespace, self.dest, _dir)
        else:
            parser.error("Error: %s is not a readable dir" % _dir)

        has_pcap_files = False
        _files = list()
        for (root, _, files) in os.walk(_dir):
            for filename in files:
                extension = filename.split(".")[-1]
                if extension in SUPPORTED_EXTENSIONS:
                    has_pcap_files = True
                    _files.append(os.path.join(root, filename))
        if not has_pcap_files:
            parser.error("Error: %s doesn't contain pcap files." % _dir)
        else:
            setattr(namespace, self.dest, _files)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument('-v', '--verbose',
        dest='verbose_level',
        action='count',
        default=0,
        help='Output verbosity (incremental).')

    parser.add_argument('-c', '--concurrent',
        type=int,
        default=4,
        metavar='count',
        help='Number of PCAP capture files to process simultaneously.')

    parser.add_argument('-a', '--active',
        action="store_true",
        help='Some modules can perform frame injection, this is define by setting the active mode.')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface',
        action='append',
        metavar='network interface',
        help='IEEE 802.11 network interface on monitor mode.')
    group.add_argument('-r',
        action='append',
        metavar='pcap file',
        help='PCAP capture file with IEEE 802.11 network traffic.')
    group.add_argument('-R',
        action=PcapCatureDir,
        metavar='pcap directory',
        help='Directory with PCAP capture files.')

    args = parser.parse_args()

    if args.interface:
        check_input_network_interfaces(args.interface)
        doit_live_capture(args.interface, args.verbose_level, args.active)

    if args.r:
        check_input_pcap_capture_files(args.r)
        doit_pcap_files(args.r, args.concurrent, args.verbose_level)

    if args.R:
        check_input_pcap_capture_files(args.R)
        doit_pcap_files(args.R, args.concurrent, args.verbose_level)
