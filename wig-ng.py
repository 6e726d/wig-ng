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

import os
import time
import argparse

from multiprocessing import Queue, TimeoutError

from consumers.base import Mediator
from producers.base import LiveNetworkCapture
from producers.base import OfflineNetworkCapture

from helpers.network import interfaces
from helpers.output import writer

import pcapy


DESCRIPTION = ""  # TODO: Add application description

SUPPORTED_EXTENSIONS = ["cap", "pcap"]


def check_input_network_interfaces(interfaces_list):
    """
    Check if interfaces support IEEE 802.11 and are on monitor mode.
    """
    for interface in interfaces_list:
        if interface not in interfaces.get_ieee80211_network_interfaces():
            print("%s is not a valid IEEE 802.11 interface." % interface)
            raise Exception("Network Interface Error.")
        if not interfaces.is_monitor_mode_set(interface):
            print("%s is not on monitor mode." % interface)
            raise Exception("Network Interface Error.")


def check_input_pcap_capture_files(files_list):
    """
    Check if pcap capture files exist and are valid for the application.
    """
    for file in files_list:
        if not os.path.exists(file):
            print("%s does not exists." % file)
            raise Exception("PCAP Capture File Error.")
        if not os.path.isfile(file):
            print("%s is not a file." % file)
            raise Exception("PCAP Capture File Error.")
        pd = pcapy.open_offline(file)
        datalink = pd.datalink()
        if datalink not in [interfaces.DLT_IEEE802_11,
                            interfaces.DLT_IEEE802_11_RADIO]:
            print("%s is not a valid IEEE 802.11 network capture file." % file)
            raise Exception("PCAP Capture File Error.")


def doit_pcap_files(files_list, concurrent_files, verbose_level):

    try:
        fq = Queue()

        mediator = Mediator(fq, OfflineNetworkCapture.PRODUCER_TYPE, verbose_level)

        producers_list = list()
        while files_list:
            _file = files_list[0]

            if len(producers_list) < concurrent_files:
                producer = OfflineNetworkCapture(_file, fq)
                if verbose_level > writer.OUTPUT_INFO:
                    print("%s - %s" % (producer, _file))
                producers_list.append(producer)
                producer.start()
                files_list.remove(_file)

            # Start mediator as soon as we have one or more producers
            if not mediator.is_alive():
                mediator.start()

            for producer in producers_list:
                if not producer.is_alive():
                    print("%s finished" % producer)
                    producers_list.remove(producer)

            # To avoid 100% CPU usage
            time.sleep(1)

        # We started all producers, we can flag the timeout event.
        mediator.timeout_event()

        while True:
            if not producers_list:
                print("All producers ended.")
                break

            for producer in producers_list:
                if not producer.is_alive():
                    print("%s finished" % producer)
                    producers_list.remove(producer)
                time.sleep(1)

        if mediator.is_alive():
            # Give mediator 15 minutes to join.
            mediator.join(60 * 15)
            if mediator.is_alive():
                mediator.terminate()
    except KeyboardInterrupt:
        print("Caugth Ctrl+C...")
        # Graceful shutdown on all producers and consumers.
        for producer in producers_list:
            print("Stoping %s" % producer)
            producer.shutdown()
            producer.join(10)
            producer.terminate()
        mediator.shutdown()
        mediator.join(10)
        mediator.terminate()


def doit_live_capture(interfaces_list, verbose_level):

    try:
        fq = Queue()

        producers_list = list()
        for interface in interfaces_list:
            producer = LiveNetworkCapture(interface, fq)
            if verbose_level > writer.OUTPUT_INFO:
                print("%s - %s" % (producer, interface))
            producers_list.append(producer)
            producer.start()

        mediator = Mediator(fq, producers_list[0].PRODUCER_TYPE, verbose_level)
        mediator.start()

        for producer in producers_list:
            if verbose_level > writer.OUTPUT_INFO:
                print("Waiting for producer %s..." % producer)
            producer.join()

        mediator.shutdown()
    except KeyboardInterrupt:
        print("Caugth Ctrl+C...")
        # Graceful shutdown on all producers and consumers.
        for producer in producers_list:
            producer.shutdown()
            producer.join()
        mediator.shutdown()
        mediator.join()


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
            parser.error("%s is not a readable dir" % _dir)

        has_pcap_files = False
        _files = list()
        for (root, _, files) in os.walk(_dir):
            for filename in files:
                extension = filename.split(".")[-1]
                if extension in SUPPORTED_EXTENSIONS:
                    has_pcap_files = True
                    _files.append(os.path.join(root, filename))
        if not has_pcap_files:
            parser.error("%s doesn't contain pcap files." % _dir)
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

    print("Verbose Level: %d" % args.verbose_level)

    if args.interface:
        check_input_network_interfaces(args.interface)
        doit_live_capture(args.interface, args.verbose_level)

    if args.r:
        check_input_pcap_capture_files(args.r)
        doit_pcap_files(args.r, args.concurrent, args.verbose_level)

    if args.R:
        check_input_pcap_capture_files(args.R)
        doit_pcap_files(args.R, args.concurrent, args.verbose_level)
