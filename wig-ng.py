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

import pcapy


DESCRIPTION = ""  # TODO: Add application description

# Verbose Count
OUTPUT_INFO = 0
OUTPUT_VERBOSE = 1
OUTPUT_DEBUG = 2


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


def doit_pcap_files(files_list, verbose_count):

    try:
        fq = Queue()

        producers_list = list()
        for file in files_list:
            producer = OfflineNetworkCapture(file, fq)
            if verbose_count > OUTPUT_INFO:
                print("Starting producer %s - %s" % (producer, file))
            producers_list.append(producer)
            producer.start()

        mediator = Mediator(fq, producers_list[0].PRODUCER_TYPE)
        mediator.start()

        while True:
            if not producers_list:
                print("All producers ended.")
                break

            for producer in producers_list:
                if not producer.is_alive():
                    print("%s finished" % producer)
                    producers_list.remove(producer)
                time.sleep(2)

        # print("doit_pcap_files: before mediator shutdown.")
        # mediator.shutdown()
        # print("doit_pcap_files: after mediator shutdown.")
        # print("doit_pcap_files: before mediator join.")
        if mediator.is_alive():
            mediator.join(60 * 15)  # Wait 15 minutes.
            if mediator.is_alive():
                mediator.terminate()
        # mediator.terminate()
        # print("doit_pcap_files: after mediator join.")
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


def doit_live_capture(interfaces_list, verbose_count):

    try:
        fq = Queue()

        producers_list = list()
        for interface in interfaces_list:
            producer = LiveNetworkCapture(interface, fq)
            if verbose_count > OUTPUT_INFO:
                print("Starting producer %s - %s" % (producer, interface))
            producers_list.append(producer)
            producer.start()

        mediator = Mediator(fq, producers_list[0].PRODUCER_TYPE)
        mediator.start()

        for producer in producers_list:
            if verbose_count > OUTPUT_INFO:
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


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-v', '--verbose',
        dest='verbose_count',
        action='count',
        default=0,
        help='Output verbosity (incremental).')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--interface',
        action='append',
        metavar='network interface',
        help='IEEE 802.11 network interface on monitor mode.')
    group.add_argument('-r',
        action='append',
        metavar='pcap file',
        help='PCAP capture file with IEEE 802.11 network traffic.')
    args = parser.parse_args()

    if args.interface:
        check_input_network_interfaces(args.interface)
        doit_live_capture(args.interface, args.verbose_count)

    if args.r:
        check_input_pcap_capture_files(args.r)
        doit_pcap_files(args.r, args.verbose_count)
