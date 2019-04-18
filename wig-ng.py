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
import argparse

from multiprocessing import Queue

import consumers
import producers

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
            producer = producers.OfflineNetworkCapture(file, fq)
            if verbose_count > OUTPUT_INFO:
                print("Starting producer %s - %s" % (producer, file))
            producers_list.append(producer)
            producer.start()

        consumer = consumers.ConsumerProofOfConcept(fq)
        consumer.start()

        for producer in producers_list:
            if verbose_count > OUTPUT_INFO:
                print("Waiting for producer %s..." % producer)
            producer.join()

        consumer.shutdown()
        consumer.join()
    except KeyboardInterrupt:
        print("Caugth Ctrl+C...")
        # Graceful shutdown on all producers and consumers.
        for p in producers_list:
            p.shutdown()
            producer.join()
        consumer.shutdown()
        consumer.join()


def doit_live_capture(interfaces_list, verbose_count):

    try:
        fq = Queue()

        producers_list = list()
        for interface in interfaces_list:
            producer = producers.LiveNetworkCapture(interface, fq)
            if verbose_count > OUTPUT_INFO:
                print("Starting producer %s - %s" % (producer, interface))
            producers_list.append(producer)
            producer.start()

        consumer = consumers.ConsumerProofOfConcept(fq)
        consumer.start()

        for producer in producers_list:
            if verbose_count > OUTPUT_INFO:
                print("Waiting for producer %s..." % producer)
            producer.join()

        consumer.shutdown()
    except KeyboardInterrupt:
        print("Caugth Ctrl+C...")
        # Graceful shutdown on all producers and consumers.
        for p in producers_list:
            p.shutdown()
            p.join()
        consumer.shutdown()
        consumer.join()


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

    if args.i:
        check_input_network_interfaces(args.i)
        doit_live_capture(args.i, verbose_count)

    if args.r:
        check_input_pcap_capture_files(args.r)
        doit_pcap_files(args.r, verbose_count)
