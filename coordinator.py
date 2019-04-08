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
import struct
import argparse

from multiprocessing import Process, Queue

import pcapy

from helpers import radiotap
from helpers import ieee80211


def management_processing(iq, oq, fq):
    """
    TODO: function documentation.
    """
    pass


def control_processing(iq, oq, fq):
    """
    TODO: function documentation.
    """
    pass


def data_processing(iq, oq, fq):
    """
    TODO: function documentation.
    """
    pass

def pcap_processing(pcap_filename):
    """
    TODO: function documentation.
    """
    mq = Queue()  # Management Frame Queue [Input]
    cq = Queue()  # Control Frame Queue [Input]
    dq = Queue()  # Data Frame Queue [Input]
    pq = Queue()  # Processed Frame Queue [Output]
    fq = Queue()  # Frame Injection Queue [Output]
    mp = Process(target=management_processing, args=(mq, pq, fq,))
    cp = Process(target=control_processing, args=(cq, pq, fq,))
    dp = Process(target=data_processing, args=(dq, pq, fq,))

    processes = [mp, cp, dp]

    for process in processes:
        process.start()

    # Do stuff until end and send END signal to the processes
    pd = pcapy.open_offline(pcap_filename)
    datalink = pd.datalink()
    if datalink not in [DLT_IEEE802_11, DLT_IEEE802_11_RADIO]:
        raise Exception("Invalid Datalink. Not a IEEE 802.11 network capture.")
    hdr, frame = pd.next()
    if datalink == DLT_IEEE802_11:
        idx = 0
    else:
        idx = radiotap.get_length(frame)
    while frame:
        frame_control = frame[idx:idx+ieee80211.FRAME_CONTROL_HEADER_LENGTH]
        # print "0x%02X" % ieee80211.get_frame_type(frame_control)
        hdr, frame = pd.next()

    for process in processes:
        if process.is_alive():
            process.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()  # TODO: add description
    parser.add_argument("input", help="pcap input filename")
    args = parser.parse_args()
    if not os.path.exists(args.input) or not os.path.isfile(args.input):
        print("%r does not exists or is a file." % args.input)
        exit(-1)
    pcap_processing(args.input)
