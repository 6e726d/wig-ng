#!/usr/bin/env python

import os
import struct
import argparse

from multiprocessing import Process, Queue

import pcapy

# Link-Layer Headre Types
# https://www.tcpdump.org/linktypes.html
DLT_IEEE802_11 = 105
DLT_IEEE802_11_RADIO = 127


def get_frame_type(buff):
    """
    """
    pass


def management_processing(iq, oq, fq):
    pass


def control_processing(iq, oq, fq):
    pass


def data_processing(iq, oq, fq):
    pass


def get_radiotap_header_length(buff):
    """
    https://www.radiotap.org/
    struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
    } __attribute__((__packed__));
    """
    if len(buff) < 8:
        raise Exception("Invalid radiotap header.")
    length = struct.unpack("<H", buff[2:4])[0]
    return length


def pcap_processing(pcap_filename):
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
    idx = get_radiotap_header_length(frame)
    while frame:
        print "%r" % frame[idx:idx+2]
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
