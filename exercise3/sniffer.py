#!/usr/bin/env python3

import socket
import struct

def parse_ip(packet):
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    header = packet[:header_length_in_bytes]
    data = packet[header_length_in_bytes:]
    (total_length, protocol, source_addr, dest_addr) = struct.unpack_from("!2xH5xB2x4s4s", header)
    source_addr = socket.inet_ntoa(source_addr)
    dest_addr = socket.inet_ntoa(dest_addr)
    print("Source Address: {}\nDestination Address: {}\n".format(source_addr, dest_addr))
    return header_length_in_bytes, header, data

def parse_udp(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    (source_port, dest_port, data_length, checksum) = struct.unpack("!HHHH", header)
    print("Source Port: {}\nDestination Port: {}\nData length: {}\nChecksum: {}\n".format(source_port, dest_port, data_length, checksum))
    return source_port, dest_port, data_length, checksum, data

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
    #s.bind(("localhost",0))
    while True:
       (data, address) = s.recvfrom(65565)
       (header_length_in_bytes, header, data) = parse_ip(data)
       parse_udp(data)

if __name__ == "__main__":
    main()

