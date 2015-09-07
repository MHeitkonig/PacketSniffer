#!/usr/bin/env python3

import socket
import struct
import binascii

def parse_ethernet(frame):
    header_length = 14
    header = frame[:header_length]
    (dest, source, type_code) = struct.unpack("!6s6sH", header)
    if type_code == 0x8100:
        header_length = 18
        header = frame[:header_length]
        type_code = struct.unpack("!16xH", header)
    packet = frame[header_length:]
    return dest, source, type_code, packet

def parse_ICMP(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    (typecode, code, checksum) = struct.unpack_from("!BBH4x", header)
    return typecode, code, checksum
    
   
def parse_ip(packet):
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    header = packet[:header_length_in_bytes]
    data = packet[header_length_in_bytes:]
    (total_length, protocol, source_addr, dest_addr) = struct.unpack_from("!2xH5xB2x4s4s", header)
    source_addr = socket.inet_ntoa(source_addr)
    dest_addr = socket.inet_ntoa(dest_addr)
    #print("Source Address: {}\nDestination Address: {}\n".format(source_addr, dest_addr))
    return header_length_in_bytes, data, total_length, protocol, source_addr, dest_addr

def parse_udp(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    (source_port, dest_port, data_length, checksum) = struct.unpack("!HHHH", header)
    #print("Source Port: {}\nDestination Port: {}\nData length: {}\nChecksum: {}\n".format(source_port, dest_port, data_length, checksum))
    return source_port, dest_port, data_length, checksum, data

def prettify(mac_string):
    a = ""
    for b in mac_string:
        a += ("%02x:" % (b))
    return(a[0:-1])

def main():    
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    #s.bind(("localhost",0))

    while True:
        (frame, address) = s.recvfrom(65565)
        (dest, source, type_code, packet) = parse_ethernet(frame)
        dest = prettify(dest)
        source = prettify(source)
        if type_code == 0x0800:
            (header_length_in_bytes, data, total_length, protocol, source_addr, dest_addr) = parse_ip(packet)
            if protocol == 17:
                (source_port, dest_port, data_length, checksum, data) = parse_udp(data)
                
            
            elif protocol == 1:
            	(typecode, code, checksum) = parse_ICMP(data)


            else:
                print("Protocol number {} is not ICMP (1) or UDP (17)\n".format(protocol))
                continue
        else:
        	print("Type code {} did not match 0x0800 (IPv4)\n".format(type_code))
        	continue
        
        print("\n\n==================\nEthernet:\n\nDestination MAC: {}\nSource MAC: {}\nType code: {}".format(dest, source, type_code))
        #print("Socket address: {}\n".format(address))
        print("\nIP:\n\nHeader length: {}\nTotal length: {}\nProtocol: {}\nSource address: {}\nDestination address: {}".format(header_length_in_bytes, total_length, protocol, source_addr, dest_addr))
        if protocol == 1:
            print ("\nICMP:\n\nTypecode: {}\nCode: {}\nChecksum: {}\n".format(typecode, code, checksum))
        if protocol == 17:
            print("\nUDP:\n\nSource port: {}\nDestination port: {}\nData length: {}\nChecksum: {}\nData: {}".format(source_port, dest_port, data_length, checksum, data))
        




if __name__ == "__main__":
    main()