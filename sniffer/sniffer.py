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

def parse_TCP(packet):
    header_length = 20
    header = packet[:header_length]
    (source_port, dest_port, sequence_number, ack_number, doff_res_flag , window, checksum, urgent_pointer) = struct.unpack("!HHLLHHHH", header)
    doff = (doff_res_flag >> 12)
    header_length = doff * 4
    data = packet[header_length:]
    flags = doff_res_flag & 0xFF
    return source_port, dest_port, sequence_number, ack_number, doff, flags, window, checksum, urgent_pointer, data

def parse_ICMP(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    (typecode, code, checksum) = struct.unpack_from("!BBH4x", header)
    return typecode, code, checksum

def parse_IP(packet):
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    header = packet[:header_length_in_bytes]
    data = packet[header_length_in_bytes:]
    (total_length, protocol, source_addr, dest_addr) = struct.unpack_from("!2xH5xB2x4s4s", header)
    source_addr = socket.inet_ntoa(source_addr)
    dest_addr = socket.inet_ntoa(dest_addr)
    #print("Source Address: {}\nDestination Address: {}\n".format(source_addr, dest_addr))
    return header_length_in_bytes, data, total_length, protocol, source_addr, dest_addr

def parse_UDP(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    (source_port, dest_port, data_length, checksum) = struct.unpack("!HHHH", header)
    #print("Source Port: {}\nDestination Port: {}\nData length: {}\nChecksum: {}\n".format(source_port, dest_port, data_length, checksum))
    return source_port, dest_port, data_length, checksum, data

def parse_ARP(packet):
    #This time, let's slice it up
    #hardware_type = packet[0:8]
    #protocol_type = packet[8:16]
    #hardware_address_length = ""
    #protocol_address_length = "" 
    #operation = "" 
    #sender_hardware_address = "" 
    #sender_ip_address = "" 
    #target_hardware_address = ""
    #target_ip_address = ""
    (hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation, sender_hardware_address1, sender_hardware_address2, sender_ip_address, target_hardware_address1, target_hardware_address2, target_ip_address) = struct.unpack_from("!HHBBHIHIHII", packet)
    sender_hardware_address = sender_hardware_address1 + sender_hardware_address2
    target_hardware_address = target_hardware_address1 + target_hardware_address2
    return hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation, sender_hardware_address, sender_ip_address, target_hardware_address, target_ip_address

def prettify(mac_string):
    a = ""
    for b in mac_string:
        a += ("%02x:" % (b))
    return(a[0:-1])

def parseFlags(flags):
    flagnames = ["CRW ", "ECE ", "URG ", "ACK ", "PSH ", "RST ", "SYN ", "FIN "]
    flagString = ""
    for x in range(0, 7):
        if flags & 2**x == 2**x:
            flagString += flagnames[x] 
    return flagString

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    #s.bind(("localhost",0))

    while True:
        (frame, address) = s.recvfrom(65565)
        (dest, source, type_code, packet) = parse_ethernet(frame)
        dest = prettify(dest)
        source = prettify(source)
        if type_code == 0x0800:
            (header_length_in_bytes, data, total_length, protocol, source_addr, dest_addr) = parse_IP(packet)
            if protocol == 17:
                (source_port, dest_port, data_length, checksum, data) = parse_UDP(data)
                
            
            elif protocol == 1:
            	(typecode, code, checksum) = parse_ICMP(data)

            elif protocol == 6:
                print(type_code)  
                (source_port, dest_port, sequence_number, ack_number, doff, flags, window, checksum, urgent_pointer, data) = parse_TCP(data)


            else:
                print("Protocol number {} is not ICMP (1) or UDP (17)\n".format(protocol))
                continue
        elif type_code == 0x0806:
            (hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation, sender_hardware_address, sender_ip_address, target_hardware_address, target_ip_address) = parse_ARP(packet)
            print("\nARP:\n\tHardware type: {}\n\tProtocol type: {}\n\tHardware address length: {}\n\tProtocol address length: {}\n\tOperation: {}\n\tSender hardware address: {}\n\tSender IP address: {}\n\tTarget hardware address: {}\n\tTarget IP address: {}\n\t".format(hardware_type, protocol_type, hardware_address_length, protocol_address_length, operation, sender_hardware_address, sender_ip_address, target_hardware_address, target_ip_address))

        else:
            print("\nPacket ignored: type code {} did not match 0x0800 (IPv4) or 0x806 (ARP)\n".format(type_code))
            continue

        print("\n+-+-+-+-+-+-+-+-+-+-+-+")
        print("\nEthernet:\n\tDestination MAC: {}\n\tSource MAC: {}\n\tType code: {}".format(dest, source, type_code))
        #print("Socket address: {}\n".format(address))
        print("\nIP:\n\tHeader length: {}\n\tTotal length: {}\n\tProtocol: {}\n\tSource address: {}\n\tDestination address: {}".format(header_length_in_bytes, total_length, protocol, source_addr, dest_addr))
        if protocol == 1:
            print ("\nICMP:\n\t\tTypecode: {}\n\t\tCode: {}\n\t\tChecksum: {}\n".format(typecode, code, checksum))
        if protocol == 17:
            print("\nUDP:\n\tSource port: {}\n\tDestination port: {}\n\tData length: {}\n\tChecksum: {}\n\tData: {}".format(source_port, dest_port, data_length, checksum, data))
        if protocol == 6:
            print("\nTCP:\n\tSource port: {}\n\tDestination port: {}\n\tSequence number: {}\n\tACK number: {}\n\tData Offset: {}\n\tFlags: {}\n\tWindow: {}\n\tChecksum: {}\n\tUrgent pointer: {}\n\tData: {}".format(source_port, dest_port, sequence_number, ack_number, doff, parseFlags(flags), window, checksum, urgent_pointer, data))
        print("\n\n")




if __name__ == "__main__":
    main()
