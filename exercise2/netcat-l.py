#!/usr/bin/env python3

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

host = "localhost"
port = 42424
size = 1024
message = ""

s.bind((host, port))


while True:
    message = s.recvfrom(size)
    print (message)