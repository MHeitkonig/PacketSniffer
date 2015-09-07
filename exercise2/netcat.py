#!/usr/bin/env python

import socket

host = "localhost"
port = 42424
message = "Hello there"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("Sending \"" + message + "\" to " + host + ":" + str(port))
s.sendto(message.encode("utf-8"), (host, port))
s.close()