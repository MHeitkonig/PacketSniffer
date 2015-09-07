#!/usr/bin/env python

import socket

stringbuf = ""
for i in range(0, 1000):
    stringbuf = stringbuf + "spam " + str(i) + "\n"
buf = stringbuf.encode("utf-8")

s = socket.create_connection(("localhost", 42424))
s.sendall(buf)
s.close()
