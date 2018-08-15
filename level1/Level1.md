## First look

```sh
level1@io:/levels$ ls -l level01*
-r-sr-x--- 1 level2 level1 1184 Jan 13  2014 level01
```
We can see that there is no source code for level01.
This means that we have to reverse engineer the logic to get to level2.

```sh
level1@io:/levels$ file level01
level01: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```

From this simple `file` command, we can see that it is Executable Linkable Format. 32 bits architecture and written for the intel cpu. 

```sh
level1@io:/levels$ strings level01
,0<	w
Enter the 3 digit passcode to enter: Congrats you found it, now read the password for level2 from /home/level2/.pass
/bin/sh
.symtab
.strtab
.shstrtab
.text
.lib
.data
level01.asm
fscanf
skipwhite
doit
exitscanf
YouWin
exit
puts
main
prompt1
prompt2
shell
_start
__bss_start
_edata
_end
```
Without running first running the binary, we can see from the `strings` command that the program will be asking for a 3 digit passcode. 

```sh
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter: 111
```
We can run the actual binary to confirm our inference.

## Radare2 
Ionetgarage has installed a very useful command line reversing framework. This allows us to do static analysis easier than plain `gdb` or `objdump`.

### Static analysis

```sh
level1@io:/levels$ r2 level01
Warning: Cannot initialize dynamic strings
 -- Use rarun2 to launch your programs with a predefined environment.
[0x08048080]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
```
`aaa` will run radare2's auto analysis. This will help analyse functions and autorename functions for us.

```sh
[0x08048080]> s main
[0x08048080]> VV
```
we can proceed to seek to main function and `VV` trigger a visual graph mode.

![radare visual](./images/image1.png)

In intel x86 architecture, the convention for function is to pass arguments via the stack and pass the return value to register `eax`. From here, we can see a `cmp` instruction, followed by a `je YouWin` which means jump to the function YouWin() if the content of register `eax` is equal to the value `0x10f`. 

You should notice the `0x` prefix. This means that this is a hexadecimal representation.

```sh
level1@io:/levels$ rax2 0x10f
271
level1@io:/levels$ python
Python 2.7.13 (default, Nov 24 2017, 17:33:09) 
[GCC 6.3.0 20170516] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x10f
271
```
One can convert a hexadecimal to a decimal value by the above 2 methods.

```sh
level1@io:/levels$ ./level01
Enter the 3 digit passcode to enter: 271
Congrats you found it, now read the password for level2 from /home/level2/.pass
sh-4.3$ id    
uid=1001(level1) gid=1001(level1) euid=1002(level2) groups=1001(level1),1029(nosu)
sh-4.3$ cat /home/level2/.pass
XXXXXXXXXXXXXXXXXXXXXX
```

We successfully obtained a shell. We can see that our effective user id became level2.
Thus, we have access to the password for the next level.

## Additionals

The good thing about radare over gdb here is that this binary is statically linked. 

```sh
(gdb) set disassembly-flavor intel
(gdb) disass main
Dump of assembler code for function main:
   0x08048080 <+0>:	push   0x8049128
   0x08048085 <+5>:	call   0x804810f
   0x0804808a <+10>:	call   0x804809f
   0x0804808f <+15>:	cmp    eax,0x10f
   0x08048094 <+20>:	je     0x80480dc
   0x0804809a <+26>:	call   0x8048103
End of assembler dump.
```
The output of gdb didn't tell us what function is being called. This would introduced more time to figure out that these are just library functions. IDA also is capable of analysing library functions. Its technology has a very interesting name called FLIRT.

Hope this write up helps beginners who are interested in reversing and pwn.
