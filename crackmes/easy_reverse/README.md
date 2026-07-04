# [easy_reverse](https://crackmes.one/crackme/5b8a37a433c5d45fc286ad83) — crackme.one

| | |
|---|---|
| **Author** | cbm-hackers |
| **Language** | C/C++ |
| **Arch** | x86-64 |
| **Platform** | Linux/Unix |
| **Objective** | Find the password |

---

## 1. Reconnaissance

Running the binary to observe its behavior:

```text
$ ./rev50_linux64-bit
USAGE: ./rev50_linux64-bit <password>
try again!
```

The binary expects a password. Trying a random one:

```text
$ ./rev50_linux64-bit password
USAGE: ./rev50_linux64-bit <password>
try again!
```
both cases fail and lead to the same usage message

Gathering basic information with `strings`, `file` and `checksec`

```text
$ file rev50_linux64-bit
rev50_linux64-bit: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0,
BuildID[sha1]=6db637ef1b479f1b821f45dfe2960e37880df4fe, not stripped
```

```text
$ checksec --file=rev50_linux64-bit
RELRO      Partial RELRO
STACK      No canary found
NX         NX enabled
PIE        PIE enabled
FORTIFY    No
```

```text
$ strings rev50_linux64-bit
try again!
Nice Job!!
flag{%s}
GCC: (Debian 7.3.0-25) 7.3.0
main
usage
```

Key takeaways:
- **file**: 64-bit ELF, dynamically linked, **not stripped** (so we'll see function names).
- **checksec**: **PIE enabled** (addresses will be randomized at runtime), no FORTIFY.
- **strings**: the success/failure messages and the flag format, the gcc version, and the
  function names `main` and `usage` (visible because the binary is not stripped).

---

## 2. Static Analysis (Ghidra)

Opening it in Ghidra, we directly get the `main` function:

```c
undefined8 main(int param_1,undefined8 *param_2)

{
  size_t sVar1;
  
  if (param_1 == 2) {
    sVar1 = strlen((char *)param_2[1]);
    if (sVar1 == 10) {
      if (*(char *)(param_2[1] + 4) == '@') {
        puts("Nice Job!!");
        printf("flag{%s}\n",param_2[1]);
      }
      else {
        usage(*param_2);
      }
    }
    else {
      usage(*param_2);
    }
  }
  else {
    usage(*param_2);
  }
  return 0;
}
```

- `undefined8`: Ghidra doesn't recognize the return type of `main`.
- We can deduce the real signature from how the parameters are used:

```c
param_1 == 2)
(char *)param_2[1]
```

This is the classic `argc` / `argv` pattern, so we can reconstruct the signature and fix it
in Ghidra for clarity:

```c

int main(int argc,char **argv)

{
  size_t sVar1;
  
  if (argc == 2) {
    sVar1 = strlen(argv[1]);
    if (sVar1 == 10) {
      if (argv[1][4] == '@') {
        puts("Nice Job!!");
        printf("flag{%s}\n",argv[1]);
      }
      else {
        usage(*argv);
      }
    }
    else {
      usage(*argv);
    }
  }
  else {
    usage(*argv);
  }
  return 0;
}
```
The conditions required for the password to be accepted and print the flag:
- `argc == 2` : we need exactly one argument (the password).
- `strlen(argv[1]) == 10` : the password must contain exactly **10 characters**.
- `argv[1][4] == '@'` : the 5th character must be an **`@`**.

If any of these conditions fails, execution goes to the `usage` function:

```c
void usage(undefined8 param_1)

{
  printf("USAGE: %s <password>\n",param_1);
  puts("try again!");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```
This function prints the usage message and terminates the process. It calls `exit`, so it
never returns — hence Ghidra's *"does not return"* warning.

There is no fixed password: the binary only checks a **format**:
- exactly **10 characters**,
- the 5th character is an **`@`**.

So any input matching these two rules is accepted:

```text
$ ./rev50_linux64-bit anyt@hing1
Nice Job!!
flag{anyt@hing1}
```

The flag is simply the input we entered.

Now that we understand the logic statically, we can run a dynamic analysis to observe the
behavior at runtime.

---

## 3. Dynamic Analysis (pwndbg)

This analysis isn't needed to find the password (we already have it from the static
analysis). It's here to observe the binary at runtime: register states, calling convention,
and how memory addresses are manipulated.

> Note: `checksec` reported the binary as **PIE**, so addresses are randomized at each run
> (ASLR). That's why we see `0x5555...` addresses here instead of the clean addresses Ghidra
> shows.

Setting a breakpoint on `main` and running with a valid password:

```text
pwndbg> break main
Breakpoint 1 at 0x11cc
pwndbg> run 0123@67891
```

We run it with a valid password, but a wrong one would let us follow the failing paths too.

Focusing on the two registers that matter here:

```text
 RDI  2
 RSI  0x7fffffffd588 —▸ 0x7fffffffd9fe ◂— 'rev50_linux64-bit'
```

- **RDI** = `argc` (2 for us: the binary name and the password).
- **RSI** = the address of `argv`, the array of pointers to our arguments (directly related
  to `argc` in RDI).

Walking through the first part of the disassembly:

```asm
 ► main+8      mov    dword ptr [rbp - 4], edi        [rbp-4]  <= 2
   main+11     mov    qword ptr [rbp - 0x10], rsi     [rbp-0x10] <= argv
   main+15     cmp    dword ptr [rbp - 4], 2          2 - 2   (ZF set)
   main+19   ✘ jne    main+147
   main+21     mov    rax, qword ptr [rbp - 0x10]     rax = argv
   main+25     add    rax, 8                          rax = &argv[1]
   main+29     mov    rax, qword ptr [rax]            rax = argv[1]  (the string)
   main+32     mov    rdi, rax
   main+35     call   strlen@plt
   main+40     cmp    rax, 0xa
   main+44     jne    main+130
```

- **main+8**: save `argc` (EDI) on the stack at `rbp-4`.
- **main+11**: save `argv` (RSI) on the stack at `rbp-0x10`.
- **main+15**: compare `argc` with the expected value `2` (`if (argc == 2)`).
- **main+19**: the comparison is true, so the `jne` is not taken.
- **main+21 to +32**: load `argv` into `rax`, add 8 bytes to point at `argv[1]`,
  dereference to get the address of the string, and put it in `rdi`.
- **main+35**: call `strlen`, which computes the length of the string in RDI and returns it
  in RAX.
- **main+40**: compare RAX with the expected length `0xa` (10 in decimal).

If the length matches, the `jne` is not taken and we reach the next part:

```asm
   main+46     mov    rax, qword ptr [rbp - 0x10]     rax = argv
   main+50     add    rax, 8                          rax = &argv[1]
   main+54     mov    rax, qword ptr [rax]            rax = argv[1]  (the string)
   main+57     add    rax, 4                          rax = &argv[1][4]  (5th char)
   main+61     movzx  eax, byte ptr [rax]             eax = argv[1][4]  (= 0x40)
   main+64     cmp    al, 0x40                        0x40 - 0x40  (ZF set)
```

- **main+46 to +54**: same as before, reload the address of `argv[1]`'s string.
- **main+57**: add 4 bytes to point at the 5th character.
- **main+61**: load a single byte (the 5th character) into `eax`; `movzx` zero-extends it to
  fill the upper bits of the register.
- **main+64**: compare `al` (the 5th character) with `0x40` (`'@'` in ASCII).

If this comparison passes, the password is valid and the flag is printed.

---

## 4. Conclusion

This binary doesn't expect a unique, fixed password. It's a **format check**, so there is an
infinite number of valid inputs, as long as they match the expected format (10 characters,
5th one being `@`).

More importantly, the binary itself contains **no secret** — there is no real password to
recover, and the flag is just the input echoed back (`printf("flag{%s}", argv[1])`). This is
a common weakness: validating the *format* of an input instead of a specific secret value.
Such a check is trivially bypassed once you understand the expected format.
