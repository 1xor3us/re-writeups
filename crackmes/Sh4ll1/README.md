# [Sh4ll1](https://crackmes.one/crackme/5aef37c733c5d41ac64b492e) — crackme.one

<!-- Fill in the metadata table. Keep it short: it's just to set the scene. -->

| | |
|---|---|
| **Author** | destructeur |
| **Language** | C/C++ |
| **Arch** | x86-64 |
| **Platform** | Linux |
| **Objective** | find the password |

---

## 1. Reconnaissance

Running the binary to observe its behavior:

```text
$ ./crackMe1.bin
Password: jhndjkzqndhjqzd
Bad password
```

The binary reads the password from `stdin` (not from a command-line argument).

Gathering basic information:

```text
$ file crackMe1.bin
crackMe1.bin: ELF 64-bit LSB pie executable, x86-64, dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, not stripped

$ checksec --file=crackMe1.bin
RELRO      Partial RELRO
STACK      No canary found
NX         NX enabled
PIE        PIE enabled

$ strings crackMe1.bin
Password:
Good password
Bad password
main
```

Key takeaways:
- 64-bit ELF, **not stripped** (we'll see function names).
- **PIE enabled**, so runtime addresses are randomized (ASLR) — expect `0x5555...` addresses under the debugger.
- The success/failure strings and the `main` symbol.

---

## 2. Static Analysis (Ghidra)

`main` simply calls two functions and returns:

```c
undefined8 main(void)

{
  systemv();
  systemo();
  return 0;
}
```

The decompiler shows `systemv` as **empty**:

```c
void systemv(void)

{
  return;
}

And `systemo` contains the actual logic:

void systemo(void)

{
  ostream *poVar1;
  int local_18;
  int local_14;
  int local_10;
  int local_c;

  local_c = local_c + local_10;
  local_14 = local_c * 0x2d;
  local_18 = 0;
  std::operator<<((ostream *)std::cout,"Password: ");
  std::istream::operator>>((istream *)std::cin,&local_18);
  if (local_18 == local_14) {
    poVar1 = std::operator<<((ostream *)std::cout,"Good password");
    std::ostream::operator<<(poVar1,std::endl<>);
  }
  else {
    poVar1 = std::operator<<((ostream *)std::cout,"Bad password");
    std::ostream::operator<<(poVar1,std::endl<>);
  }
  return;
}
```

The `std::` calls confirm this is a C++ binary. The win condition is straightforward:

- **`local_18` (our input) must equal `local_14` (the computed password).**
- `local_14 = (local_c + local_10) * 0x2d`.

**At first glance**, `local_c` and `local_10` look like *uninitialized* local variables:
nothing in `systemo` writes to them before they are read. That would make the password
depend on stack garbage. But `systemv` — shown as empty by the decompiler — is
suspicious. Time to check what actually runs.

---

## 3. Dynamic Analysis (pwndbg)

> The binary is PIE, so addresses are randomized each run. The values below are from one
> session; only the relative layout matters.

`main` calls `systemv` then `systemo` back-to-back:

```asm
main+4   call   systemv
main+9   call   systemo
```

### The decompiler was hiding something

Breaking in `systemv` and looking at the **raw disassembly** (not the decompiler) reveals
that `systemv` is **not empty at all**:

```asm
systemv()+4    mov    dword ptr [rbp - 4], 5        ; writes 5
systemv()+11   mov    dword ptr [rbp - 8], 7        ; writes 7
systemv()+18   mov    dword ptr [rbp - 0xc], 0x1f5  ; writes 501
systemv()+25   nop
systemv()+26   pop    rbp
systemv()+27   ret
```

Ghidra's decompiler removed these three writes as **dead code**: from `systemv`'s point of
view, they write to local variables that are never read again inside the function, so the
decompiler considered them useless and hid them.

Saving the addresses written by `systemv`:

```text
pwndbg> p/x $rbp        # 0x7fffffffd480
pwndbg> p/x $rbp-4      # 0x7fffffffd47c   <- 5 written here
pwndbg> p/x $rbp-8      # 0x7fffffffd478   <- 7 written here
```

### systemo reuses the same stack slots

Breaking in `systemo` and reading the same offsets:

```text
pwndbg> p/x $rbp        # 0x7fffffffd480   <- SAME rbp as systemv
pwndbg> p/x $rbp-4      # 0x7fffffffd47c   <- SAME address
pwndbg> p/x $rbp-8      # 0x7fffffffd478   <- SAME address
```

`systemv` and `systemo` share the **same `rbp`**, so `[rbp-4]` and `[rbp-8]` point to the
**same absolute addresses** in both functions. This happens because:

- both functions are called at the **same depth** from `main` (sibling calls),
- `main` does nothing between the two calls, so `rsp` is identical at both `call`
  instructions,
- the stack is never cleared, so the bytes written by `systemv` survive.

`systemo` therefore reads back exactly the `5` and `7` that `systemv` wrote:

```asm
systemo()+8    mov    eax, dword ptr [rbp - 8]      ; eax = 7
systemo()+11   add    dword ptr [rbp - 4], eax      ; [rbp-4] = 5 + 7 = 0xc
systemo()+14   mov    eax, dword ptr [rbp - 4]      ; eax = 0xc (12)
systemo()+17   imul   eax, eax, 0x2d               ; 12 * 45 = 540 (0x21c)
systemo()+20   mov    dword ptr [rbp - 0xc], eax    ; pwd = 540
...
systemo()+68   mov    eax, dword ptr [rbp - 0x10]   ; eax = input
systemo()+71   cmp    eax, dword ptr [rbp - 0xc]    ; input == pwd ?
```

So the expected password is `(5 + 7) * 45 = 540`.

Note the `0x1f5` (501) written by `systemv` is never used in the computation — it's a decoy,
like the `system`-looking function names.

---

## 4. Solution

```text
$ ./crackMe1.bin
Password: 540
Good password
```

The value is stable across runs (even with `env -i`), because `5` and `7` are written by
`systemv` as hard-coded constants, not inherited from a fragile environment.

---

## 5. Conclusion

The password does not come from stack garbage, as it first appeared. It comes from a
**use-of-uninitialized-variable** pattern: `systemo` reads locals it never initializes, and
those slots happen to hold values written by `systemv` a moment earlier, at the same stack
depth.

This is a bug in the **program**, made possible by a **design choice of C++**: the language
favors performance and control over safety. It does not require zero-initializing memory,
initializing variables, or bounds checking — it leaves that responsibility to the
programmer. Compiling with `-Wall` would have warned (`used uninitialized`), and compiling
with `-O2` would break the trick entirely (the compiler eliminates `systemv`'s dead writes).

In this crackme there is no attacker-controlled input into the vulnerable values, so it isn't
a real vulnerability here. But use of uninitialized memory is a bug class that is
dangerous in real code:
- a function returning an uninitialized buffer → **information leak** (leftover sensitive
  bytes; this is essentially what Heartbleed exposed),
- an uninitialized variable driving control flow (a flag, a length, a pointer) → unexpected,
  potentially **exploitable** behavior,
- an uninitialized pointer used for a write → **arbitrary write** primitive.

The main takeaway is methodological: the decompiler showed `systemv` as empty, but the raw
disassembly and the runtime proved otherwise.

