# [simple XOR](https://crackmes.one/crackme/6946be18523504d8c842eb7e) — crackme.one

| | |
|---|---|
| **Author** | YandereMia |
| **Language** | C/C++ |
| **Arch** | x86-64 |
| **Platform** | Linux |
| **Objective** | find the key |

---

## 1. Reconnaissance

Running the binary to observe its behavior:

```text
./crackme 
usage ./crackme "<key>"

./crackme test
Nope.
```

the binary reads the key from `argv`

Gathering basic information:

```text
$ file crackme 
ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=5c4e8ac6d7a71eeda4b5ad18884d44161238cf58, for GNU/Linux 4.4.0, not stripped

$ checksec --file=crackme
RELRO           STACK CANARY      NX            PIE
Partial RELRO   Canary found      NX enabled    PIE enabled


$ strings crackme
usage ./crackme "<key>"
Pass valid!
Nope.
main
```

Key takeaways from recon:
- 64-bit ELF, **not stripped** (we'll see function names).
- **PIE enabled**, so runtime addresses are randomized (ASLR)
- The success/failure strings and the `main` symbol.

---

## 2. Static Analysis (Ghidra)

`main` function (after edit signature of main for `argc, argv`):

```c

int main(int argc,char **argv)

{
  byte *input;
  byte *pbVar1;
  byte *pbVar2;
  byte *pbVar3;
  byte *pbVar4;
  long in_FS_OFFSET;
  byte local_88 [32];
  byte local_68 [32];
  byte local_48 [32];
  byte local_28 [24];
  long canary;
  
  pbVar1 = local_88;
  canary = *(long *)(in_FS_OFFSET + 0x28);
  if (argc == 2) {
    local_88[0x10] = 0;
    pbVar4 = local_68;
    local_68[0x10] = 0;
    input = (byte *)argv[1];
    pbVar3 = local_48;
    pbVar2 = local_28;
    local_48[0x10] = 0;
    local_28[0x10] = 0;
    local_88[0] = 0x5e;
    local_88[1] = 0x36;
    local_88[2] = 0x32;
    local_88[3] = 0x28;
    local_88[4] = 0x41;
    local_88[5] = 0x79;
    local_88[6] = 0x26;
    local_88[7] = 0x33;
    local_88[8] = 0x60;
    local_88[9] = 0x72;
    local_88[10] = 0x37;
    local_88[0xb] = 0x6a;
    local_88[0xc] = 0x7c;
    local_88[0xd] = 0x51;
    local_88[0xe] = 0x7d;
    local_88[0xf] = 0x3e;
    local_68[0] = 0x36;
    local_68[1] = 0x69;
    local_68[2] = 0x75;
    local_68[3] = 0x37;
    local_68[4] = 0x28;
    local_68[5] = 0x69;
    local_68[6] = 0x55;
    local_68[7] = 0x42;
    local_68[8] = 0x70;
    local_68[9] = 0x44;
    local_68[10] = 0x24;
    local_68[0xb] = 0x39;
    local_68[0xc] = 0x4b;
    local_68[0xd] = 0x6c;
    local_68[0xe] = 0x49;
    local_68[0xf] = 0x43;
    local_48[0] = 0x3a;
    local_48[1] = 0x76;
    local_48[2] = 0x54;
    local_48[3] = 0x33;
    local_48[4] = 0x3f;
    local_48[5] = 0x5b;
    local_48[6] = 0x5a;
    local_48[7] = 0x7d;
    local_48[8] = 99;
    local_48[9] = 0x56;
    local_48[10] = 0x27;
    local_48[0xb] = 0x6f;
    local_48[0xc] = 0x66;
    local_48[0xd] = 0x38;
    local_48[0xe] = 0x3f;
    local_48[0xf] = 0x43;
    local_28[0] = 0x33;
    local_28[1] = 0x4b;
    local_28[2] = 0x70;
    local_28[3] = 0x2a;
    local_28[4] = 0x33;
    local_28[5] = 0x2b;
    local_28[6] = 0x4e;
    local_28[7] = 100;
    local_28[8] = 0x6a;
    local_28[9] = 0x78;
    local_28[10] = 0x5f;
    local_28[0xb] = 0x29;
    local_28[0xc] = 0x40;
    local_28[0xd] = 0x6b;
    local_28[0xe] = 100;
    local_28[0xf] = 0x4e;
    do {
      if (*input != (byte)(*pbVar1 ^ *pbVar2 ^ *pbVar4 ^ *pbVar3 ^ 0x20)) {
        puts("Nope.");
        goto LAB_00101176;
      }
      pbVar1 = pbVar1 + 1;
      pbVar4 = pbVar4 + 1;
      pbVar3 = pbVar3 + 1;
      pbVar2 = pbVar2 + 1;
      input = input + 1;
    } while (pbVar1 != local_88 + 0x10);
    puts("Pass valid!");
  }
  else {
    puts("usage ./crackme \"<key>\"");
  }
LAB_00101176:
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

we have **4 variables** use to make the Xor-Key : 
`local_88`, `local_68`, `local_48`, `local_28`,
these variables are allocated with **32 bytes** but
we can see the **17th byte** of this **variables** was set to **0** so when the xor was applied, we going to compare the **16 first bytes**

the **4 variables** are written `byte` by `byte`, this bytes are hardcoded so we can rebuild it :
- `local_88` = **5e 36 32 28 41 79 26 33 60 72 37 6a 7C 51 7D 3E**
- `local_68` = **36 69 75 37 28 69 55 42 70 44 24 39 4B 6C 49 43**
- `local_48` = **3A 76 54 33 3F 5B 5A 7D 63 56 27 6F 66 38 3F 43**
- `local_28` = **33 4B 70 2A 33 2B 4E 64 6A 78 5F 29 40 6B 64 4E**

> **_NOTE:_** Ghidra displays some values in decimal (99, 100) among the hex ones — these are 0x63 and 0x64. Also, 0x100 wouldn't fit in a byte, which confirms they're decimal.

so now with these **four keys** we can calculate the final key with the format check the binary execute
- ```c (byte)(*local_88 ^ *local_28 ^ *local_68 ^ *local_48 ^ 0x20) ```

so to calculate the key we can **manually xor the 4 key with 0x20** or automattically with a script like this :

```py
from pwn import xor
b88 = bytes([0x5e,0x36,0x32,0x28,0x41,0x79,0x26,0x33,0x60,0x72,0x37,0x6a,0x7C,0x51,0x7D,0x3E])
b68 = bytes([0x36,0x69,0x75,0x37,0x28,0x69,0x55,0x42,0x70,0x44,0x24,0x39,0x4B,0x6C,0x49,0x43])
b48 = bytes([0x3a,0x76,0x54,0x33,0x3F,0x5B,0x5A,0x7D,0x63,0x56,0x27,0x6F,0x66,0x38,0x3F,0x43])
b28 = bytes([0x33,0x4b,0x70,0x2a,0x33,0x2B,0x4E,0x64,0x6A,0x78,0x5F,0x29,0x40,0x6B,0x64,0x4E])
key = xor(b88, b68, b48, b28, 0x20)
print(key)
```

we use **pwntools** library (`python -m pip install pwntools`)

and the result of this script : **ABC&E@GH98K51NOP**

this binary compare this key with the user input

The conditions required to succeed:
- user input equal to the **XORed Key**

---

## 3. Dynamic Analysis (pwndbg)

we can try to see the comparator in **runtime** to validate our **key** :

```text
   0x0000555555555140 <+192>:   movzx  eax,BYTE PTR [rdx]
   0x0000555555555143 <+195>:   xor    al,BYTE PTR [rsi]
   0x0000555555555145 <+197>:   xor    al,BYTE PTR [r8]
   0x0000555555555148 <+200>:   xor    al,BYTE PTR [rdi]
   0x000055555555514a <+202>:   xor    eax,0x20
   0x000055555555514d <+205>:   cmp    BYTE PTR [rcx],al
   0x000055555555514f <+207>:   jne    0x555555555190 <main+272>
   0x0000555555555151 <+209>:   add    rdx,0x1
   0x0000555555555155 <+213>:   add    r8,0x1
   0x0000555555555159 <+217>:   add    rdi,0x1
   0x000055555555515d <+221>:   add    rsi,0x1
   0x0000555555555161 <+225>:   add    rcx,0x1
   0x0000555555555165 <+229>:   cmp    rdx,r9
   0x0000555555555168 <+232>:   jne    0x555555555140 <main+192>

```

 > **_NOTE:_** on register labels: In Ghidra's listing view, some registers are labeled argc and argv, but at this point in the loop they no longer hold argc/argv. The compiler reused them as pointers into the buffers. Ghidra keeps the original label but the =>local_XX annotation reveals the real target:

```text
XOR  AL, byte ptr [argv]=>local_28   ; "argv" actually points to local_28
XOR  AL, byte ptr [argc]=>local_48   ; "argc" actually points to local_48
```
> Ghidra's labels are an interpretation — the register names reflect their first use, not their current one.

this is the loop that compares **our key** with the **binary key** (**byte** by **byte**)

at **each loop**, it compare the **byte of the binary key** and **input key** (`main+205`)
- `$rcx` points to the **input `byte`**
- `$al` holds the **computed key `byte`** (the XOR result)

we break in the **loop** to verify the **registers and their content**

```text
pwndbg> break *main+205
Breakpoint 2 at 0x55555555514d
pwndbg> continue

pwndbg> p/c $al
$1 = 65 'A'
pwndbg> x/c $rcx
0x7fffffffda97: 65 'A'

pwndbg> continue

pwndbg> p/c $al
$3 = 66 'B'
pwndbg> x/c $rcx
0x7fffffffda98: 66 'B'

pwndbg> continue

pwndbg> p/c $al
$4 = 67 'C'
pwndbg> x/c $rcx
0x7fffffffda99: 67 'C'

```
the **key** we computed **matches** the one computed **by the binary**

---

## 4. Solution

```text
$ ./crackme "ABC&E@GH98K51NOP"
Pass valid!
```

---

## 5. Conclusion

The key is split across four buffers and recombined via XOR — a form of naive secret-sharing. 

But since all four parts are hardcoded in the binary, this provides no real protection: 

any reverser can read the four buffers and reproduce the XOR. 

A secret derived entirely from data present in the binary is not a secret.