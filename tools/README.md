# Tools

Reusable tooling I build while working through reverse engineering challenges.
Unlike the per-challenge solve scripts under [`../crackmes/`](../crackmes/),
these are generic and meant to be used across binaries.

## strings_filter.py

Cuts the noise from a `strings` dump — especially on statically-linked binaries —
to surface the messages and codes that actually belong to the program. Static
linking embeds the whole libc, so a raw `strings` dump is flooded with library
noise (symbols, linker internals, strerror tables, mangled code fragments) that
buries the handful of program-specific strings.

It filters on three criteria: known libc/linker noise, the `strerror` error-message
table, and lines that look like mis-decoded code fragments. Output is
deduplicated and sorted.

> Not an oracle: it reduces how much you have to read, the final spotting is still
> human. The `NOISE` list is meant to grow as you meet new binaries — that list is
> the actual asset.

**Usage**

    python3 strings_filter.py <binary>              # run strings, then filter
    python3 strings_filter.py <binary> -v           # also report how much noise was dropped
    python3 strings_filter.py dump.txt --from-dump  # filter an already-saved dump
    python3 strings_filter.py <binary> --min-len 6  # min length passed to strings

**Example** — surfacing the meaningful strings of a static binary during recon:

    $ strings CodeLinux | wc -l              # raw: thousands of lines
    $ python3 strings_filter.py CodeLinux
    *****This is Code Linux Agent!*****
    - Enter The Code :
    Alert! I hate debugging stuff
    You Are Not Code Linux Member!
    You are a Code Linux Memeber!!

Requires `binutils` (for `strings`).
