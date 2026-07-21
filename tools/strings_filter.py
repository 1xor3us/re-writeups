#!/usr/bin/env python3
"""
strings_filter.py - cuts the noise from a `strings` dump (especially static
binaries) to surface the messages / codes that actually belong to the program.

Usage:
    python3 strings_filter.py <binary>               # run strings, then filter
    python3 strings_filter.py <binary> -v            # + report how much noise was dropped
    python3 strings_filter.py dump.txt --from-dump   # filter an already-saved dump
    python3 strings_filter.py <binary> --min-len 6   # min length passed to strings

Not an oracle: it reduces how much you have to read, the final spotting stays
human. Grow the NOISE list as you meet new binaries - that list is the asset.
"""
import subprocess, shutil, os, sys, signal, argparse, re

# Cleanly ignore SIGPIPE (for `| head`, `| less`, ...)
signal.signal(signal.SIGPIPE, signal.SIG_DFL)

# --- Known noise (symbols / libc internals / linker). GROW THIS over time. ---
NOISE = re.compile('|'.join([
    r'__', r'GLIBC', r'glibc', r'/usr', r'/lib', r'\.so', r'sysdep',
    r'mchunkptr', r'malloc_chunk', r'heap_info', r'main_arena', r'ar_ptr',
    r'sizeof', r'builtin', r'offsetof', r'alignof', r'size_t', r'pthread',
    r'reloc', r'Verdef', r'Verneed', r'_dl_', r'\bTLS\b', r'\bELF\b',
    r'zone_names', r'tzname', r'paligned', r'pagesz', r'l_idx', r'l_name',
    r'asm ', r'volatile', r'prev_size', r'decimalwc', r'nloaded',
    r'phdr|phnum|phentsize|aspace|mprotect',
    # leaking libc message fragments (unanchored, so .search catches them)
    r'cannot (open|map|stat|create|load|allocate|enable|find|read)',
    r'PLTREL', r'shared object', r'dynamic string', r'no version',
    r'search (path|cache)', r'trying file', r'link time reference',
    r'writable segment', r'not defined in file', r'profile data',
]), re.IGNORECASE)

# System errors (strerror table) - almost always noise in a crackme
STRERROR = re.compile('|'.join([
    r'^Success$', r'^Bad ', r'^Wrong ', r'^No such', r'^Not a', r'^Too many',
    r'^Invalid', r'^Cannot', r'^cannot', r'^Device', r'^Operation', r'^Resource',
    r'^Permission', r'^Address', r'^Connection', r'^Protocol', r'^Interrupted',
    r'^Read-only', r'^Broken', r'^Illegal', r'^Argument', r'^Numerical',
    r'^No route', r'^Host ', r'^Network', r'^Is a', r'^Directory',
]))


def get_strings(binary, min_len=4, scan_all=True):
    """Run `strings` on the binary and return the list of lines."""
    if shutil.which('strings') is None:
        sys.exit("Error: 'strings' not found. Install binutils "
                 "(dnf install binutils / apt install binutils).")
    if not os.path.isfile(binary):
        sys.exit(f"Error: file not found: {binary}")
    cmd = ['strings', '-n', str(min_len)]
    if scan_all:
        cmd.append('-a')          # -a: scan the whole file, not just the data sections
    cmd.append(binary)
    result = subprocess.run(cmd, capture_output=True, text=True, errors='replace')
    if result.returncode != 0:
        sys.exit(f"strings error: {result.stderr.strip()}")
    return result.stdout.splitlines()


def read_dump(path):
    """Read an already-generated `strings` dump (text file)."""
    if not os.path.isfile(path):
        sys.exit(f"Error: file not found: {path}")
    with open(path, errors='replace') as f:
        return f.read().splitlines()


def looks_like_code_fragment(s):
    """Code fragments mis-decoded by strings: many symbols, little meaning."""
    weird = sum(1 for c in s if c in '$\\{}|<>^`')
    return weird >= 2 and len(s) < 25


def is_noise(s):
    return bool(NOISE.search(s) or STRERROR.match(s) or looks_like_code_fragment(s))


def main():
    ap = argparse.ArgumentParser(description="Filter the noise out of a strings dump.")
    ap.add_argument('target', help='binary to analyze (or text dump with --from-dump)')
    ap.add_argument('--from-dump', action='store_true',
                    help='treat the target as an already-made strings dump')
    ap.add_argument('-v', '--verbose', action='store_true',
                    help='report how many lines were dropped as noise')
    ap.add_argument('--min-len', type=int, default=4,
                    help='minimum length (passed to strings, default 4)')
    args = ap.parse_args()

    if args.from_dump:
        lines = read_dump(args.target)
    else:
        lines = get_strings(args.target, min_len=args.min_len)

    kept, dropped = [], []
    for line in lines:
        s = line.rstrip('\n')
        if len(s.strip()) < args.min_len:
            continue
        (dropped if is_noise(s) else kept).append(s)

    for s in sorted(set(kept)):
        print(s)
    if args.verbose:
        print(f"\n--- {len(kept)} kept / {len(dropped)} dropped as noise ---",
              file=sys.stderr)


if __name__ == '__main__':
    main()
