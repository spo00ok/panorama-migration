#!/usr/bin/env python3
"""
dedupe_lines.py

Deduplicate lines in a text file.

Defaults:
  - Keeps the FIRST occurrence of each unique line
  - Preserves original order of lines that remain
  - Writes to STDOUT unless --inplace or --output is provided
  - Normalization (for duplicate comparison) is opt-in:
      --ignore-case      -> compare case-insensitively
      --strip            -> compare after .strip() (leading/trailing whitespace ignored)

Options:
  --keep {first,last}   Choose whether to keep the first or last occurrence
  --inplace             Overwrite the input file safely (atomic replace)
  -o, --output PATH     Write to a separate file

Examples

Keep first occurrences, ignore case, write in place:

python dedupe_lines.py input.txt --ignore-case --inplace


Keep last occurrences, ignore leading/trailing spaces, write to a new file:

python dedupe_lines.py input.txt --keep last --strip -o deduped.txt


Simple STDOUT usage (pipe to a new file):

python dedupe_lines.py input.txt > deduped.txt

"""

import argparse
import os
import sys
import tempfile

def parse_args():
    p = argparse.ArgumentParser(description="Deduplicate lines in a file.")
    p.add_argument("input", help="Path to input text file")
    p.add_argument("-o", "--output", help="Output path (default: stdout unless --inplace)")
    p.add_argument("--inplace", action="store_true", help="Overwrite the input file (atomic)")
    p.add_argument("--keep", choices=["first", "last"], default="first",
                   help="Keep the first or last occurrence of a duplicate (default: first)")
    p.add_argument("--ignore-case", action="store_true",
                   help="Compare lines case-insensitively")
    p.add_argument("--strip", action="store_true",
                   help="Compare lines after stripping leading/trailing whitespace")
    return p.parse_args()

def key_of(line: str, ignore_case: bool, strip_ws: bool) -> str:
    k = line
    if strip_ws:
        k = k.strip()
    if ignore_case:
        k = k.lower()
    return k

def dedupe_keep_first(in_path: str, ignore_case: bool, strip_ws: bool):
    seen = set()
    with open(in_path, "r", encoding="utf-8", newline="") as f:
        for line in f:
            k = key_of(line, ignore_case, strip_ws)
            if k not in seen:
                seen.add(k)
                yield line  # emit original line unchanged

def dedupe_keep_last(in_path: str, ignore_case: bool, strip_ws: bool):
    """
    To keep the *last* occurrence while preserving the order of survivors,
    we record the final index for each key, then emit lines whose index equals the final index.
    """
    indices = {}
    lines = []
    with open(in_path, "r", encoding="utf-8", newline="") as f:
        for idx, line in enumerate(f):
            lines.append(line)
            k = key_of(line, ignore_case, strip_ws)
            indices[k] = idx  # last occurrence wins
    for idx, line in enumerate(lines):
        k = key_of(line, ignore_case, strip_ws)
        if indices.get(k) == idx:
            yield line

def write_atomic(out_path: str, lines_iter):
    # Write to a temp file in the same directory, then atomically replace
    dir_ = os.path.dirname(os.path.abspath(out_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".dedupe_tmp_", dir=dir_, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp:
            for line in lines_iter:
                tmp.write(line)
        os.replace(tmp_path, out_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise

def main():
    args = parse_args()

    if args.inplace and args.output:
        print("Choose either --inplace or --output, not both.", file=sys.stderr)
        sys.exit(2)

    if not os.path.isfile(args.input):
        print(f"Input not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if args.keep == "first":
        deduped = dedupe_keep_first(args.input, args.ignore_case, args.strip)
    else:
        deduped = dedupe_keep_last(args.input, args.ignore_case, args.strip)

    # Decide where to write
    if args.inplace:
        write_atomic(args.input, deduped)
    elif args.output:
        write_atomic(args.output, deduped)
    else:
        # stdout
        for line in deduped:
            sys.stdout.write(line)

if __name__ == "__main__":
    main()
