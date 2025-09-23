#!/usr/bin/env python3
import sys

"""
Usage:
    python deduplicate_lines_with_count.py input.txt output.txt
"""

if len(sys.argv) != 3:
    print("Usage: python deduplicate_lines_with_count.py <input_file> <output_file>")
    sys.exit(1)

input_file  = sys.argv[1]
output_file = sys.argv[2]

seen = set()
duplicate_count = 0

with open(input_file, "r", encoding="utf-8", errors="replace") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:
    for line in infile:
        if line not in seen:          # first occurrence
            outfile.write(line)
            seen.add(line)
        else:                         # duplicate found
            duplicate_count += 1

print(f"Deduplication complete. Output written to {output_file}")
print(f"Duplicate lines removed: {duplicate_count}")
