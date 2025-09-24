#!/usr/bin/env python3
import sys

"""
Usage:
    python remove_238th_space.py input.txt output.txt
"""

if len(sys.argv) != 3:
    print("Usage: python remove_238th_space.py <input_file> <output_file>")
    sys.exit(1)

input_file  = sys.argv[1]
output_file = sys.argv[2]

with open(input_file, "r", encoding="utf-8", errors="replace") as infile, \
     open(output_file, "w", encoding="utf-8") as outfile:
    for line in infile:
        # Only modify if line has at least 238 characters
        if len(line) >= 238 and line[237] == " ":   # 237 = 238th character (0-based)
            # Remove the 238th character
            line = line[:237] + line[238:]
        outfile.write(line)

print(f"Processing complete. Output written to {output_file}")
