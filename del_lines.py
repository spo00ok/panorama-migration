#!/usr/bin/env python3
import sys
import shutil

"""
Usage:
    python delete_matching_lines.py <string_to_delete>
    # The script will look for config.set in the current directory,
    # remove every line containing the string (case-sensitive),
    # and save a backup as config.set.bak
"""

if len(sys.argv) != 2:
    print("Usage: python delete_matching_lines.py <string_to_delete>")
    sys.exit(1)

target = sys.argv[1]

filename = "config.set"

# Backup the original file first
shutil.copy(filename, filename + ".bak")

kept_lines = []
removed_count = 0

with open(filename, "r", encoding="utf-8", errors="replace") as infile:
    for line in infile:
        if target in line:
            removed_count += 1
            continue
        kept_lines.append(line)

with open(filename, "w", encoding="utf-8", errors="replace") as outfile:
    outfile.writelines(kept_lines)

print(f"✅ Removed {removed_count} line(s) containing '{target}' from {filename}")
print(f"✅ Backup saved as {filename}.bak")
