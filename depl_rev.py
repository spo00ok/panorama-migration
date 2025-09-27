#!/usr/bin/env python3
import sys

"""
Usage:
    python remove_duplicate_lines.py panorama.set second_config.set
    # The first file is modified in place; a .bak backup is created.
"""

if len(sys.argv) != 3:
    print("Usage: python remove_duplicate_lines.py <panorama.set> <second_config.set>")
    sys.exit(1)

file1 = sys.argv[1]    # panorama.set (will be modified)
file2 = sys.argv[2]    # second panorama configuration

# Read all lines from the second config into a set for fast lookup
with open(file2, "r", encoding="utf-8", errors="replace") as f2:
    second_lines = set(line.rstrip("\n") for line in f2)

# Backup the original first file
import shutil
shutil.copy(file1, file1 + ".bak")

removed_count = 0
kept_lines = []

with open(file1, "r", encoding="utf-8", errors="replace") as f1:
    for line in f1:
        if line.rstrip("\n") in second_lines:
            removed_count += 1
            continue
        kept_lines.append(line)

with open(file1, "w", encoding="utf-8", errors="replace") as out:
    out.writelines(kept_lines)

print(f"✅ Done. {removed_count} matching lines were removed from {file1}.")
print(f"✅ Original file saved as {file1}.bak")
