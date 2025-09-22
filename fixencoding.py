#!/usr/bin/env python3
import sys
import chardet

def convert_to_utf8(infile, outfile):
    # 1️⃣ Detect source encoding
    with open(infile, 'rb') as f:
        raw = f.read()
    guess = chardet.detect(raw)
    enc = guess['encoding'] or 'latin-1'    # fallback if detection fails
    confidence = guess.get('confidence', 0)

    print(f"Detected encoding: {enc} (confidence {confidence:.2f})")

    # 2️⃣ Decode using detected encoding
    text = raw.decode(enc, errors='replace')

    # 3️⃣ Write out as UTF-8
    with open(outfile, 'w', encoding='utf-8') as f:
        f.write(text)

    print(f"✅ Converted '{infile}' -> '{outfile}' in UTF-8.")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert_to_utf8.py <input_file> <output_file>")
        sys.exit(1)

    convert_to_utf8(sys.argv[1], sys.argv[2])
