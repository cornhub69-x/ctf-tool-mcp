---
name: ctf-stego-plus
description: Solve CTF steganography: signature scan (binwalk), LSB/plane analysis (zsteg, channel noise), steghide info, carving (foremost), and payload decoding. Use when a carrier file likely hides a payload or flag.
---

# CTF Stego Plus

## Pipeline (follow in order):

1. **Carrier Deep Scan & Triage**: `duachuot_stego_probe` or CLI `ctftool forensics stego <path>`. Automatically parses PNG chunks, verifies IHDR CRC to detect & calculate repaired dimensions, detects trailing overlay payloads (data after IEND / EOI), extracts comments (tEXt, zTXt, JPEG COM), and calculates Shannon entropy.
2. **Signature scan**: binwalk + steghide info. Binwalk finds appended/embedded files; steghide confirms passphrase-protected payloads.
3. **LSB / plane analysis**: pure-Python audio LSB bias deviation analyzer (`_lsb_analysis`); zsteg / stegolsb for image LSB.
3. **Carve**: foremost/binwalk -e into a scratch directory (never on the original).
4. **Payload decode**: once carved, strings/xxd/file; apply common encodings (base64, zlib, XOR with hint key).
5. **Passphrase hints**: filename, metadata comments, challenge description, EXIF Software field.

## Rules

- Never brute-force passphrases on scope (OPSEC rule 4).
- If GPS or metadata coords appear, hand off to ctf-geo for verification.
- Missing tool → BLOCKER with exact missing command; never guess.
- Record evidence: carrier file, tool, offset, extracted bytes excerpt.
