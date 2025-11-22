# Regionals - Detailed Cheat Sheet

This cheat sheet is designed to accelerate solving CTF-style challenges at regionals. It focuses on practical steps, fast triage, and tried-and-true commands/tools for each problem class. Use it as a checklist and quick reference.

---

## 1) Mindset & Triage (first 5–10 minutes)
- Read every problem title and description once. Note which ones look familiar (web, crypto, pwn, forensics).
- Prioritize by:
  - Low-hanging fruit (easy web/jeopardy tasks, stego, basic crypto).
  - Known strengths on your team.
  - Point value vs. expected time.
- If stuck > 15–20 minutes on a task and no progress, pivot to another and log what you tried.
- Communication: one person documents flags and commands (shared doc), another hunts, another scripts/repeats.

---

## 2) General reconnaissance & workspace
- Collect initial artifacts: URLs, files, images, PCAPs, binaries.
- Standard directory:
  - /ctf/<challenge-name>/{notes,extracted,tools,scripts}
- Useful initial commands:
  - file target.*
  - strings -a target | head -n 200
  - binwalk target
  - exiftool image.jpg
  - identify image.png (ImageMagick)
- Always keep a copy of original files.

---

## 3) Tools cheat-list (install / quick)
- Recon & web: curl, wget, burpsuite, ffuf, dirb, gobuster
- Binary & reverse: Ghidra, IDA, radare2, ghidra-headless, objdump, readelf
- Pwn: pwntools, gdb / peda / gdb-pwndbg, ropper, ROPgadget
- Crypto: Python (pycryptodome), CyberChef (web), hashcat, john
- Forensics: strings, foremost, scalpel, binwalk, volatility, sleuthkit
- Stego: zsteg, stegsolve, steghide, exiftool, binwalk, foremost
- Misc: zip & tar utilities, openssl, socat, nc (ncat), tshark, wireshark

Quick install (Debian):
```bash
sudo apt update
sudo apt install -y python3-pip git binwalk exiftool imagemagick foremost \
  gdb gcc make upx zsteg wireshark aircrack-ng
pip3 install pwntools ropper capstone keystone-engine unicorn
```

---

## 4) Web challenges
- Quick checks:
  - curl -I -L <url>
  - check robots.txt, sitemap.xml
  - enumerate directories with ffuf/gobuster:
    ffuf -w /usr/share/wordlists/dirb/common.txt -u http://target/FUZZ -mc all
- Common issues:
  - LFI: look for include parameters and traversal (../). Try php://filter/convert.base64-encode/resource=
  - RCE via deserialization: check for suspicious cookies and serialized payloads.
  - SQLi: basic payloads ' OR '1'='1'; use sqlmap only after manual verification.
  - SSTI: try {{7*7}} or {%7*7%}, payloads that produce file read.
- Login bypasses:
  - Default creds, parameter tampering, session fixation, JWT alg=none.
- Tool: Burp for interactive testing; use Repeater and Intruder.

---

## 5) Crypto
- First steps:
  - Identify algorithm (RSA, AES, XOR, substitution, base encoding).
  - Check ciphertext structure (length, repeated blocks).
- Quick tests:
  - Is it base64? echo "..." | base64 -d
  - Repeating block detection (ECB): use AES block size 16 — repeated 16-byte blocks hint ECB.
  - Simple XOR: try single-byte XOR (use scripts or CyberChef).
- RSA tips:
  - Check small exponent (e=3) and small message or common modulus reuse.
  - Try factorization for small keys (yafu, msieve).
- Tools/commands:
  - hashcat/john for hashes.
  - Python quick XOR brute:
    ```python
    def xor_crack(ct):
      for k in range(256):
        pt = bytes([b ^ k for b in ct])
        if b'flag' in pt: print(k, pt)
    ```
- Use CyberChef for fast baking and layering operations.

---

## 6) Forensics (images, PCAPs, disk)
- Images:
  - exiftool image.jpg
  - strings image | grep -i flag
  - binwalk -e image
  - zsteg for PNG: zsteg image.png
  - stegsolve (Java) for color-plane analysis
  - look for hidden zip: binwalk/strings/foremost
- PCAP:
  - open in Wireshark, follow TCP streams
  - tshark -r file.pcap -q -z conv,tcp
  - strings / grep for "flag"
  - reconstruct files: foremost -i capture.pcap -o outdir
  - use networkminer for passive parsing
- Memory: volatility for process / strings / DLLs if memory dump provided

---

## 7) Reverse engineering & Binary exploitation
- Quick binary checks:
  - file bin
  - checksec --file=bin
  - readelf -a bin
  - strings bin | grep -i flag
- If ELF with symbols, start with Ghidra or IDA. For quick flow, use objdump -d or radare2 r2 -A.
- Buffer overflow basics:
  - Determine offset with cyclic patterns (pwntools cyclic).
  - Overwrite return address, disable stack protections (if allowed).
  - Use ret2libc vs ROP; find gadgets with ROPgadget/ropper.
- Pwntools snippet:
  ```python
  from pwn import *
  p = process('./vuln')
  p.sendline(b'A'*offset + p64(pop_rdi) + p64(bin_sh) + p64(system))
  p.interactive()
  ```
- For Windows PE: use x64dbg or Ghidra to inspect.

---

## 8) Pwn / Remote exploitation
- Test local reproducibility. Run binary under same environment (glibc version).
- Use LD_PRELOAD for library tricks, or run in docker with correct glibc.
- For remote sockets: use nc / socat; for interactive exploitation with pwntools:
  ```python
  p = remote('host', 1337)
  p.sendline(payload)
  p.recvuntil(b'> ')
  ```
- If ASLR present, look for infoleak to bypass.

---

## 9) Steganography
- Always try these in order:
  - exiftool
  - strings
  - binwalk -e
  - zsteg (PNG)
  - stegsolve (color planes)
  - steghide (try default/no pass)
  - check LSB by viewing with hex editor
- Example zip in image trick:
  - binwalk may extract appended ZIP; try unzip on extracted files.

---

## 10) Misc quick-hacks & obfuscation
- Base encodings: base16/32/64/85, uuencode
- Re-encode common: hex <-> ascii, URL decode
- Common Caesar / ROT: try rot13..rot25
- Look for repeated patterns that suggest substitution cipher; use simple frequency analysis or tools like `quipqiup`.

---

## 11) Automation & scripts
- Template: quick Python harness for bruteforce or format string
- Save reusable functions for:
  - XOR cracking
  - Base conversion pipeline
  - Automating ffuf scans
- Example ffuf command:
  ffuf -c -w /usr/share/wordlists/raft-small-directories.txt -u http://TARGET/FUZZ -t 50 -mc 200,301,302,403

---

## 12) Flag handling & writeups
- Flag formats vary. Common regex: FLAG{.*}, flag{.*}, ICS{.*}
- Once flag found:
  - Verify formatting and submit only once.
  - Log how you found it (commands, tool output).
- Writeup template:
  - Challenge name & category
  - Summary of approach
  - Tools used
  - Step-by-step commands
  - Flag and confirmation
  - Potential alternate solutions / notes

---

## 13) Quick reference commands
- File type: file file.bin
- Strings: strings -a file | less
- Binwalk extract: binwalk -e file
- Identify PNG hidden: zsteg file.png
- Extract PCAP HTTP streams: tshark -r p.pcap -Y http -T fields -e http.file_data
- GDB run with args: gdb --args ./binary arg1 arg2
- Check symbols: readelf -s binary | grep -i system

---

## 14) Teamwork & time management
- Assign: recon, exploitation, writeup
- Keep one shared notes doc with timestamps & attempts
- Use short check-ins every 10–15 minutes
- Reserve last 20–30 minutes to polish highest-value solves and submit.

---

## 15) Further resources
- CTF writeups on ctftime.org and GitHub
- pwntools docs, ROPgadget, Ghidra tutorials
- CyberChef for quick transforms
- Practical reverse engineering books and online tutorials

---

If you want, I can:
- Expand any section into runnable scripts and starters (ffuf templates, pwntools boilerplates).
- Create per-challenge starter folders in the repository with these templates.

Good luck — keep calm, triage fast, and iterate quickly.
