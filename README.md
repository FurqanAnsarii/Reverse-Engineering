# 🔍 Reverse Engineering Tool (CTF Focused)

A Python-based reverse engineering tool designed for CTF (Capture The Flag) challenges and binary analysis.

This tool automates common reverse engineering techniques such as encoded string detection, binary inspection, and execution tracing to speed up flag discovery.

---

## 🚀 Features
- Static binary analysis (ELF / PE)
- Detection of XOR, Base64, ROT, and Hex encoded strings
- Magic number and hidden logic detection
- Assembly inspection using objdump
- Dynamic analysis via ltrace and strace
- Automatic execution with extracted inputs to retrieve flags

---

## ▶️ Usage
```bash
python3 reverse_engineer.py binary_file
