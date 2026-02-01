#!/usr/bin/env python3
import sys
import os
import shutil
import subprocess
import hashlib
import re
import struct
import base64

# --------------------------
# UI / Helpers
# --------------------------
COLORS = {
    "HEADER": "\033[95m",
    "BLUE": "\033[94m",
    "GREEN": "\033[92m",
    "WARNING": "\033[93m",
    "FAIL": "\033[91m",
    "ENDC": "\033[0m",
    "BOLD": "\033[1m"
}

def log(msg, color="ENDC"):
    print(f"{COLORS.get(color, COLORS['ENDC'])}{msg}{COLORS['ENDC']}")

def check_dependencies():
    """Check for required and optional tools, suggest installation."""
    # Required tools - script won't work well without these
    REQUIRED = {
        "file": "file",
        "strings": "binutils", 
        "objdump": "binutils",
    }
    # Recommended tools - enhance functionality
    RECOMMENDED = {
        "binwalk": "binwalk",
        "ltrace": "ltrace",
        "strace": "strace",
        "readelf": "binutils",
        "nm": "binutils",
        "upx": "upx-ucl",
    }
    # Optional tools - nice to have
    OPTIONAL = {
        "radare2": "radare2",
        "r2": "radare2",
    }
    
    missing_required = []
    missing_recommended = []
    
    for tool, pkg in REQUIRED.items():
        if not shutil.which(tool):
            missing_required.append((tool, pkg))
    
    for tool, pkg in RECOMMENDED.items():
        if not shutil.which(tool):
            missing_recommended.append((tool, pkg))
    
    if missing_required:
        log("[-] MISSING REQUIRED TOOLS:", "FAIL")
        pkgs = list(set([pkg for _, pkg in missing_required]))
        for tool, pkg in missing_required:
            log(f"    - {tool} (from {pkg})")
        log(f"\n    Install with: sudo apt install {' '.join(pkgs)}", "BLUE")
        log("\n[!] These tools are essential. Please install and re-run.", "FAIL")
        sys.exit(1)
    
    if missing_recommended:
        log("[!] MISSING RECOMMENDED TOOLS:", "WARNING")
        pkgs = list(set([pkg for _, pkg in missing_recommended]))
        for tool, pkg in missing_recommended:
            log(f"    - {tool} (from {pkg})")
        log(f"\n    Install with: sudo apt install {' '.join(pkgs)}", "BLUE")
        choice = input(f"{COLORS['WARNING']}Continue with limited functionality? (y/n): {COLORS['ENDC']}")
        if choice.lower() != 'y':
            sys.exit(1)
    else:
        log("[+] All recommended tools are installed.", "GREEN")

# --------------------------
# ReverseEngAgent Class (Advanced Static Analysis)
# Adapted from rev_eng.py
# --------------------------
class ReverseEngAgent:
    def __init__(self, filepath):
        self.filepath = filepath
        self.strings_cache = []
        self.elf_props = {}

    def _extract_strings(self, min_len=4):
        """Uses system 'strings' command for robustness, falls back to Python."""
        if self.strings_cache: return self.strings_cache
        
        # Try system strings first (FAST & ROBUST)
        if shutil.which("strings"):
            try:
                # -a: all sections, -n: minimum length, -t x: print offset (optional, we skip for now)
                res = subprocess.run(["strings", "-a", "-n", str(min_len), self.filepath], capture_output=True, text=True, errors="ignore")
                self.strings_cache = res.stdout.splitlines()
                return self.strings_cache
            except: pass
            
        # Fallback to Python Regex (SLOW but standalone)
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
            ascii_regex = re.compile(b"[ -~]{" + str(min_len).encode() + b",}")
            utf16_regex = re.compile(b"(?:[ -~]\x00){" + str(min_len).encode() + b",}")
            found_strings = []
            for match in ascii_regex.finditer(data):
                try: found_strings.append(match.group().decode("utf-8"))
                except: pass
            for match in utf16_regex.finditer(data):
                try: found_strings.append(match.group().decode("utf-16le"))
                except: pass
            self.strings_cache = sorted(list(set(found_strings)))
        except: self.strings_cache = []
        return self.strings_cache

    def compute_hashes(self):
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()
        try:
            with open(self.filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5.update(chunk)
                    sha256.update(chunk)
            return f"MD5:    {md5.hexdigest()}\n    SHA256: {sha256.hexdigest()}"
        except Exception as e:
            return f"Hash Error: {e}"

    def find_flags(self, custom_patterns=None):
        """Search for CTF flag patterns in extracted strings."""
        strings = self._extract_strings()
        # Comprehensive CTF flag formats
        defaults = [
            r"flag\{.*?\}", r"FLAG\{.*?\}",
            r"ctf\{.*?\}", r"CTF\{.*?\}",
            r"thm\{.*?\}", r"THM\{.*?\}",
            r"htb\{.*?\}", r"HTB\{.*?\}",
            r"picoctf\{.*?\}", r"picoCTF\{.*?\}",
            r"ductf\{.*?\}", r"DUCTF\{.*?\}",
            r"aei\{.*?\}", r"AEI\{.*?\}",
            r"hacker\{.*?\}", r"HACKER\{.*?\}",
            r"secret\{.*?\}", r"SECRET\{.*?\}",
            r"key\{.*?\}", r"KEY\{.*?\}",
        ]
        patterns = defaults + (custom_patterns if custom_patterns else [])
        matches = []
        for s in strings:
            for pat in patterns:
                if re.search(pat, s, re.IGNORECASE):
                    matches.append((s, "High Confidence Flag"))
        return sorted(list(set(matches)), key=lambda x: x[1])

    def decode_hex_strings(self):
        """Find hex-looking strings and decode them."""
        strings = self._extract_strings(min_len=10)
        decoded = []
        hex_pat = re.compile(r"^[0-9a-fA-F]+$")
        
        for s in strings:
            clean = s.strip()
            if len(clean) >= 10 and len(clean) % 2 == 0 and hex_pat.match(clean):
                try:
                    result = bytes.fromhex(clean).decode('utf-8', errors='ignore')
                    if result and all(32 <= ord(c) <= 126 or c in '\n\r\t' for c in result):
                        decoded.append(f"Hex '{clean[:20]}...' -> '{result}'")
                except: pass
        return decoded

    def brute_rot_flags(self):
        """Brute-force ROT1-25 on strings to find hidden flags."""
        strings = self._extract_strings(min_len=10)
        found = []
        flag_patterns = ["flag{", "ctf{", "thm{", "htb{", "picoctf{", "ductf{"]
        
        for s in strings:
            for rot in range(1, 26):
                decoded = ""
                for c in s:
                    if 'a' <= c <= 'z':
                        decoded += chr((ord(c) - ord('a') + rot) % 26 + ord('a'))
                    elif 'A' <= c <= 'Z':
                        decoded += chr((ord(c) - ord('A') + rot) % 26 + ord('A'))
                    else:
                        decoded += c
                
                for pat in flag_patterns:
                    if pat in decoded.lower():
                        found.append(f"ROT{rot}: '{s[:30]}...' -> '{decoded}'")
                        break
        return list(set(found))

    def scan_and_decode_base64(self):
        """Scan for Base64 strings and decode them."""
        strings = self._extract_strings(min_len=16)
        decoded_flags = []
        b64_pat = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        
        flag_patterns = [b"flag{", b"ctf{", b"thm{", b"htb{", b"picoctf{", b"ductf{"]
        
        for s in strings:
            for m in b64_pat.findall(s):
                try:
                    # Fix padding
                    padded = m + "=" * ((4 - len(m) % 4) % 4)
                    res = base64.b64decode(padded)
                    
                    # Check for flags
                    for pat in flag_patterns:
                        if pat in res.lower():
                            decoded_flags.append(f"B64 '{m[:20]}...' -> '{res.decode('utf-8', errors='ignore')}'")
                            break
                    else:
                        # Also report if it's readable ASCII
                        if all(32 <= b <= 126 or b in [10, 13, 9] for b in res) and len(res) > 5:
                            decoded_flags.append(f"B64 '{m[:20]}...' -> '{res.decode('utf-8', errors='ignore')}'")
                except: pass
        return decoded_flags

    def heuristic_analysis(self):
        """Scan ALL extracted strings for interesting patterns."""
        strings = self._extract_strings(min_len=6)
        artifacts = []
        
        url_pattern = re.compile(r"https?://[a-zA-Z0-9\-\.]+(?:\:[0-9]+)?(?:/[a-zA-Z0-9\-\._~:/?#[\]@!$&'()*+,;=]*)?")
        path_pattern = re.compile(r"(?:/[a-zA-Z0-9\._\-]+){2,}")
        ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
        
        suspicious = ["password", "admin", "root", "secret", "key", "auth", "token", "private", "api_key", "credential"]
        
        for s in strings:
            if url_pattern.search(s): artifacts.append((s, "URL"))
            elif email_pattern.search(s): artifacts.append((s, "Email"))
            elif ip_pattern.search(s): artifacts.append((s, "IP Address"))
            elif path_pattern.search(s):
                if not any(x in s for x in ["/lib", "/usr", "/bin", "/dev"]): artifacts.append((s, "Path"))
            else:
                for kw in suspicious:
                    if kw in s.lower():
                        artifacts.append((s, f"Keyword: {kw}"))
                        break
        return sorted(list(set(artifacts)), key=lambda x: x[1])

    def _read_elf_header(self, f):
        f.seek(0)
        magic = f.read(4)
        if magic != b'\x7fELF': return False
        self.elf_props['class'] = f.read(1)[0]
        self.elf_props['data'] = f.read(1)[0]
        f.read(1)
        self.elf_props['osabi'] = f.read(1)[0]
        endian = "<" if self.elf_props['data'] == 1 else ">"
        self.elf_props['endian_char'] = endian
        f.seek(0x10)
        self.elf_props['type'] = struct.unpack(f"{endian}H", f.read(2))[0]
        self.elf_props['machine'] = struct.unpack(f"{endian}H", f.read(2))[0]
        return True

    def analyze_pe(self):
        try:
            with open(self.filepath, "rb") as f:
                f.seek(0x3C)
                pe_offset = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_offset)
                if f.read(4) != b'PE\0\0': return "Not a PE file"
                machine = struct.unpack("<H", f.read(2))[0]
                machine_map = {0x14c: "x86", 0x8664: "x64"}
                return f"PE File. Machine: {machine_map.get(machine, hex(machine))}"
        except: return "PE Parse Error"

    def analyze_elf(self):
        try:
            with open(self.filepath, "rb") as f:
                if not self._read_elf_header(f): return "Not an ELF"
            p = self.elf_props
            return (f"ELF File. Arch: {'64-bit' if p['class']==2 else '32-bit'} {p.get('endian_char', '')}")
        except Exception as e: return f"ELF Error: {e}"

    def get_elf_symbols(self):
        """Extract symbols from ELF using nm."""
        if shutil.which("nm"):
            try:
                res = subprocess.run(["nm", "-D", self.filepath], capture_output=True, text=True, timeout=10)
                return [line for line in res.stdout.splitlines() if len(line) > 10]
            except: pass
        # Fallback to readelf
        if shutil.which("readelf"):
            try:
                res = subprocess.run(["readelf", "-s", self.filepath], capture_output=True, text=True, timeout=10)
                symbols = []
                for line in res.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 8 and parts[3] == "FUNC":
                        symbols.append(parts[-1])
                return symbols
            except: pass
        return []

    def analyze_assembly(self):
        """Runs objdump to find Stack Strings and Character Comparisons."""
        try:
            if not shutil.which("objdump"): return "Objdump not found.", []
            cmd = ["objdump", "-d", "-M", "intel", self.filepath]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = res.stdout
            
            # Method 1: Stack Strings (esi/edi pattern)
            extracted_chars = []
            mov_esi = re.compile(r"mov\s+esi,(0x[0-9a-f]+)")
            mov_edi = re.compile(r"mov\s+edi,(0x[0-9a-f]+)")
            last_esi, last_edi = None, None
            
            for line in output.splitlines():
                if "mov" in line:
                    m_esi = mov_esi.search(line)
                    if m_esi: 
                        try: last_esi = int(m_esi.group(1), 16)
                        except: pass
                    m_edi = mov_edi.search(line)
                    if m_edi:
                        try: last_edi = int(m_edi.group(1), 16)
                        except: pass
                if "call" in line:
                    if last_esi is not None and last_edi is not None:
                         if 32 <= last_esi <= 126:
                             extracted_chars.append({'key': last_edi, 'char': chr(last_esi)})
                         last_esi = None 
            
            # Method 2: Character-by-character comparison (cmp $0xNN,%al) - uses AT&T syntax
            cmp_chars = []
            # Run objdump again WITHOUT Intel syntax to get AT&T format for cmp matching
            cmd_att = ["objdump", "-d", self.filepath]
            res_att = subprocess.run(cmd_att, capture_output=True, text=True, timeout=30)
            output_att = res_att.stdout
            
            cmp_pattern = re.compile(r"cmp\s+\$0x([0-9a-f]+),%al")
            for line in output_att.splitlines():
                m = cmp_pattern.search(line)
                if m:
                    try:
                        val = int(m.group(1), 16)
                        if 32 <= val <= 126:  # Printable ASCII
                            cmp_chars.append(chr(val))
                    except: pass
            
            result_str = ""
            hidden_passwords = []
            
            if extracted_chars:
                str_exec = "".join([x['char'] for x in extracted_chars])
                result_str += f"Stack String: \"{str_exec}\""
                hidden_passwords.append(str_exec)
            
            if cmp_chars:
                char_pwd = "".join(cmp_chars)
                if result_str: result_str += " | "
                result_str += f"Char-Compare Password: \"{char_pwd}\""
                hidden_passwords.append(char_pwd)
            
            if not result_str:
                result_str = "No constructed strings found."
            
            return result_str, hidden_passwords
        except Exception as e: 
            return f"Assembly Error: {e}", []

    def brute_xor_flags(self):
        """Brute-force XOR decryption to find hidden flags."""
        if not os.path.exists(self.filepath): return []
        with open(self.filepath, "rb") as f: data = f.read(5*1024*1024)
        patterns = [b"flag{", b"CTF{", b"thm{", b"htb{", b"picoctf{", b"ductf{", b"aei{"]
        found = []
        for key in range(1, 256):
            for pat in patterns:
                enc_pat = bytes([b ^ key for b in pat])
                idx = data.find(enc_pat)
                if idx != -1:
                    start, end = max(0, idx - 10), min(len(data), idx + 60)
                    chunk = data[start:end]
                    decoded_chunk = bytes([b ^ key for b in chunk])
                    try:
                        decoded_str = decoded_chunk.decode('utf-8', errors='ignore')
                        found.append(f"XOR Key 0x{key:02x}: ...{decoded_str}...")
                    except: pass
        return list(set(found))

    def analyze_entropy(self, block_size=256):
        """Calculate entropy of file sections to detect encryption/packing."""
        import math
        try:
            with open(self.filepath, "rb") as f:
                data = f.read()
            
            def calc_entropy(chunk):
                if not chunk: return 0
                freq = {}
                for b in chunk:
                    freq[b] = freq.get(b, 0) + 1
                entropy = 0
                for count in freq.values():
                    p = count / len(chunk)
                    entropy -= p * math.log2(p)
                return entropy
            
            total_entropy = calc_entropy(data)
            high_entropy_sections = []
            
            # Check for high-entropy regions (potential encryption/compression)
            for i in range(0, len(data), block_size * 10):
                block = data[i:i + block_size * 10]
                ent = calc_entropy(block)
                if ent > 7.5:  # Very high entropy threshold
                    high_entropy_sections.append(f"Offset 0x{i:x}: Entropy {ent:.2f}")
            
            return total_entropy, high_entropy_sections
        except Exception as e:
            return 0, [f"Entropy Error: {e}"]

    def find_magic_numbers(self):
        """Find magic numbers/constants in comparisons that might unlock hidden features."""
        if not shutil.which("objdump"): return []
        
        try:
            import ctypes
            cmd = ["objdump", "-d", self.filepath]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            output = res.stdout
            
            magic_numbers = []
            # Pattern: cmp with immediate values (AT&T syntax)
            cmp_pattern = re.compile(r"cmp[lq]?\s+\$0x([0-9a-f]+),")
            
            # Known CTF magic numbers
            known_magic = [0x7a69, 0x539, 1337, 31337, 0xdeadbeef, 0xcafebabe, 0xcafef00d, 0xbadc0de, 0xfeedface]
            
            for line in output.splitlines():
                m = cmp_pattern.search(line)
                if m:
                    val = int(m.group(1), 16)
                    # Filter out common small values and focus on "interesting" ones
                    if val > 0xff and val != 0xffffffff:
                        # Compute signed 32-bit value (for atoi comparisons)
                        signed_val = ctypes.c_int32(val).value
                        
                        # Check for common CTF magic numbers
                        if val in known_magic:
                            magic_numbers.append((val, signed_val, f"KNOWN CTF magic: {val} (0x{val:x}) / signed: {signed_val}"))
                        elif 1000 < val < 100000:  # Reasonable range for hidden options
                            magic_numbers.append((val, signed_val, f"Potential magic: {val} (0x{val:x}) / signed: {signed_val}"))
            
            return list(set(magic_numbers))
        except Exception as e:
            return [(0, 0, f"Magic Number Error: {e}")]

    def analyze_sections(self):
        """Analyze ELF sections using readelf."""
        if not shutil.which("readelf"): return "readelf not installed"
        
        try:
            res = subprocess.run(["readelf", "-S", self.filepath], capture_output=True, text=True, timeout=10)
            sections = []
            suspicious = []
            
            for line in res.stdout.splitlines():
                if "[" in line and "]" in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        name = parts[1] if parts[1].startswith(".") else parts[0]
                        sections.append(name)
                        
                        # Flag suspicious sections
                        if name in [".packed", ".upx", ".aspack", ".petite"]:
                            suspicious.append(f"{name} (Packer section)")
                        elif name.startswith(".") and not name.startswith((".text", ".data", ".bss", ".rodata", ".got", ".plt", ".dynamic", ".symtab", ".strtab", ".shstrtab", ".rela", ".rel", ".note", ".eh_", ".init", ".fini", ".ctors", ".dtors", ".comment", ".interp", ".gnu")):
                            if len(name) > 2:  # Filter noise
                                suspicious.append(f"{name} (Non-standard)")
            
            return sections, suspicious
        except Exception as e:
            return [], [f"Section Error: {e}"]

    def detect_anti_debugging(self):
        """Detect common anti-debugging techniques."""
        findings = []
        strings = self._extract_strings(min_len=4)
        
        # String-based detection
        anti_debug_strings = ["ptrace", "PTRACE", "TracerPid", "/proc/self/status", "gdb", "strace", "ltrace", "IsDebuggerPresent"]
        for ad in anti_debug_strings:
            if any(ad in s for s in strings):
                findings.append(f"String reference: '{ad}'")
        
        # Objdump-based detection
        if shutil.which("objdump"):
            try:
                res = subprocess.run(["objdump", "-d", self.filepath], capture_output=True, text=True, timeout=30)
                output = res.stdout
                
                # Check for ptrace syscall
                if "ptrace" in output.lower():
                    findings.append("ptrace call detected")
                
                # Check for int3 breakpoint traps
                if re.search(r"\bint3\b", output) or re.search(r"\bcc\s*\n", output):
                    findings.append("INT3 (breakpoint) instructions found")
                    
            except: pass
        
        return findings

    def analyze_got_plt(self):
        """Analyze GOT/PLT for imported functions."""
        if not shutil.which("objdump"): return []
        
        try:
            res = subprocess.run(["objdump", "-R", self.filepath], capture_output=True, text=True, timeout=10)
            relocations = []
            interesting_imports = ["system", "execve", "popen", "dlopen", "mprotect", "ptrace", "fork", "socket", "connect"]
            
            for line in res.stdout.splitlines():
                for imp in interesting_imports:
                    if imp in line:
                        relocations.append(line.strip())
            
            return relocations
        except Exception as e:
            return [f"GOT/PLT Error: {e}"]

    def detect_packer(self):
        if not os.path.exists(self.filepath): return []
        with open(self.filepath, "rb") as f: data = f.read(4096)
        if b"UPX0" in data or b"UPX1" in data: return ["UPX"]
        return []

    def unpack_upx(self):
        if not shutil.which("upx"): return "UPX not installed."
        out_file = self.filepath + ".unpacked"
        cmd = ["upx", "-d", "-o", out_file, self.filepath]
        res = subprocess.run(cmd, capture_output=True, text=True)
        return f"Unpacked to {out_file}" if res.returncode == 0 else f"Failed: {res.stderr}"

    def auto_analyze_static(self):
        """Runs the full suite of static checks and returns a formatted string."""
        report = []
        report.append(f"[*] HASHES:\n    {self.compute_hashes()}")
        
        # Format
        with open(self.filepath, "rb") as f: head = f.read(4)
        if head.startswith(b'MZ'): report.append(f"[*] FORMAT: {self.analyze_pe()}")
        elif head.startswith(b'\x7fELF'): report.append(f"[*] FORMAT: {self.analyze_elf()}")
        
        # Packers
        packers = self.detect_packer()
        if packers:
             report.append(f"[!] PACKER DETECTED: {', '.join(packers)}")
             if "UPX" in packers: report.append(f"    Action: {self.unpack_upx()}")

        # Flags (Static)
        flags = self.find_flags()
        if flags:
            report.append("[+] FOUND FLAGS (Static):")
            for s, tag in flags: report.append(f"    - {s}")
        
        # Assembly - now returns (result_str, hidden_passwords)
        asm_passwords = []
        if head.startswith(b'\x7fELF'):
             asm_result, asm_passwords = self.analyze_assembly()
             if "No constructed" not in asm_result:
                 report.append(f"[*] ASSEMBLY ANALYSIS: {asm_result}")
             if asm_passwords:
                 report.append(f"[!!!] ASSEMBLY-EXTRACTED PASSWORDS: {asm_passwords}")
             
             # Symbols
             syms = self.get_elf_symbols()
             interesting_syms = [s for s in syms if any(x in s.lower() for x in ['main', 'flag', 'check', 'valid', 'auth', 'pass', 'secret', 'key', 'encrypt', 'decrypt'])]
             if interesting_syms:
                 report.append(f"[+] SUSPICIOUS SYMBOLS ({len(interesting_syms)}):")
                 for s in interesting_syms[:15]: report.append(f"    - {s}")
             elif syms:
                 report.append(f"[i] Symbols found ({len(syms)}), but none matched keywords.")
             else:
                 report.append("[i] No symbols found (Stripped binary?).")
                 
        # Heuristics
        heuristics = self.heuristic_analysis()
        if heuristics:
            report.append("[+] INTERESTING STRINGS:")
            for s, tag in heuristics[:15]: report.append(f"    - [{tag}] {s[:80]}")
            
        # Deobfuscation - XOR
        xor_flags = self.brute_xor_flags()
        if xor_flags:
            report.append("[+] XOR Encoded Flags Found:")
            for f in xor_flags: report.append(f"    {f}")
        
        # Deobfuscation - ROT
        rot_flags = self.brute_rot_flags()
        if rot_flags:
            report.append("[+] ROT Encoded Flags Found:")
            for f in rot_flags: report.append(f"    {f}")
        
        # Deobfuscation - Hex
        hex_decoded = self.decode_hex_strings()
        if hex_decoded:
            report.append("[+] Hex Decoded Strings:")
            for f in hex_decoded[:10]: report.append(f"    {f}")
            
        # Deobfuscation - Base64
        b64_flags = self.scan_and_decode_base64()
        if b64_flags:
             report.append("[+] Base64 Decoded Content:")
             for f in b64_flags[:10]: report.append(f"    {f}")

        # --- NEW ADVANCED ANALYSIS ---
        
        # Entropy Analysis
        total_entropy, high_ent = self.analyze_entropy()
        report.append(f"\n[*] ENTROPY ANALYSIS: Overall {total_entropy:.2f}/8.0")
        if total_entropy > 7.0:
            report.append("    [!] HIGH ENTROPY - File may be packed/encrypted")
        if high_ent:
            report.append(f"    High-entropy regions: {len(high_ent)}")
            for h in high_ent[:3]: report.append(f"      - {h}")
        
        # Magic Numbers - collect for auto-run
        magic = self.find_magic_numbers()
        magic_passwords = []
        if magic:
            report.append("[+] MAGIC NUMBERS FOUND (Hidden menu/password?):") 
            for item in magic[:10]:
                if len(item) == 3:
                    val, signed_val, desc = item
                    magic_passwords.extend([str(val), str(signed_val)])  # Try both unsigned and signed
                    report.append(f"    - {desc}")
                else:
                    report.append(f"    - {item}")
        
        # Section Analysis
        sections, suspicious_sects = self.analyze_sections()
        if suspicious_sects:
            report.append("[!] SUSPICIOUS SECTIONS:")
            for s in suspicious_sects: report.append(f"    - {s}")
        
        # Anti-Debugging Detection
        anti_dbg = self.detect_anti_debugging()
        if anti_dbg:
            report.append("[!] ANTI-DEBUGGING DETECTED:")
            for a in anti_dbg: report.append(f"    - {a}")
        
        # GOT/PLT Analysis
        got_plt = self.analyze_got_plt()
        if got_plt:
            report.append("[+] INTERESTING IMPORTS (GOT/PLT):")
            for g in got_plt[:10]: report.append(f"    - {g}")

        # Combine all extracted passwords
        all_extracted = asm_passwords + magic_passwords
        return "\n".join(report), all_extracted  # Return all passwords for dynamic analysis

# --------------------------
# Main Execution
# --------------------------
def main():
    log("\n--- Unified Reverse Engineering Tool ---\n", "HEADER")
    
    # Parse arguments
    auto_mode = "--auto" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    
    if len(args) < 1:
        log("Usage: ./reverse_engineer.py <binary_file> [--auto]", "FAIL")
        log("       --auto: Run both Static and Dynamic analysis without prompts", "BLUE")
        sys.exit(1)
        
    target = args[0]
    if not os.path.exists(target):
        log(f"[-] File '{target}' not found.", "FAIL")
        sys.exit(1)

    check_dependencies()
    log(f"\n[*] Analyzing: {target}", "BOLD")

    # Determine mode
    if auto_mode:
        log("[*] Auto Mode: Running Full Analysis...\n", "GREEN")
        do_static = True
        do_dynamic = True
    else:
        print(f"\nSelect Analysis Mode:")
        print(f"  {COLORS['BLUE']}1) Static Analysis (Deep Scan: XOR, ROT, Hex, B64, Stack Strings){COLORS['ENDC']}")
        print(f"  {COLORS['BLUE']}2) Dynamic Analysis (Safe Execution with ltrace/strace){COLORS['ENDC']}")
        print(f"  {COLORS['BLUE']}3) Both (Default){COLORS['ENDC']}")
        
        mode = input(f"Choice [3]: ").strip()
        do_static = mode in ["1", "3", ""]
        do_dynamic = mode in ["2", "3", ""]

    # --- STATIC ANALYSIS ---
    if do_static:
        log("\n--- Static Analysis ---", "HEADER")
        
        # 1. Run standard binwalk signatures first
        if shutil.which("binwalk"):
            log("\n[+] Running Binwalk (Signature Scan)...", "BLUE")
            bw_out = subprocess.run(f"binwalk '{target}'", shell=True, capture_output=True, text=True).stdout
            lines = bw_out.splitlines()
            if len(lines) > 10: print("\n".join(lines[:10]) + "\n    ... (truncated)")
            else: print(bw_out)
            
            # Check if multiple signatures found (embedded files likely)
            sig_count = len([l for l in lines if l.strip() and not l.startswith("DECIMAL") and not l.startswith("-")])
            if sig_count > 1:
                log("\n[+] Multiple signatures detected, attempting extraction...", "WARNING")
                extract_dir = f"_extracted_{os.path.basename(target)}"
                try:
                    # Run binwalk -e for extraction
                    subprocess.run(f"binwalk -e --directory '{extract_dir}' '{target}'", shell=True, capture_output=True, timeout=30)
                    
                    # Check what was extracted
                    if os.path.exists(extract_dir):
                        extracted_files = []
                        for root, dirs, files in os.walk(extract_dir):
                            for f in files:
                                extracted_files.append(os.path.join(root, f))
                        
                        if extracted_files:
                            log(f"    [+] Extracted {len(extracted_files)} file(s):", "GREEN")
                            for ef in extracted_files[:10]:
                                log(f"      - {ef}")
                                # Scan extracted files for flags
                                try:
                                    with open(ef, 'rb') as f:
                                        data = f.read(10000)
                                    # Check for flag patterns
                                    for pat in [b"flag{", b"CTF{", b"thm{", b"htb{", b"picoctf{"]:
                                        if pat in data.lower():
                                            idx = data.lower().find(pat)
                                            end = data.find(b"}", idx) + 1
                                            found_flag = data[idx:end].decode('utf-8', errors='ignore')
                                            log(f"    [!!!] FLAG FOUND in {ef}: {found_flag}", "GREEN")
                                except: pass
                        else:
                            log("    [-] No files extracted.", "WARNING")
                except Exception as e:
                    log(f"    [-] Extraction failed: {e}", "FAIL")

        # 2. Run Advanced Agent Analysis
        log("\n[+] Deep Static Scan (Agent)...", "BLUE")
        agent = ReverseEngAgent(target)
        static_report, asm_passwords = agent.auto_analyze_static()
        print(static_report)
        
        # 3. Dump Strings (Robust)
        log("\n[+] Creating Full Strings Dump...", "BLUE")
        try:
            output = subprocess.check_output(["strings", "-a", "-n", "6", target], text=True)
            dump_file = f"strings_{os.path.basename(target)}.txt"
            with open(dump_file, "w") as f: f.write(output)
            log(f"    [*] Saved to: {dump_file}", "GREEN")
        except: pass
    else:
        asm_passwords = []

    # --- DYNAMIC ANALYSIS ---
    if do_dynamic:
        log("\n--- Dynamic Analysis ---", "HEADER")
        log("\n[+] Safe Dynamic Analysis (Timeout: 5s)...", "BLUE")
        
        if shutil.which("ltrace"):
            log("    Running ltrace...", "GREEN")
            extracted_passwords = []
            try:
                cmd = f"timeout 5s ltrace -s 128 ./{target} testinput"
                proc = subprocess.run(cmd, input="password\n", shell=True, capture_output=True, text=True)
                output = proc.stderr if proc.stderr else proc.stdout
                
                interesting = []
                for line in output.splitlines():
                    if any(x in line for x in ["strcmp", "strncmp", "strcasecmp"]):
                        interesting.append(line)
                        # Extract password from strcmp("password", "input")
                        match = re.search(r'str[n]?cmp\("([^"]+)"', line)
                        if match:
                            pwd = match.group(1)
                            if pwd != "testinput" and len(pwd) > 3:
                                extracted_passwords.append(pwd)
                    elif any(x in line for x in ["open", "fopen", "getenv", "system"]):
                        interesting.append(line)
                
                if interesting:
                    log("    [!] Interesting Library Calls:", "WARNING")
                    for line in interesting[-10:]: log(f"      {line.strip()}")
                
                if extracted_passwords:
                    log(f"    [!!!] EXTRACTED PASSWORDS: {extracted_passwords}", "GREEN")
                else:
                    log("    [-] No passwords extracted from strcmp.")
            except Exception as e: log(f"    [-] ltrace failed: {e}", "FAIL")
            
            # Merge assembly-extracted passwords with ltrace-extracted ones
            all_passwords = list(set(extracted_passwords + asm_passwords))
            
            # Auto-run with extracted passwords to get the flag
            if all_passwords:
                log(f"\n    [+] Auto-running with {len(all_passwords)} password(s)...", "BLUE")
                for pwd in all_passwords[:5]:  # Try first 5
                    try:
                        cmd = f"timeout 3s ./{target} '{pwd}'"
                        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                        combined_output = proc.stdout + proc.stderr
                        
                        # Check for flag patterns in output
                        flag_patterns = ["flag{", "ctf{", "thm{", "htb{", "picoctf{", "ductf{", "password ok", "correct", "success", "win"]
                        if any(pat in combined_output.lower() for pat in flag_patterns):
                            log(f"    [!!!] SUCCESS with password '{pwd}':", "GREEN")
                            log(f"    {combined_output.strip()}", "GREEN")
                            break
                        elif "ok" in combined_output.lower() or "correct" in combined_output.lower():
                            log(f"    [+] Password '{pwd}' might be correct:", "WARNING")
                            log(f"    {combined_output.strip()}")
                    except Exception as e:
                        log(f"    [-] Auto-run failed: {e}", "FAIL")
        else: log("[-] ltrace missing.", "WARNING")

        if shutil.which("strace"):
            log("\n    Running strace (Files & Net)...", "GREEN")
            try:
                cmd = f"timeout 5s strace -e trace=open,openat,connect,socket,read,write ./{target}"
                proc = subprocess.run(cmd, input="password\n", shell=True, capture_output=True, text=True)
                lines = proc.stderr.splitlines()
                if lines:
                    log("    [Last 10 syscalls]:")
                    for l in lines[-10:]: log(f"      {l.strip()}")
            except Exception as e: log(f"    [-] strace failed: {e}", "FAIL")

    log("\n[*] Analysis Complete.", "BOLD")

if __name__ == "__main__":
    main()
