#!/usr/bin/env python3
"""
Generate a synthetic memory dump for testing the Memory Forensics Analyzer.
Contains embedded patterns that each analysis function can detect.
"""
import struct
import os

def generate_test_dump():
    """Build a synthetic .raw dump with all the forensic artifacts we want to test."""
    parts = []

    # ================================================================
    # SECTION 0: Header / Padding (raw dump, no magic header)
    # ================================================================
    parts.append(b'\x00' * 256)

    # ================================================================
    # SECTION 1: Embedded PE image (valid MZ + PE signature for PE analyzer)
    # ================================================================
    pe = bytearray(4096)
    pe[0:2] = b'MZ'                          # DOS magic
    struct.pack_into('<I', pe, 60, 128)       # e_lfanew -> offset 128
    pe[128:132] = b'PE\x00\x00'              # PE signature
    # COFF header at 132
    struct.pack_into('<H', pe, 132, 0x8664)   # Machine: AMD64
    struct.pack_into('<H', pe, 134, 2)        # NumberOfSections = 2
    struct.pack_into('<I', pe, 136, 0)        # TimeDateStamp = 0 (anomaly)
    struct.pack_into('<H', pe, 148, 112)     # SizeOfOptionalHeader (PE32+)
    struct.pack_into('<H', pe, 150, 0x0022)   # Characteristics
    # Optional header at 152
    struct.pack_into('<H', pe, 152, 0x20b)    # Magic: PE32+ (64-bit)
    struct.pack_into('<I', pe, 168, 0x1000)   # AddressOfEntryPoint
    # Sections start at 152 + 112 = 264
    # Section 1: .text (normal)
    pe[264:272] = b'.text\x00\x00\x00'
    struct.pack_into('<I', pe, 272, 0x1000)   # VirtualSize
    struct.pack_into('<I', pe, 276, 0x1000)   # VirtualAddress
    struct.pack_into('<I', pe, 280, 0x200)    # SizeOfRawData
    struct.pack_into('<I', pe, 300, 0x60000020)  # Characteristics: code+exec+read
    # Section 2: .UPX0 (suspicious packer!)
    pe[304:312] = b'.UPX0\x00\x00\x00'
    struct.pack_into('<I', pe, 312, 0x10000)  # VirtualSize (huge)
    struct.pack_into('<I', pe, 316, 0x2000)   # VirtualAddress
    struct.pack_into('<I', pe, 320, 0x100)    # SizeOfRawData (small -> ratio anomaly)
    struct.pack_into('<I', pe, 340, 0xE0000020)  # writable+executable+read+code
    # Embed some suspicious import names in the PE body
    offset = 500
    for api in [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread',
                b'NtCreateThreadEx', b'QueueUserAPC', b'SetThreadContext']:
        pe[offset:offset+len(api)] = api
        offset += len(api) + 1
    parts.append(bytes(pe))

    # ================================================================
    # SECTION 2: Process name patterns (.exe / .dll / .sys references)
    # ================================================================
    proc_section = b'\x00' * 64
    proc_section += b'svchost.exe\x00' * 3
    proc_section += b'explorer.exe\x00' * 2
    proc_section += b'lsass.exe\x00'
    proc_section += b'csrss.exe\x00'
    proc_section += b'C:\\Windows\\System32\\cmd.exe\x00'
    proc_section += b'notepad.exe\x00'
    proc_section += b'\x00' * 64
    # Suspicious process names
    proc_section += b'mimikatz.exe\x00'
    proc_section += b'beacon.exe\x00'
    proc_section += b'meterpreter\x00'
    proc_section += b'\x00' * 128
    parts.append(proc_section)

    # ================================================================
    # SECTION 3: DLL references
    # ================================================================
    dll_section = b'\x00' * 32
    dll_section += b'kernel32.dll\x00'
    dll_section += b'ntdll.dll\x00'
    dll_section += b'user32.dll\x00'
    dll_section += b'advapi32.dll\x00'
    dll_section += b'ws2_32.dll\x00'
    dll_section += b'wininet.dll\x00'
    dll_section += b'msvcrt.dll\x00'
    # Suspicious DLLs
    dll_section += b'metsrv.dll\x00'
    dll_section += b'inject.dll\x00'
    dll_section += b'beacon.dll\x00'
    dll_section += b'payload.dll\x00'
    dll_section += b'\x00' * 128
    parts.append(dll_section)

    # ================================================================
    # SECTION 4: Network artifacts (IPs, URLs, domains, emails)
    # ================================================================
    net_section = b'\x00' * 32
    # IPv4 addresses
    net_section += b'192.168.1.100\x00'
    net_section += b'10.0.0.1\x00'
    net_section += b'8.8.8.8\x00'
    net_section += b'185.220.101.42\x00'
    net_section += b'172.16.0.5\x00'
    # URLs
    net_section += b'https://evil-c2.example.com/beacon\x00'
    net_section += b'https://update.microsoft.com/check\x00'
    net_section += b'http://malware-host.xyz/payload.bin\x00'
    # Domains
    net_section += b'malicious-domain.xyz\x00'
    net_section += b'legit-site.com\x00'
    net_section += b'data-exfil.onion\x00'
    # Emails
    net_section += b'admin@target-corp.com\x00'
    net_section += b'hacker@evil.org\x00'
    # MAC address
    net_section += b'AA:BB:CC:DD:EE:FF\x00'
    net_section += b'\x00' * 128
    parts.append(net_section)

    # ================================================================
    # SECTION 5: Registry key patterns
    # ================================================================
    reg_section = b'\x00' * 32
    reg_section += b'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Backdoor\x00'
    reg_section += b'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Office\\Word\x00'
    reg_section += b'HKLM\\SYSTEM\\CurrentControlSet\\Services\\MalService\x00'
    reg_section += b'HKCU\\Software\\Classes\\exefile\\shell\\open\x00'
    reg_section += b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Updater\x00'
    reg_section += b'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell\x00'
    reg_section += b'\x00' * 128
    parts.append(reg_section)

    # ================================================================
    # SECTION 6: File path patterns (C:\path\file.ext)
    # ================================================================
    path_section = b'\x00' * 32
    path_section += b'C:\\Windows\\System32\\drivers\\etc\\hosts\x00'
    path_section += b'C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe\x00'
    path_section += b'C:\\Windows\\Temp\\malware.dll\x00'
    path_section += b'C:\\Program Files\\Legitimate\\app.exe\x00'
    path_section += b'D:\\Data\\documents\\secret.docx\x00'
    path_section += b'\x00' * 128
    parts.append(path_section)

    # ================================================================
    # SECTION 7: Malware signature patterns (for YARA + signature detection)
    # ================================================================
    mal_section = b'\x00' * 32

    # Mimikatz signatures (triggers Credential_Dumper + Mimikatz YARA)
    mal_section += b'mimikatz tool\x00'
    mal_section += b'gentilkiwi author\x00'
    mal_section += b'sekurlsa module\x00'
    mal_section += b'kerberos:: command\x00'
    mal_section += b'lsadump:: command\x00'
    mal_section += b'privilege::debug\x00'
    mal_section += b'logonPasswords dump\x00'
    mal_section += b'wdigest provider\x00'
    mal_section += b'lsass.exe process\x00'
    mal_section += b'SAM database\x00'
    mal_section += b'SECURITY hive\x00'
    mal_section += b'NTDS database\x00'

    # Metasploit patterns
    mal_section += b'metsrv server\x00'
    mal_section += b'ext_server_stdapi module\x00'
    mal_section += b'ext_server_priv module\x00'
    mal_section += b'ReflectiveLoader function\x00'
    mal_section += b'stdapi_ prefix\x00'

    # Cobalt Strike patterns
    mal_section += b'beacon.dll library\x00'
    mal_section += b'beacon.x64.dll library\x00'

    # PowerShell Empire
    mal_section += b'Invoke-Empire staging\x00'
    mal_section += b'empire_staging data\x00'
    mal_section += b'Get-Keystrokes logger\x00'

    # Ransomware indicators
    mal_section += b'YOUR FILES HAVE BEEN ENCRYPTED\x00'
    mal_section += b'Bitcoin payment address\x00'
    mal_section += b'.onion hidden service\x00'
    mal_section += b'decrypt your files\x00'
    mal_section += b'ransom payment\x00'
    mal_section += b'AES encryption\x00'
    mal_section += b'RSA public key\x00'

    # RAT indicators
    mal_section += b'webcam capture\x00'
    mal_section += b'keylog data\x00'
    mal_section += b'screenshot taken\x00'
    mal_section += b'download file\x00'
    mal_section += b'upload data\x00'
    mal_section += b'shell command\x00'
    mal_section += b'execute payload\x00'

    # Persistence indicators
    mal_section += b'CurrentVersion\\Run\x00'
    mal_section += b'RunOnce\x00'
    mal_section += b'Winlogon\\Shell\x00'
    mal_section += b'schtasks /create\x00'

    mal_section += b'\x00' * 256
    parts.append(mal_section)

    # ================================================================
    # SECTION 8: Shellcode / opcode patterns
    # ================================================================
    shell_section = b'\x00' * 32
    # NOP sled
    shell_section += b'\x90' * 16
    # XOR patterns
    shell_section += b'\x31\xc0'   # xor eax, eax
    shell_section += b'\x31\xdb'   # xor ebx, ebx
    shell_section += b'\x31\xc9'   # xor ecx, ecx
    shell_section += b'\x31\xd2'   # xor edx, edx
    # GetPC pattern
    shell_section += b'\xe8\x00\x00\x00\x00'
    # INT3 breakpoints
    shell_section += b'\xcc' * 8
    # Indirect call/jump patterns
    shell_section += b'\xff\x15\x00\x00\x00\x00'  # call [indirect]
    shell_section += b'\xff\xd0'   # call eax
    shell_section += b'\xff\xe0'   # jmp eax
    shell_section += b'\xff\xe4'   # jmp esp
    shell_section += b'\x00' * 128
    parts.append(shell_section)

    # ================================================================
    # SECTION 9: Behavioral analysis triggers
    # ================================================================
    behav_section = b'\x00' * 32

    # Process injection APIs (need >= 2 to trigger)
    behav_section += b'VirtualAllocEx function\x00'
    behav_section += b'WriteProcessMemory call\x00'
    behav_section += b'CreateRemoteThread inject\x00'
    behav_section += b'NtCreateThreadEx kernel\x00'

    # Credential access
    # (mimikatz, gentilkiwi, sekurlsa, lsass, SAM, SECURITY already in section 7)

    # Persistence mechanisms
    behav_section += b'CurrentVersion\\Run registry\x00'
    behav_section += b'RunOnce auto-start\x00'
    behav_section += b'schtasks scheduling\x00'

    # Lateral movement
    behav_section += b'PsExec remote execution\x00'
    behav_section += b'WinRM connection\x00'
    behav_section += b'WMI query\x00'

    # Data exfiltration
    behav_section += b'curl -X POST data\x00'
    behav_section += b'certutil -encode\x00'
    behav_section += b'bitsadmin transfer\x00'

    # Defense evasion
    behav_section += b'-EncodedCommand base64\x00'
    behav_section += b'FromBase64String decode\x00'
    behav_section += b'AmsiScanBuffer bypass\x00'

    # C2 indicators
    behav_section += b'tor2web proxy\x00'
    behav_section += b'ngrok tunnel\x00'
    behav_section += b'pastebin.com\x00'

    # Crypto mining
    behav_section += b'stratum+tcp://pool.mining\x00'
    behav_section += b'xmrig miner\x00'
    behav_section += b'monero wallet\x00'

    # Common Windows APIs (informational)
    behav_section += b'GetProcAddress resolve\x00'
    behav_section += b'LoadLibrary module\x00'
    behav_section += b'CreateFile handle\x00'
    behav_section += b'RegOpenKey registry\x00'

    # Network APIs
    behav_section += b'socket connection\x00'
    behav_section += b'connect server\x00'
    behav_section += b'send data\x00'
    behav_section += b'recv buffer\x00'

    behav_section += b'\x00' * 256
    parts.append(behav_section)

    # ================================================================
    # SECTION 10: Packer signatures
    # ================================================================
    packer_section = b'\x00' * 32
    packer_section += b'UPX! compressed\x00'
    packer_section += b'ASPack packed\x00'
    packer_section += b'Themida protected\x00'
    packer_section += b'\x00' * 128
    parts.append(packer_section)

    # ================================================================
    # SECTION 11: Base64 encoded content (for ObfuscationDetector)
    # ================================================================
    b64_section = b'\x00' * 32
    # A long enough base64 string (>40 chars)
    b64_section += b'SSBhbSBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVk\x00'
    b64_section += b'\x00' * 128
    parts.append(b64_section)

    # ================================================================
    # SECTION 12: Unicode strings (for Unicode string extraction)
    # ================================================================
    uni_section = b'\x00' * 32
    # UTF-16-LE encoded strings
    uni_section += 'kernel32.dll'.encode('utf-16-le') + b'\x00\x00'
    uni_section += 'C:\\Windows\\System32\\ntdll.dll'.encode('utf-16-le') + b'\x00\x00'
    uni_section += 'explorer.exe'.encode('utf-16-le') + b'\x00\x00'
    uni_section += b'\x00' * 128
    parts.append(uni_section)

    # ================================================================
    # SECTION 13: _EPROCESS marker
    # ================================================================
    eproc_section = b'\x00' * 64
    eproc_section += b'_EPROCESS'
    eproc_section += b'\x00' * 20
    eproc_section += b'svchost.exe'
    eproc_section += b'\x00' * 64
    parts.append(eproc_section)

    # ================================================================
    # SECTION 14: Legitimate software indicators (for ML false-positive reduction)
    # ================================================================
    legit_section = b'\x00' * 32
    legit_section += b'Microsoft Corporation\x00'
    legit_section += b'Copyright (c) 2024\x00'
    legit_section += b'\x00' * 128
    parts.append(legit_section)

    # ================================================================
    # SECTION 15: Padding to reach ~100KB
    # ================================================================
    current_size = sum(len(p) for p in parts)
    target_size = 103000
    if current_size < target_size:
        # Fill with semi-random data to get decent entropy
        import random
        random.seed(42)  # reproducible
        padding_size = target_size - current_size
        padding = bytes(random.randint(0, 255) for _ in range(padding_size))
        parts.append(padding)

    # Assemble and write
    dump = b''.join(parts)
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_forensic_dump.raw')
    with open(output, 'wb') as f:
        f.write(dump)

    print(f"Generated test dump: {output}")
    print(f"Size: {len(dump):,} bytes ({len(dump)/1024:.1f} KB)")
    return output

if __name__ == '__main__':
    generate_test_dump()
