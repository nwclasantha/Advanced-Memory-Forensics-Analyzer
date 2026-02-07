# Advanced Memory Forensics Analyzer v3.0

A professional-grade, enterprise-level memory forensics GUI tool built with Python and tkinter. Features a 4-layer hybrid ML detection pipeline with external YARA rule integration targeting 99.6% precision, real-time system monitoring, MITRE ATT&CK mapping, and enterprise HTML report generation.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-267%20Passing-brightgreen)
![YARA Rules](https://img.shields.io/badge/YARA%20Rules-1881-orange)
![Bugs Fixed](https://img.shields.io/badge/Bugs%20Fixed-20-red)

---

## Table of Contents

- [Features](#features)
- [What's New in v3.0](#whats-new-in-v30)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Analysis Capabilities](#analysis-capabilities)
- [ML Detection Pipeline](#ml-detection-pipeline)
- [Real-Time Monitoring](#real-time-monitoring)
- [External YARA Rules](#external-yara-rules)
- [Report Generation](#report-generation)
- [GUI Reference](#gui-reference)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Requirements](#requirements)

---

## Features

### Core Forensics
- Load and analyze memory dumps (`.raw`, `.dmp`, `.mem`, `.vmem`)
- Process detection via 4 independent methods (PE headers, EPROCESS structures, file references, known tool names)
- DLL extraction and suspicious module identification
- Network artifact extraction (IPv4, IPv6, URLs, domains, emails, MAC addresses)
- Registry key analysis with persistence indicator detection
- String extraction (ASCII + Unicode) with search/filter
- Shannon entropy analysis for detecting encrypted/packed regions
- Hex viewer with navigation
- Simplified x86/x64 disassembly
- Event timeline construction with proper RFC 1918 private IP classification

### Hybrid ML + YARA Detection (v3.0)
- 4-layer hybrid ML ensemble detection pipeline targeting 99.6% precision
- 100 external YARA rule files with 1,881 rules and 10,000+ text patterns
- 9 built-in YARA-like malware family rules (Mimikatz, Meterpreter, Cobalt Strike, Empire, etc.)
- PE structure anomaly analysis
- N-gram byte sequence frequency analysis
- Obfuscation/packer detection (UPX, VMProtect, Themida, ASPack, etc.)
- Quality-weighted YARA scoring to eliminate false positives on common process names
- Cross-validation with 5 independent checks to minimize false positives

### Behavioral Analysis
- 8 threat categories mapped to MITRE ATT&CK framework
- Process Injection (T1055), Credential Access (T1003), Persistence (T1547)
- Lateral Movement (T1021), Data Exfiltration (T1041), Defense Evasion (T1027)
- Command & Control (T1071), Crypto Mining (T1496)
- Command-line analysis for encoded commands, obfuscation, and remote downloads

### Real-Time Monitoring (Enhanced in v3.0)
- Live process monitoring with 4-layer hybrid ML + YARA threat scoring
- 2-phase detection: fast triage for all processes, deep analysis for top 5 candidates
- External YARA rule matching against process names and command lines
- Network connection tracking with suspicious activity detection
- Configurable refresh intervals (1-10 seconds)
- Color-coded threat alerts (CRITICAL / WARNING / INFO) with YARA rule tags
- YARA engine status indicator showing loaded rules and pattern count
- Alert export to JSON/TXT

### Reporting
- Interactive text-based forensic reports
- JSON export for programmatic analysis
- CSV export for network artifacts
- Enterprise-grade HTML reports with animated visualizations, MITRE mapping, and print-optimized styling

### Memory Dump Creation
- Create process memory dumps from running processes (requires Administrator)
- Windows API integration via `MiniDumpWriteDump`
- Fallback to `procdump.exe` if available
- Process selection dialog with memory/CPU metrics

---

## What's New in v3.0

### Hybrid ML + External YARA Integration
- **ExternalYARALoader** class parses 100 `.yar` files from the `yara_rules/` directory
- Extracts ASCII text string patterns with proper escape handling (`\\`, `\"`)
- Builds inverted keyword index for O(1) candidate rule lookup
- Evaluates simplified YARA conditions: `any of them`, `N of them`, prefix wildcards, compound `and`/`or`/`not`
- Quality-weighted scoring reduces false positives from single-pattern matches

### Enhanced Real-Time Monitor
- **4-layer hybrid ML pipeline** replaces simple name-based heuristics:
  - Layer 1 (35%): Fast name-based heuristic scoring
  - Layer 2 (30%): External YARA text pattern matching
  - Layer 3 (25%): Behavioral command-line analysis via WMIC
  - Layer 4 (10%): Cross-validation ensemble with corroboration boost/dampening
- **2-phase monitoring loop**: Quick triage for all new processes, then full 4-layer deep analysis for max 5 candidates per cycle
- Previously unused `_analyze_process_behavior()` method now wired into the detection pipeline
- YARA match info displayed in alerts: `[YARA: RuleName1, RuleName2]`

### 20 Bug Fixes Across 7 Sessions
- Fixed false positive YARA matches on common process names (lsass.exe, SearchIndexer.exe, System, cmd.exe)
- Fixed YARA pattern extraction: escaped quotes, double-backslash paths, brace-containing text strings
- Fixed 172.x private IP range to cover full RFC 1918 range (172.16-31.x.x)
- Fixed lambda closure race conditions in monitor thread
- Fixed GUI widget sync issues across load/update/clear operations
- Fixed shared treeview tab cross-contamination
- See MEMORY.md for the complete bug list

### 267 Tests (up from 198)
- 37 test classes covering all functionality
- Tests for YARA false positive reduction, edge cases, condition evaluation, thread safety
- Tests for private IP range, backslash unescaping, brace pattern extraction
- Full regression test coverage for all 20 bug fixes

---

## Architecture

```
+------------------------------------------------------------------+
|                    MemoryForensicsGUI                            |
|  (15-tab tkinter interface, 5000+ lines)                         |
|                                                                  |
|  Overview | Processes | Network | Malware | Dashboard | DLLs     |
|  Strings | Behavioral | Registry | Entropy | Hex | Timeline      |
|  Code Analysis | Report | Real-Time                              |
+------------------------------------------------------------------+
         |                    |                        |
         v                    v                        v
+------------------+  +----------------+  +------------------------+
| MemoryForensics  |  | Report         |  | Real-Time Monitor      |
| Engine           |  | Generator      |  | (Background Thread)    |
| (1200+ lines)    |  | (1159 lines)   |  |                        |
|                  |  |                |  | 4-Layer Hybrid ML      |
| - Process scan   |  | - HTML output  |  | + External YARA Rules  |
| - Network extract|  | - 13 sections  |  | + Behavioral Analysis  |
| - Malware detect |  | - Dark theme   |  | Thread-safe UI updates |
| - DLL analysis   |  | - Animations   |  +------------------------+
| - String extract |  | - Print CSS    |
| - Entropy calc   |  +----------------+
| - Registry scan  |
| - Behavioral     |
| - Private IP chk |
+------------------+
         |
         v
+------------------------------------------------------------------+
|                   ML Detection Pipeline                          |
|                                                                  |
|  AdvancedMLDetector (Dump Scan Ensemble Orchestrator)            |
|  |                                                               |
|  +-- AdvancedPEAnalyzer -----> PE headers, sections, imports     |
|  |   (25% weight)                                                |
|  |                                                               |
|  +-- YARALikeEngine ---------> 9 built-in malware family rules   |
|  |   (35% weight)              multi-condition matching          |
|  |                                                               |
|  +-- NGramAnalyzer ----------> byte sequence frequency           |
|  |   (15% weight)              malicious pattern detection       |
|  |                                                               |
|  +-- ObfuscationDetector ----> entropy, XOR, Base64, packers     |
|      (15% weight)                                                |
|                                                                  |
|  ExternalYARALoader (Real-Time Monitor YARA Engine)              |
|  |                                                               |
|  +-- 100 .yar files ---------> 1,881 parsed rules                |
|  +-- Inverted pattern index -> O(1) candidate lookup             |
|  +-- Condition evaluator ----> any/all/N of, compound and/or     |
|  +-- Quality-weighted scoring  (single-match reduction: 0.25x)   |
|                                                                  |
|  MLMalwareDetector (Feature-Based Scoring)                       |
|  |                                                               |
|  +-- entropy_anomaly (15%) --+                                   |
|  +-- api_pattern_score (25%) |                                   |
|  +-- string_ioc_score (20%)  +-> Ensemble Score -> Validation    |
|  +-- byte_distribution (10%) |   (threshold: 45)  (5 checks)     |
|  +-- structural_anomaly (15%)|                                   |
|  +-- behavioral_corr (15%) --+                                   |
+------------------------------------------------------------------+
```

---

## Installation

### Prerequisites
- Python 3.8 or higher
- Windows OS (required for real-time monitoring and memory dump creation)
- tkinter (included with standard Python installation)

### Setup

```bash
# Clone or download the project
cd "Advanced Memory Forensics Analyzer"

# No external dependencies required - uses only Python standard library

# Run the application
python memory_forensics_tool.py
```

### Running with Administrator Privileges

Memory dump creation requires Administrator privileges. Use the included batch file:

```bash
# Right-click and select "Run as administrator"
RUN_AS_ADMIN.bat
```

Or run from an elevated command prompt:

```bash
python memory_forensics_tool.py
```

> **Note:** Loading and analyzing existing dump files does NOT require admin privileges. Only live memory dump creation requires elevation.

---

## Usage

### Quick Start

1. **Launch** the application: `python memory_forensics_tool.py`
2. **Load** a memory dump: Click **"Open Dump"** in the top bar and select a `.raw`, `.dmp`, or `.mem` file
3. **Analyze**: Click **"Full Analysis"** to run all detection engines automatically
4. **Review**: Navigate the 15 tabs to explore findings
5. **Export**: Generate HTML, JSON, or CSV reports from the Report tab

### Loading a Memory Dump

The tool supports multiple dump formats:
- **Windows Minidump** (`.dmp`) - Created by Task Manager or procdump
- **Raw Memory Dump** (`.raw`, `.mem`) - Full physical memory captures
- **VMware Snapshot** (`.vmem`) - Virtual machine memory
- **ELF Core Dump** - Linux process dumps
- **PE Executable** - Process-specific dumps

### Creating a Memory Dump

1. Run the application as Administrator
2. Click **"Create Dump"** in the top bar
3. Select a target process from the list
4. Choose a save location
5. The dump is created using Windows `MiniDumpWriteDump` API

---

## Analysis Capabilities

| Capability | Method | Output |
|---|---|---|
| **Process Detection** | PE header scan, EPROCESS structures, file refs, known tools | Process list with suspicion flags |
| **Malware Signatures** | YARA-like multi-pattern rules for 9 families | Detection name, confidence, severity |
| **ML Detection** | Ensemble scoring across 6 features | Risk score, confidence %, detections |
| **Enterprise Scan** | All layers combined with cross-validation | Threat score, risk level, precision |
| **External YARA** | 1,881 rules from 100 .yar files with quality weighting | Rule matches, severity, category |
| **Network Artifacts** | Regex extraction for 6 artifact types | IPs, URLs, domains, emails, MACs |
| **DLL Analysis** | ASCII + Unicode name extraction | Module list with suspicion flags |
| **Behavioral** | 8 threat categories with API pattern matching | Score, MITRE ATT&CK mapping |
| **Registry** | Pattern matching for 7 key types | Keys with persistence risk indicators |
| **Entropy** | Block-by-block Shannon entropy | Entropy map, encrypted region flags |
| **Strings** | ASCII + Unicode extraction, min-length filter | Offset, type, length, value |
| **Hex Viewer** | Direct byte viewing at any offset | Hex + ASCII dump |
| **Disassembly** | Basic x86/x64 opcode decoding | Instruction listing |
| **Timeline** | Aggregation of all findings | Chronological event list |
| **Code Patterns** | Shellcode signatures + API pattern analysis | Risk score, pattern matches |

---

## ML Detection Pipeline

The detection pipeline uses a multi-layer ensemble approach designed for high precision (99.6% target) to minimize false positives in production environments.

### Dump Analysis Layers

**Layer 1 - AdvancedPEAnalyzer (25% weight)**
- PE header validation and anomaly detection
- Section analysis (writable+executable, unusual names, entropy)
- Packer identification (UPX, VMProtect, Themida, ASPack, etc.)
- Import table analysis across 7 suspicious categories

**Layer 2 - YARALikeEngine (35% weight - highest)**
- 9 built-in malware family detection rules
- Multi-condition matching (requires minimum pattern count)
- Families: Mimikatz, Meterpreter, Cobalt Strike, PowerShell Empire, Process Injection, Credential Dumpers, Ransomware, RATs, Shellcode

**Layer 3 - NGramAnalyzer (15% weight)**
- Trigram frequency analysis of byte sequences
- Detection of indirect calls, stack manipulation, self-modifying code
- Normalized risk scoring

**Layer 4 - ObfuscationDetector (15% weight)**
- Shannon entropy calculation
- XOR encoding pattern detection
- Base64 content identification
- Packer signature matching

### Real-Time Monitor Layers (v3.0)

**Layer 1 - Name Heuristics (35% weight)**
- 60+ known malware tools (Mimikatz, Meterpreter, 30+ RATs)
- Suspicious name patterns (keylogger, trojan, backdoor)
- LOLBins analysis (PowerShell, certutil, mshta, etc.)
- Behavioral indicators (obfuscated names, double extensions, system mimics)

**Layer 2 - External YARA (30% weight)**
- 1,881 rules from 100 `.yar` files
- Quality-weighted scoring (single match from multi-pattern rule: 0.25x)
- Display threshold (score >= 20) to prevent false positives

**Layer 3 - Behavioral Analysis (25% weight)**
- Command-line analysis via WMIC process details
- Encoded commands, obfuscation, downloads, base64 content
- Only triggered for elevated scores (Layer 1 >= 30 or YARA >= 20)

**Layer 4 - Ensemble Cross-Validation (10% weight)**
- Corroboration boost (1.15x) when 2+ layers agree
- Single-source dampening (0.85x) for precision
- Named malware YARA override (critical + 2+ matches = score 95+)

### Ensemble Scoring

```
# Dump Analysis
Final Score = (PE * 0.25) + (YARA * 0.35) + (NGram * 0.15) + (Obfuscation * 0.15) + (Behavioral * 0.10)

# Real-Time Monitor
Ensemble = (Heuristic * 0.35) + (ExternalYARA * 0.30) + (Behavioral * 0.25) + Cross-Validation
```

### Cross-Validation (5 checks)

A detection must pass at least 2 of 5 independent validation checks:
1. Entropy falls within malware range (5.0 - 7.8)
2. API pattern score > 0.3
3. String IOC score > 0.4
4. Structural anomaly score > 0.2
5. Legitimate software score < 0.5

### Risk Classification

| Score | Level | Description |
|---|---|---|
| 80+ | CRITICAL | Active threat, immediate action required |
| 50-79 | HIGH | Significant malicious indicators |
| 30-49 | MEDIUM | Suspicious patterns detected |
| 0-29 | LOW | No significant threats |

---

## Real-Time Monitoring

The Real-Time tab provides live system monitoring with hybrid ML + YARA threat detection.

### How It Works

1. **YARA Loading** - On tab creation, 100 external YARA rule files are loaded in a background thread
2. **Background Thread** runs a 2-phase monitoring loop at configurable intervals (1-10s)
3. **Phase 1 - Quick Triage**: All new processes are scored with fast heuristics + YARA name-only matching
4. **Phase 2 - Deep Analysis**: Top 5 candidates get full 4-layer hybrid ML pipeline including WMIC command-line analysis
5. **Network Snapshots** via `netstat -ano` capture active connections with port/IP threat scoring
6. **UI Updates** are pushed to the main thread via thread-safe `root.after()` callbacks with value-captured lambdas

### Process Threat Scoring

**Layer 1 - Known Malware Tools (Fast)**
- 60+ malware tools with scores 85-100 (Mimikatz, Meterpreter, Cobalt Strike, 30+ RATs)
- Suspicious name patterns with scores 80-95 (keylogger, trojan, backdoor, rootkit)
- 19 LOLBins with scores 30-65 (PowerShell, mshta, certutil, regsvr32, etc.)
- Behavioral indicators: obfuscated names, double extensions, system mimics

**Layer 2 - External YARA Rules (Fast)**
- 1,881 rules matched against process name
- Quality-weighted: single match from multi-pattern rule scores 0.25x
- Patterns < 4 chars excluded from index to reduce noise
- Display threshold: YARA score >= 20 required to affect process display

**Layer 3 - Behavioral Command-Line Analysis (Slow, conditional)**
- Only triggered for elevated candidates (heuristic >= 30 or YARA >= 20)
- Analyzes 47 suspicious command-line patterns
- Detects: encoded commands, execution policy bypass, remote downloads, obfuscation
- Limited to max 5 deep analyses per monitoring cycle

**Layer 4 - Ensemble Cross-Validation**
- Corroboration boost (1.15x) when 2+ layers score high
- Single-source dampening (0.85x) for precision
- Named malware YARA override to score 95+

### Connection Threat Scoring
- Layer 1: Suspicious port analysis (known C2, RAT, backdoor ports)
- Layer 2: Port range scoring (Metasploit, common RAT ranges)
- Layer 3: IP classification (internal vs external, RFC 1918 compliant)
- Layer 4: Connection state analysis

### Alert Levels

| Score | Level | Color |
|---|---|---|
| 80+ | CRITICAL | Red |
| 50-79 | HIGH/WARNING | Orange |
| 30-49 | MEDIUM/INFO | Blue |
| <30 | Normal | Not logged |

---

## External YARA Rules

The `yara_rules/` directory contains 100 `.yar` files with 1,881 rules covering:

| Category | Files | Description |
|---|---|---|
| Malware Indicators | `malware_indicators.yar` | General malware signatures |
| Credential Stealers | `credential_stealers.yar` | Password/credential theft tools |
| Ransomware | `ransomware.yar` | Ransomware families and indicators |
| C2 Frameworks | `c2_frameworks.yar` | Command & control frameworks |
| LOLBins | `lolbins.yar` | Living-off-the-land binary abuse |
| Backdoors & RATs | `backdoors_rats.yar` | Remote access trojans |
| PowerShell Attacks | `powershell_attacks.yar` | PowerShell-based attacks |
| Fileless Malware | `fileless_malware.yar` | Memory-resident threats |
| Browser Extensions | `browser_extensions.yar` | Malicious browser plugins |
| Anti-Forensics | `anti_forensics.yar` | Evidence destruction tools |
| Advanced APTs | `advanced_apt.yar` | Nation-state threat indicators |
| + 89 more | Various | Full coverage across threat landscape |

### YARA Parser Features
- Extracts ASCII text string patterns (skips hex and regex patterns)
- Handles escaped quotes (`\"`) and escaped backslashes (`\\`) in patterns
- Correctly distinguishes hex patterns (`$h = { AB CD }`) from text patterns with braces (`$j = "{GUID}"`)
- Strips binary-only conditions (`uint16(0) == 0x5A4D`, `filesize`, `$mz at 0`)
- Evaluates compound conditions with `and`/`or`/`not`, parentheses, prefix wildcards
- Minimum pattern length filter (4 chars) to reduce false positive index matches
- Quality-weighted scoring: single match from multi-pattern rule reduced to 0.25x

---

## Report Generation

### Text Report
Generated from the Report tab, includes executive summary, risk assessment, malware detections, network artifacts, behavioral findings.

### JSON Export
Full analysis data exported as structured JSON for programmatic consumption.

### CSV Export
Network artifacts (IPs, URLs, domains, emails) exported as CSV for SIEM integration.

### Enterprise HTML Report
Professional-grade HTML report generated by `report_generator.py`:

- Dark forensic theme with animated hero section
- Sticky navigation bar with smooth scrolling
- 13 report sections with visual cards
- Risk assessment gauge visualization
- MITRE ATT&CK technique mapping
- Entropy analysis with visual bars
- Responsive grid layouts
- Print-optimized CSS
- Intersection Observer animations
- JetBrains Mono + Plus Jakarta Sans typography

---

## GUI Reference

### Top Bar
| Button | Action |
|---|---|
| Open Dump | Load a memory dump file |
| Create Dump | Create dump from running process (requires Admin) |
| Full Analysis | Run all analysis engines |
| Clear All | Reset all data and views |

### 15 Analysis Tabs

| # | Tab | Purpose |
|---|---|---|
| 1 | Overview | File info banner, risk gauge, summary stats, file hashes |
| 2 | Processes | Process detection and suspicion analysis |
| 3 | Network | Network artifact extraction (IPs, URLs, domains, emails) |
| 4 | Malware | Signature scan, ML scan, Enterprise scan, Hybrid scan |
| 5 | Dashboard | Threat intelligence visualization with bar charts and gauges |
| 6 | DLLs | DLL module detection and suspicious module flagging |
| 7 | Strings | String extraction with search, filter, and min-length control |
| 8 | Behavioral | Behavioral analysis with MITRE ATT&CK framework mapping |
| 9 | Registry | Registry keys and file paths with persistence risk indicators |
| 10 | Entropy | Block-by-block entropy analysis for encrypted/packed regions |
| 11 | Hex View | Raw hex dump viewer with offset navigation |
| 12 | Timeline | Aggregated event timeline from all analysis modules |
| 13 | Code Analysis | x86/x64 disassembly and shellcode pattern detection |
| 14 | Report | Report generation with JSON, CSV, and HTML export |
| 15 | Real-Time | Live process/network monitoring with hybrid ML + YARA alerts |

### Keyboard / UI Notes
- Dark theme optimized for extended forensic analysis sessions
- Treeviews support row selection highlighting
- Text areas use monospace fonts for hash/hex alignment
- YARA engine indicator shows loaded rules count and pattern count
- Progress bar in status bar tracks long-running operations

---

## Project Structure

```
Advanced Memory Forensics Analyzer/
|
+-- memory_forensics_tool.py    # Main application (7,200+ lines)
|   |
|   +-- AdvancedPEAnalyzer      # PE structure analysis
|   +-- YARALikeEngine          # 9 built-in YARA-like pattern rules
|   +-- ExternalYARALoader      # External .yar file parser (v3.0)
|   +-- NGramAnalyzer           # N-gram byte frequency analysis
|   +-- ObfuscationDetector     # Obfuscation/packer detection
|   +-- AdvancedMLDetector      # Multi-layer ensemble orchestrator
|   +-- MLMalwareDetector       # Feature-based ML scoring
|   +-- MemoryForensicsEngine   # Core forensics engine (35+ methods)
|   +-- MemoryForensicsGUI      # 15-tab GUI application (160+ methods)
|
+-- report_generator.py         # Enterprise HTML report generation (1,159 lines)
|   |
|   +-- generate_enterprise_html_report()
|
+-- yara_rules/                 # External YARA rules directory (v3.0)
|   |
|   +-- 100 .yar files          # 1,881 rules, 10,000+ text patterns
|
+-- ultra_deep_test.py          # Exhaustive test suite (267 tests)
|
+-- generate_test_dump.py       # Synthetic test data generator
|
+-- test_forensic_dump.raw      # Synthetic test data (~103KB)
|
+-- RUN_AS_ADMIN.bat            # Administrator elevation launcher
|
+-- README.md                   # This file
```

### Class Hierarchy

```
AdvancedPEAnalyzer          ~190 lines   PE header/section/import analysis
YARALikeEngine              ~174 lines   9-rule built-in malware matching
ExternalYARALoader          ~320 lines   External .yar file parser + matcher (v3.0)
NGramAnalyzer                ~64 lines   Byte sequence frequency analysis
ObfuscationDetector         ~118 lines   Entropy, XOR, Base64, packers
AdvancedMLDetector          ~178 lines   Ensemble ML orchestrator
MLMalwareDetector           ~386 lines   Feature extraction & scoring
MemoryForensicsEngine      ~1250 lines   Core analysis engine
MemoryForensicsGUI         ~5000 lines   Full GUI application
```

---

## Testing

The project includes an exhaustive test suite with 267 tests covering all classes, engine methods, GUI widgets, edge cases, and regression tests for all 20 bug fixes.

```bash
# Run with pytest
python -m pytest ultra_deep_test.py -v

# Or run directly
python ultra_deep_test.py
```

### Test Coverage

| Section | Tests | Description |
|---|---|---|
| AdvancedPEAnalyzer | 15 | PE parsing, anomaly detection, imports |
| YARALikeEngine | 14 | Rule loading, pattern matching, scanning |
| NGramAnalyzer | 7 | N-gram calculation, scoring |
| ObfuscationDetector | 12 | Entropy, XOR, Base64, packers |
| AdvancedMLDetector | 8 | Multi-layer detection, reporting |
| MLMalwareDetector | 15 | Feature extraction, ensemble scoring |
| MemoryForensicsEngine | 58 | All engine methods end-to-end |
| ExternalYARALoader | 14 | Rule parsing, matching, conditions |
| Enhanced Process Check | 11 | Hybrid ML pipeline, ensemble weights |
| YARA False Positive Reduction | 14 | Quality weighting, display threshold |
| YARA Edge Cases | 13 | Conditions, threading, escapes |
| Bug 17-20 Regression | 18 | Brace skip, backslash, IP range, lambda |
| GUI & Integration | 40 | Widget creation, handlers, reports |
| Edge Cases & Data | 18 | Empty data, malformed input, boundaries |
| **Total** | **267** | **100% passing** |

### Generating Test Data

```bash
# Regenerate the synthetic test dump
python generate_test_dump.py
```

The test dump contains 15 sections with embedded PE images, process names, DLL references, network artifacts, registry keys, malware signatures, shellcode patterns, and more.

---

## Requirements

### System
- **OS:** Windows 10/11 (required for real-time monitoring, memory dump creation)
- **Python:** 3.8+
- **RAM:** 4GB minimum, 8GB+ recommended for large dumps
- **Display:** 1400x900 minimum resolution

### Python Dependencies
All standard library - no external packages required:

```
tkinter          GUI framework
hashlib          Cryptographic hashing
json             Data serialization
csv              CSV export
re               Regular expressions
struct           Binary data parsing
os               File system operations
sys              System configuration
math             Mathematical operations
datetime         Timestamps
collections      Counter for frequency analysis
threading        Background monitoring
subprocess       System command execution
ctypes           Windows API calls
webbrowser       Report viewing
```

---

## Supported Memory Dump Formats

| Format | Extension | Detection Method |
|---|---|---|
| Windows Minidump | `.dmp` | `MDMP` magic bytes |
| Windows Full Dump | `.dmp` | `PAGE`/`PAGEDUMP` signature |
| PMem Format | `.raw` | `pmem` signature |
| Windows Kernel Dump | `.dmp` | `KDBG` signature |
| ELF Core Dump | `.core` | `\x7fELF` magic bytes |
| PE Executable | `.exe`, `.dll` | `MZ` header |
| VMware Snapshot | `.vmem` | File extension |
| Raw Memory | `.raw`, `.mem`, `.bin` | Default fallback |

---

## Malware Family Detection

### Built-in YARA-Like Rules

| Family | Confidence | Severity | Key Indicators |
|---|---|---|---|
| Mimikatz | 99% | CRITICAL | sekurlsa, logonpasswords, kerberos ticket |
| Metasploit/Meterpreter | 98% | CRITICAL | metsrv, stdapi, reverse_tcp |
| Cobalt Strike | 97% | CRITICAL | beacon, sleeptime, spawnto |
| PowerShell Empire | 96% | HIGH | invoke-empire, stager, launcher |
| Process Injection | -- | HIGH | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| Credential Dumpers | -- | HIGH | lsass, SAM, credential vault patterns |
| Ransomware | -- | CRITICAL | encrypt, .locked, bitcoin, ransom note |
| Generic RAT | -- | HIGH | keylogger, screenshot, webcam, reverse shell |
| Shellcode | -- | MEDIUM | NOP sled, GetPC, JMP ESP patterns |

### External YARA Rules (1,881 rules)

Severity distribution across the external rule set:
- **Critical:** 1,136 rules
- **High:** 540 rules
- **Medium:** 189 rules
- **Low:** 16 rules

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run the test suite: `python -m pytest ultra_deep_test.py -v`
4. Ensure all 267 tests pass
5. Submit a pull request

---

## Disclaimer

This tool is intended for authorized security analysis, incident response, and educational purposes only. Always ensure you have proper authorization before analyzing memory dumps or monitoring systems. The authors are not responsible for misuse of this tool.
