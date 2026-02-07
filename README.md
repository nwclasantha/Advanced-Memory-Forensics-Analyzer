# Advanced Memory Forensics Analyzer v2.0

A professional-grade, enterprise-level memory forensics GUI tool built with Python and tkinter. Features multi-layer ML-enhanced malware detection targeting 98.5%+ precision, real-time system monitoring, MITRE ATT&CK mapping, and enterprise HTML report generation.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-198%20Passing-brightgreen)

---

## Table of Contents

- [Features](#features)
- [Screenshots](#screenshots)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Analysis Capabilities](#analysis-capabilities)
- [ML Detection Pipeline](#ml-detection-pipeline)
- [Real-Time Monitoring](#real-time-monitoring)
- [Report Generation](#report-generation)
- [GUI Reference](#gui-reference)
- [Project Structure](#project-structure)
- [Testing](#testing)
- [Requirements](#requirements)

---

## Features

<img width="1917" height="988" alt="image" src="https://github.com/user-attachments/assets/e083d81b-1a49-4f79-9809-83133a454771" />

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
- Event timeline construction

### ML-Enhanced Detection
- 4-layer ensemble ML detection pipeline
- 9 YARA-like malware family rules (Mimikatz, Meterpreter, Cobalt Strike, Empire, etc.)
- PE structure anomaly analysis
- N-gram byte sequence frequency analysis
- Obfuscation/packer detection (UPX, VMProtect, Themida, ASPack, etc.)
- Cross-validation with 5 independent checks to minimize false positives
- 98.5%+ precision target through ensemble scoring

### Behavioral Analysis
- 8 threat categories mapped to MITRE ATT&CK framework
- Process Injection (T1055), Credential Access (T1003), Persistence (T1547)
- Lateral Movement (T1021), Data Exfiltration (T1041), Defense Evasion (T1027)
- Command & Control (T1071), Crypto Mining (T1496)

### Real-Time Monitoring
- Live process monitoring with ML-enhanced threat scoring
- Network connection tracking with suspicious activity detection
- Configurable refresh intervals (1-10 seconds)
- Color-coded threat alerts (CRITICAL / WARNING / INFO)
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

## Architecture

```
+------------------------------------------------------------------+
|                    MemoryForensicsGUI                            |
|  (15-tab tkinter interface, 4500+ lines)                         |
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
|                  |  |                |  | tasklist / netstat /   |
| - Process scan   |  | - HTML output  |  | wmic subprocess calls  |
| - Network extract|  | - 13 sections  |  | ML threat scoring      |
| - Malware detect |  | - Dark theme   |  | Thread-safe UI updates |
| - DLL analysis   |  | - Animations   |  +------------------------+
| - String extract |  | - Print CSS    |
| - Entropy calc   |  +----------------+
| - Registry scan  |
| - Behavioral     |
+------------------+
         |
         v
+------------------------------------------------------------------+
|                   ML Detection Pipeline                          |
|                                                                  |
|  AdvancedMLDetector (Ensemble Orchestrator)                      |
|  |                                                               |
|  +-- AdvancedPEAnalyzer -----> PE headers, sections, imports     |
|  |   (25% weight)                                                |
|  |                                                               |
|  +-- YARALikeEngine ---------> 9 malware family rules            |
|  |   (35% weight)              multi-condition matching          |
|  |                                                               |
|  +-- NGramAnalyzer ----------> byte sequence frequency           |
|  |   (15% weight)              malicious pattern detection       |
|  |                                                               |
|  +-- ObfuscationDetector ----> entropy, XOR, Base64, packers     |
|      (15% weight)                                                |
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

The detection pipeline uses a multi-layer ensemble approach designed for high precision (98.5%+ target) to minimize false positives in production environments.

### Layer Architecture

**Layer 1 - AdvancedPEAnalyzer (25% weight)**
- PE header validation and anomaly detection
- Section analysis (writable+executable, unusual names, entropy)
- Packer identification (UPX, VMProtect, Themida, ASPack, etc.)
- Import table analysis across 7 suspicious categories

**Layer 2 - YARALikeEngine (35% weight - highest)**
- 9 malware family detection rules
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

### Ensemble Scoring

```
Final Score = (PE * 0.25) + (YARA * 0.35) + (NGram * 0.15) + (Obfuscation * 0.15) + (Behavioral * 0.10)
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
| 75+ | CRITICAL | Active threat, immediate action required |
| 55-74 | HIGH | Significant malicious indicators |
| 35-54 | MEDIUM | Suspicious patterns detected |
| 0-34 | LOW | No significant threats |

---

## Real-Time Monitoring

The Real-Time tab provides live system monitoring with ML-enhanced threat detection.

### How It Works

1. **Background Thread** runs a monitoring loop at configurable intervals (1-10s)
2. **Process Snapshots** via `tasklist /FO CSV /NH` capture running processes
3. **Network Snapshots** via `netstat -ano` capture active connections
4. **Change Detection** compares current state against previous snapshot
5. **ML Scoring** evaluates each new process/connection against threat models
6. **UI Updates** are pushed to the main thread via thread-safe `root.after()` callbacks

### Threat Scoring

**Process Threat Layers:**
- Layer 1: Known malware tools (100 score) - Mimikatz, Meterpreter, Cobalt Strike, 30+ RATs
- Layer 2: Suspicious name patterns (80-95 score) - keylogger, trojan, backdoor, rootkit
- Layer 3: LOLBins analysis (30-65 score) - PowerShell, mshta, certutil, regsvr32, etc.
- Layer 4: Command line analysis - encoded commands, obfuscation, downloads

**Connection Threat Layers:**
- Layer 1: Suspicious port analysis (known C2, RAT, backdoor ports)
- Layer 2: Port range scoring (Metasploit, common RAT ranges)
- Layer 3: IP classification (internal vs external)
- Layer 4: Connection state analysis

### Alert Levels

| Score | Level | Color |
|---|---|---|
| 80+ | CRITICAL | Red |
| 50-79 | HIGH/WARNING | Orange |
| 30-49 | MEDIUM/INFO | Blue |
| <30 | Normal | Not logged |

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
| 15 | Real-Time | Live process/network monitoring with threat alerts |

### Keyboard / UI Notes
- Dark theme optimized for extended forensic analysis sessions
- Treeviews support row selection highlighting
- Text areas use monospace fonts for hash/hex alignment
- Progress bar in status bar tracks long-running operations

---

## Project Structure

```
Advanced Memory Forensics Analyzer/
|
+-- memory_forensics_tool.py    # Main application (6,900+ lines)
|   |
|   +-- AdvancedPEAnalyzer      # PE structure analysis
|   +-- YARALikeEngine          # YARA-like pattern matching
|   +-- NGramAnalyzer           # N-gram byte frequency analysis
|   +-- ObfuscationDetector     # Obfuscation/packer detection
|   +-- AdvancedMLDetector      # Multi-layer ensemble orchestrator
|   +-- MLMalwareDetector       # Feature-based ML scoring
|   +-- MemoryForensicsEngine   # Core forensics engine (35+ methods)
|   +-- MemoryForensicsGUI      # 15-tab GUI application (146+ methods)
|
+-- report_generator.py         # Enterprise HTML report generation (1,159 lines)
|   |
|   +-- generate_enterprise_html_report()
|
+-- ultra_deep_test.py          # Exhaustive test suite (198 tests)
|
+-- test_forensic_dump.raw      # Synthetic test data (~101KB)
|
+-- RUN_AS_ADMIN.bat            # Administrator elevation launcher
|
+-- README.md                   # This file
```

### Class Hierarchy

```
AdvancedPEAnalyzer          ~190 lines   PE header/section/import analysis
YARALikeEngine              ~174 lines   9-rule malware pattern matching
NGramAnalyzer                ~64 lines   Byte sequence frequency analysis
ObfuscationDetector         ~118 lines   Entropy, XOR, Base64, packers
AdvancedMLDetector          ~178 lines   Ensemble ML orchestrator
MLMalwareDetector           ~386 lines   Feature extraction & scoring
MemoryForensicsEngine      ~1206 lines   Core analysis engine
MemoryForensicsGUI         ~4506 lines   Full GUI application
```

---

## Testing

The project includes an exhaustive test suite covering all classes, engine methods, GUI widgets, and edge cases.

```bash
python ultra_deep_test.py
```

### Test Coverage

| Section | Tests | Description |
|---|---|---|
| AdvancedPEAnalyzer | 18 | PE parsing, anomaly detection, imports |
| YARALikeEngine | 39 | Rule loading, pattern matching, scanning |
| NGramAnalyzer | 17 | N-gram calculation, scoring |
| ObfuscationDetector | 19 | Entropy, XOR, Base64, packers |
| MLMalwareDetector | 13 | Feature extraction, ensemble scoring |
| AdvancedMLDetector | 11 | Multi-layer detection, reporting |
| MemoryForensicsEngine | 24 | All engine methods end-to-end |
| GUI Widgets | 20 | Widget creation, initialization |
| GUI Handlers | 25 | Button handlers, analysis functions |
| Edge Cases | 12 | Empty data, malformed input, boundaries |
| **Total** | **198** | **100% passing** |

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

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run the test suite: `python ultra_deep_test.py`
4. Ensure all 198 tests pass
5. Submit a pull request

---

## Disclaimer

This tool is intended for authorized security analysis, incident response, and educational purposes only. Always ensure you have proper authorization before analyzing memory dumps or monitoring systems. The authors are not responsible for misuse of this tool.
