# Advanced Memory Forensics Analyzer v3.5

A professional-grade, enterprise-level memory forensics GUI tool built with Python and tkinter. Features a 4-layer hybrid ML detection pipeline with external YARA rule integration targeting 99.6% precision, real-time system monitoring with live CPU/memory metrics, full RAM acquisition via WinPmem/DumpIt, Volatility 3 integration, MITRE ATT&CK mapping, and enterprise HTML report generation.

<img width="2752" height="1460" alt="unnamed" src="https://github.com/user-attachments/assets/8ba3297d-416a-4fc3-a44a-43dbfa29b239" />

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Tests](https://img.shields.io/badge/Tests-375%20Passing-brightgreen)
![YARA Rules](https://img.shields.io/badge/YARA%20Rules-1881-orange)
![Bugs Fixed](https://img.shields.io/badge/Bugs%20Fixed-59-red)

---

## Table of Contents

- [Features](#features)
- [What's New in v3.5](#whats-new-in-v35)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [RAM Acquisition](#ram-acquisition)
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

https://github.com/user-attachments/assets/01e2c050-f24c-4d0b-b2a7-10be874d03ed

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
- IPv6 connection parsing with bracket notation and loopback/link-local detection

### RAM Acquisition & Volatility 3 Integration (v3.1)
- Full RAM dump acquisition from within the app via WinPmem, DumpIt, or FTK Imager
- Auto-detection of installed acquisition tools across multiple search paths
- Volatility 3 plugin runner with 12 common forensic plugins
- One-click "Acquire RAM" toolbar button with tool selection dialog
- Background acquisition with progress tracking
- Auto-load acquired dumps for immediate analysis

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

### Real-Time Monitoring (Enhanced in v3.1)
- Live process monitoring with 4-layer hybrid ML + YARA threat scoring
- **Live CPU% and Memory metrics** via two-phase collection (fast tasklist + CPU time deltas)
- 2-phase detection: fast triage for all processes, deep analysis for top 5 candidates
- External YARA rule matching against process names and command lines
- Network connection tracking with suspicious activity detection (IPv4 + IPv6)
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
- Handle cleanup uses `is not None` check (safe for handle value 0)

---

## What's New in v3.5

### Deep Code Review Round 5 — 4 More Bug Fixes (v3.5)
- **Bug 56:** Netstat parser only matched `TCP`/`UDP` protocols — `TCPv6` and `UDPv6` IPv6 connections were silently dropped from real-time monitoring
- **Bug 57:** Fallback `tasklist` subprocess call in `create_memory_dump()` missing `timeout=` parameter — could freeze GUI indefinitely
- **Bug 58:** 9 bare `except:` blocks caught `BaseException` (including `KeyboardInterrupt`, `SystemExit`) — changed all to `except Exception:` or specific types
- **Bug 59:** `_process_metrics` dictionary race condition — background thread could reset dict while GUI thread reads it. Now creates dict snapshot before scheduling `_update_process_display()`

### Previous (v3.4)

### Deep Code Review Round 4 — 8 More Bug Fixes (v3.4)
- **Bug 48:** `load_dump()` didn't reset `info_findings` — stale informational findings persisted across dump loads
- **Bug 49:** `clear_all()` missing `disasm_text` and `ml_report_text` — Code Analysis and ML Report text areas not cleared
- **Bug 50:** `clear_all()` referenced wrong widget name `behavioral_text` instead of `behavior_findings_text` — behavioral tab text never cleared
- **Bug 51:** `clear_all()` didn't reset `reg_stat_labels` or `timeline_stat_labels` — stale stat values after Clear All
- **Bug 52:** `clear_all()` didn't reset real-time monitor UI labels (proc_count, net_count, alert_count, newproc_count, susp_count)
- **Bug 53:** `clear_all()` didn't reset `timeline_types_frame` dynamic frame — stale event type labels after Clear All
- **Bug 54:** Chi-square calculation iterated only `byte_counts.values()` instead of `range(256)` — zero-count bytes omitted from statistic, understating anomalies
- **Bug 55:** Report generator entropy bar width could exceed 100% when entropy > 8.0 due to floating-point — added `min(100, ...)` cap

### Previous (v3.3)

### Deep Code Review Round 3 — 7 More Bug Fixes (v3.3)
- **Bug 41:** `_safe_after()` gated on `realtime_monitoring` — acquisition/Volatility callbacks silently dropped when monitor not running. Changed 19 calls to `_safe_after_always()`
- **Bug 42:** `run_full_analysis()` had no re-entrancy guard — rapid clicks queued duplicate analyses. Added `_analysis_running` flag
- **Bug 43:** `export_json()`, `export_csv()`, Volatility `export_results()` had no try-except — uncaught errors crashed silently. Added error handling with messagebox
- **Bug 44:** `clear_all()` didn't stop realtime monitor thread — orphaned thread kept running after clear. Now calls `stop_realtime_monitoring()`
- **Bug 45:** `export_realtime_alerts()` missing `encoding='utf-8'` — Unicode alerts crash on write. Added encoding param
- **Bug 46:** YARA `_clean_condition` removed operators before empty parens — order-dependent cleanup loop fixed
- **Bug 47:** YARA `all of ($prefix*)` returned True when no vars with prefix exist (Python `all([])` vacuous truth). Added empty-list check

### Previous (v3.2)

### Deep Code Review Round 2 — 10 More Bug Fixes (v3.2)
- **Bug 31:** `_enhanced_process_check` ensemble weights summed to 0.90 instead of 1.00 — all scores were systematically 10% low
- **Bug 32:** `AdvancedMLDetector.weights` had phantom 'behavioral' key (0.10) never used in `detect()` — scores 10% low
- **Bug 33:** `MLMalwareDetector.FEATURE_WEIGHTS` had phantom 'behavioral_correlation' (0.15) — scores 15% low
- **Bug 34:** Netstat UDP parsing required 5 columns but UDP has only 4 — all UDP connections silently dropped
- **Bug 35:** String extraction with `min_length=0` created regex `{0,}` matching every byte position, hanging the app
- **Bug 36:** YARA scan division by zero when external rule has all strings filtered (empty list)
- **Bug 37:** `load_dump()` didn't reset `analysis_results`/`risk_score`/`findings` — stale data from previous dump persisted
- **Bug 38:** `clear_all()` missed dashboard canvas/metric cards, behavioral score/level/gauge/MITRE, report summary/findings, realtime trees/alerts/state
- **Bug 39:** Hex viewer and disassembler accepted negative offsets — showed wrong data from end of dump
- **Bug 40:** Report generator crashed with `TypeError` when `dump_size` is None

### Previous (v3.1)

### RAM Acquisition & Volatility 3 Integration (v3.1)
- **"Acquire RAM" toolbar button** — one-click full RAM dump acquisition
- **WinPmem** integration (bundled in `tools/` directory) — open-source RAM acquisition
- **DumpIt** support — one-click quiet-mode acquisition
- **FTK Imager** launch support — opens GUI for manual acquisition
- **Volatility 3** plugin runner — 12 common forensic plugins with results viewer and export
- Auto-detection of tools across multiple search paths (`tools/`, Desktop, Downloads, `C:\Tools`, PATH)
- Background acquisition with progress indicator and auto-load option

### Live CPU & Memory Metrics (v3.1)
- Real-time monitor now shows **actual CPU% and Memory (MB)** for all processes
- Two-phase collection: fast `tasklist` for PID/Name/Memory, then `/V` for CPU time deltas
- CPU% computed from delta CPU Time between monitoring cycles
- Graceful fallback: if `/V` times out, memory still displays (CPU stays 0.0)

### 10 More Bug Fixes (Sessions 8-10)
- **Bug 21:** CPU% and Memory columns showed "--" for all processes in real-time monitor
- **Bug 22:** `_check_suspicious_connection()` used `startswith('172.')` instead of `_is_private_ip()`
- **Bug 23:** PE section offset hardcoded 112/96, skipping data directories — now reads `SizeOfOptionalHeader` from COFF header
- **Bug 24:** IPv6 brackets not stripped — `[::1]:port` parsed with brackets, loopback treated as external
- **Bug 25:** Handle cleanup used truthiness check (`if file_handle`) — fails for handle value 0, changed to `is not None`
- **Bug 26:** Missing `grab_release()` in acquire_ram_dump dialog — GUI freezes after acquisition
- **Bug 27:** Missing `grab_release()` in create_memory_dump dialog — same freeze issue
- **Bug 28:** WMIC CSV parsed with `split(',')` — command lines with commas corrupted all fields. Fixed to `csv.reader()`
- **Bug 29:** Volatility dialog widgets accessed after user closed dialog — TclError crash. Added `winfo_exists()` + TclError catch
- **Bug 30:** `clear_all()` didn't clear any treeviews — stale analysis data visible after Clear All

### Previous (v3.0)

#### Hybrid ML + External YARA Integration
- **ExternalYARALoader** class parses 100 `.yar` files from the `yara_rules/` directory
- Extracts ASCII text string patterns with proper escape handling (`\\`, `\"`)
- Builds inverted keyword index for O(1) candidate rule lookup
- Evaluates simplified YARA conditions: `any of them`, `N of them`, prefix wildcards, compound `and`/`or`/`not`
- Quality-weighted scoring reduces false positives from single-pattern matches

#### Enhanced Real-Time Monitor
- **4-layer hybrid ML pipeline** replaces simple name-based heuristics:
  - Layer 1 (40%): Fast name-based heuristic scoring
  - Layer 2 (35%): External YARA text pattern matching
  - Layer 3 (25%): Behavioral command-line analysis via WMIC
  - Layer 4: Cross-validation ensemble modifier (corroboration boost/dampening)
- **2-phase monitoring loop**: Quick triage for all new processes, then full 4-layer deep analysis for max 5 candidates per cycle
- Previously unused `_analyze_process_behavior()` method now wired into the detection pipeline
- YARA match info displayed in alerts: `[YARA: RuleName1, RuleName2]`

#### 20 Bug Fixes Across First 7 Sessions
- Fixed false positive YARA matches on common process names
- Fixed YARA pattern extraction: escaped quotes, double-backslash paths, brace-containing text strings
- Fixed 172.x private IP range to cover full RFC 1918 range (172.16-31.x.x)
- Fixed lambda closure race conditions in monitor thread
- Fixed GUI widget sync issues across load/update/clear operations
- See MEMORY.md for the complete bug list

### 375 Tests (up from 198)
- 75 test classes covering all functionality
- Tests for CPU/memory metrics collection, PE section offsets, IPv6 parsing, handle cleanup
- Tests for grab_release dialog safety, WMIC CSV parsing, Volatility widget safety
- Tests for YARA false positive reduction, edge cases, condition evaluation, thread safety
- Tests for private IP range, backslash unescaping, brace pattern extraction
- Tests for _safe_after gating, re-entrancy guard, export error handling, YARA condition cleanup
- Tests for clear_all completeness, chi-square calculation, entropy bar overflow
- Tests for netstat IPv6 protocols, subprocess timeouts, bare except elimination, metrics snapshot
- Full regression test coverage for all 59 bug fixes

---

## Architecture

<img width="4312" height="6436" alt="NotebookLM Mind Map" src="https://github.com/user-attachments/assets/fb3317a2-02aa-4859-a5ac-431dc83812c0" />

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
|  |   (40% weight)              multi-condition matching          |
|  |                                                               |
|  +-- NGramAnalyzer ----------> byte sequence frequency           |
|  |   (20% weight)              malicious pattern detection       |
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

# No external dependencies required for core features

# Optional: Install Volatility 3 for advanced dump analysis
pip install volatility3

# Run the application
python memory_forensics_tool.py
```

### Running with Administrator Privileges

RAM acquisition and memory dump creation require Administrator privileges. Use the included batch file:

```bash
# Right-click and select "Run as administrator"
RUN_AS_ADMIN.bat
```

Or run from an elevated command prompt:

```bash
python memory_forensics_tool.py
```

> **Note:** Loading and analyzing existing dump files does NOT require admin privileges. Only live RAM acquisition and process dump creation require elevation.

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

## RAM Acquisition

The app integrates with external forensic tools for full physical RAM acquisition. Click **"Acquire RAM"** in the toolbar to open the acquisition dialog.

### Supported Tools

| Tool | Type | Detection | Notes |
|---|---|---|---|
| **WinPmem** | Open-source | Auto-detected in `tools/`, Desktop, Downloads, PATH | Bundled in `tools/` directory |
| **DumpIt** | Free/commercial | Auto-detected across search paths | Quiet mode with `/OUTPUT` and `/QUIET` flags |
| **FTK Imager** | Commercial | Auto-detected | Launched as GUI (manual acquisition) |
| **Volatility 3** | Open-source | Detected via `vol`, `vol3`, or Python Scripts dir | Plugin runner for post-acquisition analysis |

### How It Works

1. Click **"Acquire RAM"** in the toolbar
2. The dialog auto-detects all available tools and shows green/red status indicators
3. Select a tool and output path
4. Click **"Start Acquisition"** — runs in background thread with progress indicator
5. Optionally check **"Auto-analyze after acquisition"** to load the dump immediately

### Volatility 3 Plugin Runner

After acquiring or loading a dump, use the Volatility 3 integration to run forensic plugins:

| Plugin | Description |
|---|---|
| `windows.pslist` | List running processes |
| `windows.pstree` | Process tree hierarchy |
| `windows.netscan` | Network connections |
| `windows.malfind` | Find injected/hidden code |
| `windows.dlllist` | Loaded DLLs per process |
| `windows.handles` | Open handles |
| `windows.cmdline` | Process command lines |
| `windows.filescan` | Scan for file objects |
| `windows.registry.hivelist` | Registry hives |
| `windows.vadinfo` | Virtual address descriptors |
| `windows.ssdt` | System service descriptor table |
| `windows.driverscan` | Loaded kernel drivers |

### Tool Search Paths

The app searches the following locations for acquisition tools:
- `tools/` subdirectory (relative to app)
- Application directory
- Desktop and Downloads folders
- `C:\Tools` and `C:\Forensics`
- System PATH

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

**Layer 2 - YARALikeEngine (40% weight - highest)**
- 9 built-in malware family detection rules
- Multi-condition matching (requires minimum pattern count)
- Families: Mimikatz, Meterpreter, Cobalt Strike, PowerShell Empire, Process Injection, Credential Dumpers, Ransomware, RATs, Shellcode

**Layer 3 - NGramAnalyzer (20% weight)**
- Trigram frequency analysis of byte sequences
- Detection of indirect calls, stack manipulation, self-modifying code
- Normalized risk scoring

**Layer 4 - ObfuscationDetector (15% weight)**
- Shannon entropy calculation
- XOR encoding pattern detection
- Base64 content identification
- Packer signature matching

### Real-Time Monitor Layers (v3.0)

**Layer 1 - Name Heuristics (40% weight)**
- 60+ known malware tools (Mimikatz, Meterpreter, 30+ RATs)
- Suspicious name patterns (keylogger, trojan, backdoor)
- LOLBins analysis (PowerShell, certutil, mshta, etc.)
- Behavioral indicators (obfuscated names, double extensions, system mimics)

**Layer 2 - External YARA (35% weight)**
- 1,881 rules from 100 `.yar` files
- Quality-weighted scoring (single match from multi-pattern rule: 0.25x)
- Display threshold (score >= 20) to prevent false positives

**Layer 3 - Behavioral Analysis (25% weight)**
- Command-line analysis via WMIC process details
- Encoded commands, obfuscation, downloads, base64 content
- Only triggered for elevated scores (Layer 1 >= 30 or YARA >= 20)

**Layer 4 - Ensemble Cross-Validation (modifier)**
- Corroboration boost (1.15x) when 2+ layers agree
- Single-source dampening (0.85x) for precision
- Named malware YARA override (critical + 2+ matches = score 95+)

### Ensemble Scoring

```
# Dump Analysis
Final Score = (PE * 0.25) + (YARA * 0.40) + (NGram * 0.20) + (Obfuscation * 0.15)

# Real-Time Monitor
Ensemble = (Heuristic * 0.40) + (ExternalYARA * 0.35) + (Behavioral * 0.25)
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
| Acquire RAM | Full RAM acquisition via WinPmem/DumpIt/FTK Imager (requires Admin) |
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
+-- memory_forensics_tool.py    # Main application (8,200+ lines)
|   |
|   +-- AdvancedPEAnalyzer      # PE structure analysis
|   +-- YARALikeEngine          # 9 built-in YARA-like pattern rules
|   +-- ExternalYARALoader      # External .yar file parser (v3.0)
|   +-- NGramAnalyzer           # N-gram byte frequency analysis
|   +-- ObfuscationDetector     # Obfuscation/packer detection
|   +-- AdvancedMLDetector      # Multi-layer ensemble orchestrator
|   +-- MLMalwareDetector       # Feature-based ML scoring
|   +-- MemoryForensicsEngine   # Core forensics engine (35+ methods)
|   +-- MemoryForensicsGUI      # 15-tab GUI application (170+ methods)
|
+-- report_generator.py         # Enterprise HTML report generation (1,159 lines)
|   |
|   +-- generate_enterprise_html_report()
|
+-- tools/                      # External forensic tools (v3.1)
|   |
|   +-- winpmem_mini_x64.exe    # WinPmem RAM acquisition tool
|   +-- winpmem.exe             # go-winpmem signed version
|
+-- yara_rules/                 # External YARA rules directory (v3.0)
|   |
|   +-- 100 .yar files          # 1,881 rules, 10,000+ text patterns
|
+-- ultra_deep_test.py          # Exhaustive test suite (375 tests)
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
AdvancedPEAnalyzer          ~190 lines   PE header/section/import analysis (SizeOfOptionalHeader-aware)
YARALikeEngine              ~174 lines   9-rule built-in malware matching
ExternalYARALoader          ~320 lines   External .yar file parser + matcher (v3.0)
NGramAnalyzer                ~64 lines   Byte sequence frequency analysis
ObfuscationDetector         ~118 lines   Entropy, XOR, Base64, packers
AdvancedMLDetector          ~178 lines   Ensemble ML orchestrator
MLMalwareDetector           ~386 lines   Feature extraction & scoring
MemoryForensicsEngine      ~1250 lines   Core analysis engine (IPv6-aware, RFC 1918 compliant)
MemoryForensicsGUI         ~5600 lines   Full GUI + RAM acquisition + Volatility 3
```

---

## Testing

The project includes an exhaustive test suite with 375 tests covering all classes, engine methods, GUI widgets, edge cases, and regression tests for all 59 bug fixes.

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
| Bug 22 Connection Private IP | 7 | 172.x ranges, _is_private_ip usage |
| Bug 23 PE Section Offset | 3 | SizeOfOptionalHeader, PE32/PE32+ |
| Bug 24 IPv6 Connection | 6 | Bracket parsing, loopback, link-local |
| Bug 25 Handle Cleanup | 1 | `is not None` check for handle=0 |
| Bug 26-27 Grab Release | 4 | Dialog grab_release, WM_DELETE_WINDOW |
| Bug 28 WMIC CSV Parsing | 3 | csv.reader, comma-in-fields handling |
| Bug 29 Volatility Dialog Safety | 2 | winfo_exists, TclError catch |
| Bug 30 Clear All Treeviews | 8 | All 8 treeviews cleared |
| Subprocess Timeouts | 2 | Timeout on all subprocess calls |
| Process Metrics Collection | 6 | CPU delta, memory parsing, display |
| Defensive Init | 2 | Metrics/counter initialization |
| Bug 31-33 Ensemble Weights | 6 | Weight normalization, phantom keys |
| Bug 34 Netstat UDP | 2 | TCP/UDP branch parsing |
| Bug 35 String Min Length | 2 | Clamp min_length < 1 |
| Bug 36 YARA Division by Zero | 2 | max(1, len) guard |
| Bug 37 Load Dump State | 2 | Reset analysis_results, risk_score |
| Bug 38 Clear All Completeness | 10 | Dashboard, behavioral, report, realtime |
| Bug 39 Negative Offset | 4 | Hex dump, disassemble, view_hex clamp |
| Bug 40 Report Generator | 2 | dump_size None guard |
| Bug 41 Safe After Always | 2 | Acquisition/Volatility use _safe_after_always |
| Bug 42 Re-entrancy Guard | 2 | _analysis_running flag prevents duplicates |
| Bug 43 Export Error Handling | 3 | try-except on JSON, CSV, Volatility export |
| Bug 44 Clear All Monitor Stop | 2 | stop_realtime_monitoring on clear |
| Bug 45 Export Encoding | 2 | UTF-8 encoding on alert export |
| Bug 46 YARA Condition Cleanup | 2 | Empty parens before operator cleanup |
| Bug 47 YARA Vacuous Truth | 3 | all-of empty prefix returns False |
| Bug 48 Load Dump Info Findings | 2 | info_findings reset on load_dump |
| Bug 49-50 Clear All Text Widgets | 3 | disasm_text, ml_report_text, behavior_findings_text |
| Bug 51 Stat Label Resets | 2 | reg_stat_labels, timeline_stat_labels |
| Bug 52 Realtime Stat Labels | 2 | proc_count, net_count, alert_count reset |
| Bug 53 Timeline Types Frame | 1 | timeline_types_frame dynamic reset |
| Bug 54 Chi-Square | 2 | range(256) iteration, sparse vs dense |
| Bug 55 Entropy Bar Width | 2 | min(100, ...) cap in report generator |
| Bug 56 Netstat IPv6 | 2 | TCPv6/UDPv6 protocol acceptance |
| Bug 57 Subprocess Timeout | 1 | All subprocess.run calls have timeout |
| Bug 58 Bare Except | 1 | No bare except: blocks in source |
| Bug 59 Metrics Snapshot | 2 | Thread-safe metrics param + snapshot |
| GUI & Integration | 40 | Widget creation, handlers, reports |
| Edge Cases & Data | 18 | Empty data, malformed input, boundaries |
| **Total** | **375** | **100% passing** |

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
Core features use only the standard library — no external packages required:

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

### Optional Dependencies

```
volatility3      Advanced memory dump analysis (pip install volatility3)
```

### Optional External Tools

| Tool | Purpose | Installation |
|---|---|---|
| WinPmem | RAM acquisition | Bundled in `tools/` directory |
| DumpIt | RAM acquisition | Place in `tools/` or PATH |
| FTK Imager | RAM acquisition (GUI) | Install from Exterro |
| Volatility 3 | Dump analysis plugins | `pip install volatility3` |

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
4. Ensure all 375 tests pass
5. Submit a pull request

---

## Disclaimer

This tool is intended for authorized security analysis, incident response, and educational purposes only. Always ensure you have proper authorization before analyzing memory dumps or monitoring systems. The authors are not responsible for misuse of this tool.
