"""
╔══════════════════════════════════════════════════════════════════╗
║   ENTERPRISE HTML FORENSIC REPORT GENERATOR                     ║
║   Professional Memory Forensics Analysis Report                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

import datetime
import os
import json
import html


def generate_enterprise_html_report(engine, output_path="forensic_report.html"):
    """
    Generate a comprehensive enterprise-grade HTML forensic report.
    Returns the path to the generated report.
    """

    # ── Gather all analysis data ──
    hashes = engine.get_file_hashes()
    dump_type = engine.detect_dump_type()
    behavioral = engine.behavioral_analysis()
    malware = engine.detect_malware_signatures()
    network = engine.extract_network_artifacts()
    processes = engine.find_processes()
    dlls = engine.analyze_dlls()
    registry = engine.extract_registry_keys()
    file_paths = engine.extract_file_paths()
    entropy = engine.entropy_analysis()

    suspicious_procs = [p for p in processes if p['suspicious']]
    suspicious_dlls = [d for d in dlls if d['suspicious']]
    high_entropy = [e for e in entropy if e['entropy'] > 7.0]

    risk_score = behavioral['score']
    risk_level = behavioral['level']
    findings = behavioral['findings']

    now = datetime.datetime.now()
    timestamp = now.strftime('%Y-%m-%d %H:%M:%S')
    case_id = f"MFA-{now.strftime('%Y%m%d')}-{abs(hash(engine.dump_path or '')) % 99999:05d}"

    # ── Risk colors ──
    risk_colors = {
        'CRITICAL': ('#dc2626', '#fef2f2', '#991b1b'),
        'HIGH': ('#ea580c', '#fff7ed', '#9a3412'),
        'MEDIUM': ('#d97706', '#fffbeb', '#92400e'),
        'LOW': ('#16a34a', '#f0fdf4', '#166534'),
    }
    rc_main, rc_bg, rc_dark = risk_colors.get(risk_level, ('#6b7280', '#f9fafb', '#374151'))

    # ── Helper to escape HTML ──
    def esc(text):
        return html.escape(str(text))

    # ── Build MITRE mapping ──
    mitre_map = {
        'Process Injection': ('T1055', 'Process Injection', 'Defense Evasion, Privilege Escalation'),
        'Credential Access': ('T1003', 'OS Credential Dumping', 'Credential Access'),
        'Persistence': ('T1547', 'Boot or Logon Autostart Execution', 'Persistence'),
        'Lateral Movement': ('T1021', 'Remote Services', 'Lateral Movement'),
        'Data Exfiltration': ('T1041', 'Exfiltration Over C2 Channel', 'Exfiltration'),
        'Defense Evasion': ('T1027', 'Obfuscated Files or Information', 'Defense Evasion'),
        'Command & Control': ('T1071', 'Application Layer Protocol', 'Command and Control'),
        'Crypto Mining': ('T1496', 'Resource Hijacking', 'Impact'),
    }

    # ── Build network rows ──
    def build_network_table(artifacts, art_type, icon, label):
        items = artifacts.get(art_type, [])
        if not items:
            return ""
        rows = ""
        for item in items[:50]:
            rows += f'<tr><td>{icon}</td><td class="mono">{esc(item)}</td></tr>\n'
        if len(items) > 50:
            rows += f'<tr><td colspan="2" class="more">... and {len(items)-50} more</td></tr>\n'
        return f"""
        <div class="net-section">
            <h4>{icon} {label} <span class="badge">{len(items)}</span></h4>
            <table class="data-table compact">
                <thead><tr><th width="40">Type</th><th>Value</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"""

    # ── Build the HTML ──
    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Memory Forensics Report — {case_id}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap');

:root {{
    --bg-primary: #0a0e1a;
    --bg-secondary: #111827;
    --bg-card: #1a2332;
    --bg-card-alt: #1e293b;
    --bg-elevated: #243044;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-dim: #64748b;
    --accent-cyan: #06d6a0;
    --accent-blue: #3b82f6;
    --accent-purple: #8b5cf6;
    --accent-orange: #f59e0b;
    --accent-red: #ef4444;
    --accent-green: #10b981;
    --border: #1e3a5f;
    --border-subtle: rgba(255,255,255,0.06);
    --gradient-hero: linear-gradient(135deg, #0a0e1a 0%, #1a1040 30%, #0f2847 60%, #0a0e1a 100%);
    --gradient-accent: linear-gradient(135deg, #06d6a0, #3b82f6);
    --gradient-danger: linear-gradient(135deg, #dc2626, #ea580c);
    --shadow-card: 0 4px 24px rgba(0,0,0,0.4);
    --shadow-glow: 0 0 40px rgba(6,214,160,0.1);
    --radius: 12px;
    --radius-sm: 8px;
    --radius-lg: 16px;
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}

body {{
    font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
    min-height: 100vh;
}}

/* ═══ HERO HEADER ═══ */
.hero {{
    background: var(--gradient-hero);
    position: relative;
    overflow: hidden;
    padding: 60px 0 50px;
    border-bottom: 1px solid var(--border);
}}

.hero::before {{
    content: '';
    position: absolute;
    top: -50%;
    left: -50%;
    width: 200%;
    height: 200%;
    background: 
        radial-gradient(ellipse at 20% 50%, rgba(6,214,160,0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 20%, rgba(59,130,246,0.06) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 80%, rgba(139,92,246,0.05) 0%, transparent 50%);
    animation: heroFloat 20s ease-in-out infinite;
}}

@keyframes heroFloat {{
    0%, 100% {{ transform: translate(0, 0) rotate(0deg); }}
    33% {{ transform: translate(30px, -20px) rotate(1deg); }}
    66% {{ transform: translate(-20px, 15px) rotate(-1deg); }}
}}

.hero-grid {{
    position: absolute;
    inset: 0;
    background-image: 
        linear-gradient(rgba(6,214,160,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(6,214,160,0.03) 1px, transparent 1px);
    background-size: 60px 60px;
    mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
}}

.hero-content {{
    position: relative;
    z-index: 2;
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 40px;
}}

.hero-badge {{
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(6,214,160,0.1);
    border: 1px solid rgba(6,214,160,0.2);
    color: var(--accent-cyan);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 6px 16px;
    border-radius: 100px;
    margin-bottom: 20px;
}}

.hero-badge::before {{
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: var(--accent-cyan);
    animation: pulse 2s ease-in-out infinite;
}}

@keyframes pulse {{
    0%, 100% {{ opacity: 1; transform: scale(1); }}
    50% {{ opacity: 0.5; transform: scale(1.5); }}
}}

.hero h1 {{
    font-size: 42px;
    font-weight: 800;
    letter-spacing: -1px;
    margin-bottom: 8px;
    background: var(--gradient-accent);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}}

.hero-subtitle {{
    font-size: 16px;
    color: var(--text-secondary);
    margin-bottom: 30px;
}}

.hero-meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
}}

.meta-item {{
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    padding: 14px 18px;
    backdrop-filter: blur(10px);
}}

.meta-item .meta-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: var(--text-dim);
    margin-bottom: 4px;
}}

.meta-item .meta-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    color: var(--text-primary);
    word-break: break-all;
}}

/* ═══ NAVIGATION ═══ */
.nav {{
    position: sticky;
    top: 0;
    z-index: 100;
    background: rgba(10,14,26,0.85);
    backdrop-filter: blur(20px) saturate(180%);
    border-bottom: 1px solid var(--border-subtle);
    padding: 0 40px;
}}

.nav-inner {{
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    gap: 2px;
    overflow-x: auto;
    scrollbar-width: none;
}}

.nav-inner::-webkit-scrollbar {{ display: none; }}

.nav a {{
    color: var(--text-dim);
    text-decoration: none;
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.5px;
    padding: 14px 16px;
    white-space: nowrap;
    border-bottom: 2px solid transparent;
    transition: all 0.2s;
}}

.nav a:hover {{
    color: var(--accent-cyan);
    border-bottom-color: var(--accent-cyan);
    background: rgba(6,214,160,0.05);
}}

/* ═══ MAIN CONTENT ═══ */
.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 40px;
}}

/* ═══ SECTIONS ═══ */
.section {{
    margin-bottom: 48px;
    animation: fadeUp 0.6s ease-out both;
}}

@keyframes fadeUp {{
    from {{ opacity: 0; transform: translateY(20px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}

.section-header {{
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 24px;
    padding-bottom: 16px;
    border-bottom: 1px solid var(--border-subtle);
}}

.section-icon {{
    width: 44px;
    height: 44px;
    border-radius: var(--radius-sm);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 20px;
    flex-shrink: 0;
}}

.section-icon.blue {{ background: rgba(59,130,246,0.15); }}
.section-icon.green {{ background: rgba(16,185,129,0.15); }}
.section-icon.red {{ background: rgba(239,68,68,0.15); }}
.section-icon.purple {{ background: rgba(139,92,246,0.15); }}
.section-icon.orange {{ background: rgba(245,158,11,0.15); }}
.section-icon.cyan {{ background: rgba(6,214,160,0.15); }}

.section-title {{
    font-size: 22px;
    font-weight: 700;
    letter-spacing: -0.5px;
}}

.section-count {{
    margin-left: auto;
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    padding: 4px 14px;
    border-radius: 100px;
    font-size: 13px;
    font-weight: 600;
    color: var(--text-secondary);
    font-family: 'JetBrains Mono', monospace;
}}

/* ═══ CARDS ═══ */
.card {{
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius);
    padding: 24px;
    margin-bottom: 16px;
    box-shadow: var(--shadow-card);
    transition: border-color 0.3s;
}}

.card:hover {{
    border-color: rgba(6,214,160,0.2);
}}

.card-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 16px;
}}

/* ═══ RISK SCORE ═══ */
.risk-dashboard {{
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 24px;
    margin-bottom: 24px;
}}

@media (max-width: 768px) {{
    .risk-dashboard {{ grid-template-columns: 1fr; }}
}}

.risk-gauge {{
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-lg);
    padding: 40px;
    text-align: center;
    position: relative;
    overflow: hidden;
}}

.risk-gauge::after {{
    content: '';
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: {rc_main};
    box-shadow: 0 0 20px {rc_main};
}}

.risk-number {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 80px;
    font-weight: 700;
    line-height: 1;
    color: {rc_main};
    text-shadow: 0 0 40px {rc_main}40;
}}

.risk-label {{
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--text-dim);
    margin: 8px 0;
}}

.risk-level {{
    display: inline-block;
    background: {rc_main}20;
    color: {rc_main};
    font-weight: 700;
    font-size: 14px;
    letter-spacing: 2px;
    padding: 6px 20px;
    border-radius: 100px;
    border: 1px solid {rc_main}40;
}}

.risk-bar {{
    height: 8px;
    background: var(--bg-card-alt);
    border-radius: 4px;
    margin-top: 20px;
    overflow: hidden;
}}

.risk-bar-fill {{
    height: 100%;
    width: {risk_score}%;
    background: linear-gradient(90deg, var(--accent-green), var(--accent-orange), var(--accent-red));
    border-radius: 4px;
    transition: width 1s ease;
}}

/* ═══ TABLES ═══ */
.data-table {{
    width: 100%;
    border-collapse: separate;
    border-spacing: 0;
    font-size: 13px;
}}

.data-table thead th {{
    background: var(--bg-elevated);
    color: var(--accent-cyan);
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 1px;
    text-transform: uppercase;
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
}}

.data-table thead th:first-child {{ border-radius: var(--radius-sm) 0 0 0; }}
.data-table thead th:last-child {{ border-radius: 0 var(--radius-sm) 0 0; }}

.data-table tbody tr {{
    transition: background 0.15s;
}}

.data-table tbody tr:hover {{
    background: rgba(6,214,160,0.03);
}}

.data-table tbody td {{
    padding: 10px 16px;
    border-bottom: 1px solid var(--border-subtle);
    color: var(--text-secondary);
}}

.data-table.compact td {{ padding: 8px 12px; font-size: 12px; }}

.mono {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; }}

/* ═══ STATUS BADGES ═══ */
.badge {{
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 3px 10px;
    border-radius: 100px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
}}

.badge-critical {{ background: rgba(220,38,38,0.15); color: #fca5a5; border: 1px solid rgba(220,38,38,0.3); }}
.badge-high {{ background: rgba(234,88,12,0.15); color: #fdba74; border: 1px solid rgba(234,88,12,0.3); }}
.badge-medium {{ background: rgba(217,119,6,0.15); color: #fcd34d; border: 1px solid rgba(217,119,6,0.3); }}
.badge-low {{ background: rgba(22,163,74,0.15); color: #86efac; border: 1px solid rgba(22,163,74,0.3); }}
.badge-info {{ background: rgba(59,130,246,0.15); color: #93c5fd; border: 1px solid rgba(59,130,246,0.3); }}
.badge-suspicious {{ background: rgba(239,68,68,0.15); color: #fca5a5; }}
.badge-clean {{ background: rgba(16,185,129,0.15); color: #6ee7b7; }}

/* ═══ HASH DISPLAY ═══ */
.hash-grid {{
    display: grid;
    gap: 10px;
}}

.hash-item {{
    display: flex;
    align-items: center;
    gap: 12px;
    background: var(--bg-card-alt);
    padding: 12px 16px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--border-subtle);
}}

.hash-label {{
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    color: var(--accent-cyan);
    min-width: 60px;
}}

.hash-value {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--text-secondary);
    word-break: break-all;
}}

/* ═══ FINDINGS ═══ */
.finding-card {{
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius);
    padding: 20px 24px;
    margin-bottom: 12px;
    border-left: 4px solid;
    transition: transform 0.2s, box-shadow 0.2s;
}}

.finding-card:hover {{
    transform: translateX(4px);
    box-shadow: var(--shadow-card);
}}

.finding-card.severity-critical {{ border-left-color: #dc2626; }}
.finding-card.severity-high {{ border-left-color: #ea580c; }}
.finding-card.severity-medium {{ border-left-color: #d97706; }}

.finding-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 10px;
}}

.finding-title {{
    font-size: 16px;
    font-weight: 700;
}}

.finding-detail {{
    color: var(--text-secondary);
    font-size: 13px;
    margin-bottom: 10px;
}}

.indicator-list {{
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
}}

.indicator-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    background: rgba(139,92,246,0.1);
    color: #c4b5fd;
    padding: 3px 10px;
    border-radius: 4px;
    border: 1px solid rgba(139,92,246,0.2);
}}

/* ═══ MITRE ATT&CK ═══ */
.mitre-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 12px;
}}

.mitre-card {{
    display: flex;
    align-items: center;
    gap: 14px;
    background: var(--bg-card-alt);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius-sm);
    padding: 16px;
    transition: border-color 0.2s;
}}

.mitre-card:hover {{ border-color: rgba(139,92,246,0.3); }}

.mitre-id {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 13px;
    font-weight: 700;
    color: var(--accent-purple);
    background: rgba(139,92,246,0.1);
    padding: 6px 12px;
    border-radius: 6px;
    white-space: nowrap;
}}

.mitre-info {{ flex: 1; }}
.mitre-technique {{ font-weight: 600; font-size: 13px; }}
.mitre-tactic {{ font-size: 11px; color: var(--text-dim); margin-top: 2px; }}

/* ═══ ENTROPY VIZ ═══ */
.entropy-bar-container {{
    display: flex;
    align-items: center;
    gap: 8px;
}}

.entropy-bar-bg {{
    flex: 1;
    height: 8px;
    background: var(--bg-card-alt);
    border-radius: 4px;
    overflow: hidden;
}}

.entropy-bar-fg {{
    height: 100%;
    border-radius: 4px;
    transition: width 0.3s;
}}

/* ═══ STATISTICS GRID ═══ */
.stats-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 24px;
}}

.stat-card {{
    background: var(--bg-card);
    border: 1px solid var(--border-subtle);
    border-radius: var(--radius);
    padding: 20px;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s;
}}

.stat-card:hover {{
    transform: translateY(-2px);
    border-color: rgba(6,214,160,0.2);
}}

.stat-number {{
    font-family: 'JetBrains Mono', monospace;
    font-size: 32px;
    font-weight: 700;
    line-height: 1;
    margin-bottom: 6px;
}}

.stat-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-dim);
}}

.stat-card.blue .stat-number {{ color: var(--accent-blue); }}
.stat-card.green .stat-number {{ color: var(--accent-green); }}
.stat-card.red .stat-number {{ color: var(--accent-red); }}
.stat-card.purple .stat-number {{ color: var(--accent-purple); }}
.stat-card.orange .stat-number {{ color: var(--accent-orange); }}
.stat-card.cyan .stat-number {{ color: var(--accent-cyan); }}

/* ═══ NET SECTIONS ═══ */
.net-section {{ margin-bottom: 20px; }}
.net-section h4 {{
    font-size: 14px;
    font-weight: 600;
    margin-bottom: 10px;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 8px;
}}
.net-section .badge {{
    background: var(--bg-elevated);
    color: var(--accent-cyan);
    font-family: 'JetBrains Mono', monospace;
}}

.more {{
    text-align: center;
    color: var(--text-dim) !important;
    font-style: italic;
}}

/* ═══ FOOTER ═══ */
.footer {{
    text-align: center;
    padding: 40px;
    border-top: 1px solid var(--border-subtle);
    color: var(--text-dim);
    font-size: 12px;
}}

.footer-brand {{
    font-weight: 700;
    color: var(--accent-cyan);
    letter-spacing: 2px;
    font-size: 13px;
    margin-bottom: 6px;
}}

/* ═══ PRINT ═══ */
@media print {{
    body {{ background: #fff; color: #111; }}
    .hero {{ background: #f8fafc; }}
    .hero h1 {{ color: #111; -webkit-text-fill-color: #111; }}
    .nav {{ display: none; }}
    .card {{ border: 1px solid #e2e8f0; box-shadow: none; }}
    .data-table thead th {{ background: #f1f5f9; color: #334155; }}
    .section {{ break-inside: avoid; }}
    @page {{ margin: 1.5cm; }}
}}

/* ═══ SCROLLBAR ═══ */
::-webkit-scrollbar {{ width: 8px; height: 8px; }}
::-webkit-scrollbar-track {{ background: var(--bg-primary); }}
::-webkit-scrollbar-thumb {{ background: var(--border); border-radius: 4px; }}
::-webkit-scrollbar-thumb:hover {{ background: var(--accent-cyan); }}
</style>
</head>
<body>

<!-- ═══ HERO ═══ -->
<header class="hero">
    <div class="hero-grid"></div>
    <div class="hero-content">
        <div class="hero-badge">Memory Forensics Analysis Report</div>
        <h1>Memory Forensics Report</h1>
        <p class="hero-subtitle">Automated deep analysis of memory dump artifacts, behavioral indicators, and threat signatures</p>
        <div class="hero-meta">
            <div class="meta-item">
                <div class="meta-label">Case ID</div>
                <div class="meta-value">{esc(case_id)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Generated</div>
                <div class="meta-value">{esc(timestamp)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">File</div>
                <div class="meta-value">{esc(os.path.basename(engine.dump_path or 'N/A'))}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">File Size</div>
                <div class="meta-value">{engine.dump_size:,} bytes ({engine.dump_size/1024/1024:.2f} MB)</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Dump Type</div>
                <div class="meta-value">{esc(dump_type)}</div>
            </div>
            <div class="meta-item">
                <div class="meta-label">Risk Level</div>
                <div class="meta-value" style="color:{rc_main};font-weight:700">{risk_level}</div>
            </div>
        </div>
    </div>
</header>

<!-- ═══ NAV ═══ -->
<nav class="nav">
    <div class="nav-inner">
        <a href="#overview">Overview</a>
        <a href="#risk">Risk Assessment</a>
        <a href="#malware">Malware</a>
        <a href="#behavioral">Behavioral</a>
        <a href="#mitre">MITRE ATT&CK</a>
        <a href="#processes">Processes</a>
        <a href="#dlls">DLLs</a>
        <a href="#network">Network</a>
        <a href="#registry">Registry</a>
        <a href="#entropy">Entropy</a>
        <a href="#hashes">Hashes</a>
    </div>
</nav>

<div class="container">

<!-- ═══ OVERVIEW STATISTICS ═══ -->
<section class="section" id="overview">
    <div class="section-header">
        <div class="section-icon cyan">📊</div>
        <h2 class="section-title">Executive Overview</h2>
    </div>

    <div class="stats-grid">
        <div class="stat-card red">
            <div class="stat-number">{risk_score}</div>
            <div class="stat-label">Risk Score</div>
        </div>
        <div class="stat-card orange">
            <div class="stat-number">{len(malware)}</div>
            <div class="stat-label">Malware Detections</div>
        </div>
        <div class="stat-card purple">
            <div class="stat-number">{len(findings)}</div>
            <div class="stat-label">Behavioral Findings</div>
        </div>
        <div class="stat-card blue">
            <div class="stat-number">{len(processes)}</div>
            <div class="stat-label">Process References</div>
        </div>
        <div class="stat-card red">
            <div class="stat-number">{len(suspicious_procs)}</div>
            <div class="stat-label">Suspicious Processes</div>
        </div>
        <div class="stat-card green">
            <div class="stat-number">{len(dlls)}</div>
            <div class="stat-label">DLL References</div>
        </div>
        <div class="stat-card cyan">
            <div class="stat-number">{len(network.get('ipv4', []))}</div>
            <div class="stat-label">IP Addresses</div>
        </div>
        <div class="stat-card purple">
            <div class="stat-number">{len(network.get('url', []))}</div>
            <div class="stat-label">URLs Found</div>
        </div>
        <div class="stat-card orange">
            <div class="stat-number">{len(network.get('domain', []))}</div>
            <div class="stat-label">Domains</div>
        </div>
        <div class="stat-card blue">
            <div class="stat-number">{len(registry)}</div>
            <div class="stat-label">Registry Keys</div>
        </div>
        <div class="stat-card green">
            <div class="stat-number">{len(file_paths)}</div>
            <div class="stat-label">File Paths</div>
        </div>
        <div class="stat-card red">
            <div class="stat-number">{len(high_entropy)}</div>
            <div class="stat-label">High Entropy Blocks</div>
        </div>
    </div>
</section>

<!-- ═══ RISK ASSESSMENT ═══ -->
<section class="section" id="risk">
    <div class="section-header">
        <div class="section-icon red">⚠️</div>
        <h2 class="section-title">Risk Assessment</h2>
    </div>

    <div class="risk-dashboard">
        <div class="risk-gauge">
            <div class="risk-number">{risk_score}</div>
            <div class="risk-label">Overall Risk Score</div>
            <div class="risk-level">{risk_level}</div>
            <div class="risk-bar"><div class="risk-bar-fill"></div></div>
        </div>
        <div class="card">
            <h3 style="margin-bottom:16px;font-size:16px;color:var(--accent-cyan)">Threat Categories Detected</h3>
            {"".join(f'''
            <div class="finding-card severity-{f['severity'].lower()}">
                <div class="finding-header">
                    <span class="finding-title">{esc(f['category'])}</span>
                    <span class="badge badge-{f['severity'].lower()}">{f['severity']}</span>
                </div>
                <div class="finding-detail">{esc(f['detail'])}</div>
                <div class="indicator-list">
                    {"".join(f'<span class="indicator-tag">{esc(ind)}</span>' for ind in f.get('indicators', f.get('apis', []))[:10])}
                </div>
            </div>''' for f in findings) if findings else '<p style="color:var(--text-dim)">No significant behavioral threat indicators detected.</p>'}
        </div>
    </div>
</section>

<!-- ═══ MALWARE DETECTIONS ═══ -->
<section class="section" id="malware">
    <div class="section-header">
        <div class="section-icon red">🛡️</div>
        <h2 class="section-title">Malware Signature Detections</h2>
        <span class="section-count">{len(malware)} found</span>
    </div>
    {"" if not malware else '''<div class="card"><table class="data-table"><thead><tr>
        <th>Malware Family</th><th>Confidence</th><th>Severity</th><th>Matched</th><th>Patterns</th>
    </tr></thead><tbody>''' +
    "".join(f'''<tr>
        <td style="font-weight:600;color:var(--text-primary)">{esc(m['name'])}</td>
        <td><span class="badge badge-info">{esc(m['confidence'])}</span></td>
        <td><span class="badge badge-{m['severity'].lower()}">{m['severity']}</span></td>
        <td class="mono">{m['matched_signatures']}/{m['total_signatures']}</td>
        <td class="mono" style="font-size:11px">{esc(", ".join(m['matched_patterns'][:5]))}</td>
    </tr>''' for m in malware) +
    '</tbody></table></div>' if malware else '<div class="card"><p style="color:var(--accent-green)">✅ No malware signatures detected in the memory dump.</p></div>'}
</section>

<!-- ═══ BEHAVIORAL ANALYSIS ═══ -->
<section class="section" id="behavioral">
    <div class="section-header">
        <div class="section-icon purple">🧠</div>
        <h2 class="section-title">Behavioral Analysis</h2>
        <span class="section-count">{len(findings)} categories</span>
    </div>
    {("".join(f'''
    <div class="finding-card severity-{f['severity'].lower()}">
        <div class="finding-header">
            <span class="finding-title">{esc(f['category'])}</span>
            <span class="badge badge-{f['severity'].lower()}">{f['severity']}</span>
        </div>
        <div class="finding-detail">{esc(f['detail'])}</div>
        <div class="indicator-list">
            {"".join(f'<span class="indicator-tag">{esc(ind)}</span>' for ind in f.get('indicators', f.get('apis', [])))}
        </div>
    </div>''' for f in findings)) if findings else '<div class="card"><p style="color:var(--accent-green)">✅ No significant behavioral indicators detected.</p></div>'}
</section>

<!-- ═══ MITRE ATT&CK ═══ -->
<section class="section" id="mitre">
    <div class="section-header">
        <div class="section-icon orange">🎯</div>
        <h2 class="section-title">MITRE ATT&CK Mapping</h2>
    </div>
    <div class="mitre-grid">
        {"".join(f'''
        <div class="mitre-card">
            <div class="mitre-id">{mitre_map[f['category']][0]}</div>
            <div class="mitre-info">
                <div class="mitre-technique">{mitre_map[f['category']][1]}</div>
                <div class="mitre-tactic">{mitre_map[f['category']][2]}</div>
            </div>
        </div>''' for f in findings if f['category'] in mitre_map) if findings else '<div class="card"><p style="color:var(--text-dim)">No MITRE ATT&CK techniques mapped.</p></div>'}
    </div>
</section>

<!-- ═══ PROCESSES ═══ -->
<section class="section" id="processes">
    <div class="section-header">
        <div class="section-icon blue">🔄</div>
        <h2 class="section-title">Process Analysis</h2>
        <span class="section-count">{len(processes)} found ({len(suspicious_procs)} suspicious)</span>
    </div>

    {"" if not suspicious_procs else '''
    <div class="card" style="border-left:4px solid var(--accent-red);margin-bottom:16px">
        <h3 style="color:var(--accent-red);margin-bottom:12px">⚠ Suspicious Processes</h3>
        <table class="data-table compact"><thead><tr>
            <th>Offset</th><th>Process Name</th><th>Type</th><th>Status</th>
        </tr></thead><tbody>''' +
    "".join(f'''<tr>
        <td class="mono">{esc(p['offset'])}</td>
        <td style="font-weight:600;color:#fca5a5">{esc(p['name'])}</td>
        <td>{esc(p['type'])}</td>
        <td><span class="badge badge-critical">SUSPICIOUS</span></td>
    </tr>''' for p in suspicious_procs[:100]) +
    '</tbody></table></div>'}

    <div class="card">
        <h3 style="margin-bottom:12px;color:var(--accent-cyan)">All Process References (top 100)</h3>
        <table class="data-table compact"><thead><tr>
            <th>Offset</th><th>Process Name</th><th>Type</th><th>Status</th>
        </tr></thead><tbody>
        {"".join(f'''<tr>
            <td class="mono">{esc(p['offset'])}</td>
            <td style="font-weight:{'600' if p['suspicious'] else '400'};color:{'#fca5a5' if p['suspicious'] else 'var(--text-secondary)'}">{esc(p['name'])}</td>
            <td>{esc(p['type'])}</td>
            <td><span class="badge {'badge-suspicious' if p['suspicious'] else 'badge-clean'}">{"SUSPICIOUS" if p['suspicious'] else "NORMAL"}</span></td>
        </tr>''' for p in processes[:100])}
        </tbody></table>
    </div>
</section>

<!-- ═══ DLLs ═══ -->
<section class="section" id="dlls">
    <div class="section-header">
        <div class="section-icon green">📚</div>
        <h2 class="section-title">DLL / Module Analysis</h2>
        <span class="section-count">{len(dlls)} found ({len(suspicious_dlls)} suspicious)</span>
    </div>
    <div class="card">
        <table class="data-table compact"><thead><tr>
            <th>DLL Name</th><th>Offset</th><th>Status</th>
        </tr></thead><tbody>
        {"".join(f'''<tr>
            <td class="mono" style="color:{'#fca5a5' if d['suspicious'] else 'var(--text-secondary)'}">{esc(d['name'])}</td>
            <td class="mono">{esc(d['offset'])}</td>
            <td><span class="badge {'badge-suspicious' if d['suspicious'] else 'badge-clean'}">{"⚠ SUSPICIOUS" if d['suspicious'] else "Normal"}</span></td>
        </tr>''' for d in dlls[:150])}
        {"<tr><td colspan='3' class='more'>... and " + str(len(dlls)-150) + " more</td></tr>" if len(dlls)>150 else ""}
        </tbody></table>
    </div>
</section>

<!-- ═══ NETWORK ARTIFACTS ═══ -->
<section class="section" id="network">
    <div class="section-header">
        <div class="section-icon cyan">🌐</div>
        <h2 class="section-title">Network Artifacts</h2>
        <span class="section-count">{sum(len(v) for v in network.values())} total</span>
    </div>
    <div class="card">
        {build_network_table(network, 'ipv4', '🔹', 'IPv4 Addresses')}
        {build_network_table(network, 'url', '🔗', 'URLs')}
        {build_network_table(network, 'domain', '🌍', 'Domains')}
        {build_network_table(network, 'email', '📧', 'Email Addresses')}
        {build_network_table(network, 'ipv6', '🔷', 'IPv6 Addresses')}
        {build_network_table(network, 'mac_addr', '🔌', 'MAC Addresses')}
        {"<p style='color:var(--text-dim)'>No network artifacts found.</p>" if not any(network.values()) else ""}
    </div>
</section>

<!-- ═══ REGISTRY ═══ -->
<section class="section" id="registry">
    <div class="section-header">
        <div class="section-icon orange">🔑</div>
        <h2 class="section-title">Registry Key References</h2>
        <span class="section-count">{len(registry)} found</span>
    </div>
    <div class="card">
        <table class="data-table compact"><thead><tr>
            <th>Registry Key</th><th>Persistence Risk</th>
        </tr></thead><tbody>
        {"".join(f'''<tr>
            <td class="mono">{esc(key)}</td>
            <td><span class="badge {'badge-high' if any(x in key.lower() for x in ['run','winlogon','shell']) else 'badge-info'}">
                {"⚠ PERSISTENCE" if any(x in key.lower() for x in ['run','winlogon','shell']) else "Normal"}
            </span></td>
        </tr>''' for key in registry[:100])}
        {"<tr><td colspan='2' class='more'>... and " + str(len(registry)-100) + " more</td></tr>" if len(registry)>100 else ""}
        {"<tr><td colspan='2' style='color:var(--text-dim)'>No registry keys found.</td></tr>" if not registry else ""}
        </tbody></table>
    </div>
</section>

<!-- ═══ ENTROPY ═══ -->
<section class="section" id="entropy">
    <div class="section-header">
        <div class="section-icon purple">📊</div>
        <h2 class="section-title">Entropy Analysis</h2>
        <span class="section-count">{len(high_entropy)} high-entropy blocks</span>
    </div>
    <div class="card">
        <p style="margin-bottom:16px;color:var(--text-secondary);font-size:13px">
            High entropy (>7.0) indicates encrypted or packed data. Showing {"top 50 high-entropy" if high_entropy else "sample"} regions.
        </p>
        <table class="data-table compact"><thead><tr>
            <th>Offset</th><th>Entropy</th><th>Visual</th><th>Classification</th>
        </tr></thead><tbody>
        {"".join(f'''<tr>
            <td class="mono">{esc(e['offset'])}</td>
            <td class="mono" style="color:{'#fca5a5' if e['entropy']>7.0 else '#6ee7b7' if e['entropy']<3.0 else 'var(--text-secondary)'}">{e['entropy']:.4f}</td>
            <td><div class="entropy-bar-container">
                <div class="entropy-bar-bg"><div class="entropy-bar-fg" style="width:{e['entropy']/8*100:.0f}%;background:{'#ef4444' if e['entropy']>7.0 else '#f59e0b' if e['entropy']>5.0 else '#10b981'}"></div></div>
            </div></td>
            <td><span class="badge {'badge-critical' if e['entropy']>7.0 else 'badge-medium' if e['entropy']>5.0 else 'badge-low'}">{esc(e['classification'])}</span></td>
        </tr>''' for e in (high_entropy[:50] if high_entropy else entropy[:30]))}
        </tbody></table>
    </div>
</section>

<!-- ═══ FILE HASHES ═══ -->
<section class="section" id="hashes">
    <div class="section-header">
        <div class="section-icon blue">🔐</div>
        <h2 class="section-title">Cryptographic Hashes</h2>
    </div>
    <div class="card">
        <div class="hash-grid">
            <div class="hash-item">
                <span class="hash-label">MD5</span>
                <span class="hash-value">{esc(hashes.get('MD5', 'N/A'))}</span>
            </div>
            <div class="hash-item">
                <span class="hash-label">SHA1</span>
                <span class="hash-value">{esc(hashes.get('SHA1', 'N/A'))}</span>
            </div>
            <div class="hash-item">
                <span class="hash-label">SHA256</span>
                <span class="hash-value">{esc(hashes.get('SHA256', 'N/A'))}</span>
            </div>
        </div>
    </div>
</section>

</div>

<!-- ═══ FOOTER ═══ -->
<footer class="footer">
    <div class="footer-brand">MEMORY FORENSICS ANALYZER v2.0</div>
    <p>Report generated on {esc(timestamp)} • Case ID: {esc(case_id)}</p>
    <p style="margin-top:8px">This report is auto-generated for forensic investigation purposes.</p>
</footer>

<script>
// Smooth scroll for navigation
document.querySelectorAll('.nav a').forEach(a => {{
    a.addEventListener('click', e => {{
        e.preventDefault();
        const id = a.getAttribute('href').slice(1);
        document.getElementById(id)?.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
    }});
}});

// Animate stats on scroll
const observer = new IntersectionObserver(entries => {{
    entries.forEach(entry => {{
        if (entry.isIntersecting) {{
            entry.target.style.animationDelay = (Array.from(entry.target.parentElement.children).indexOf(entry.target) * 0.05) + 's';
            entry.target.classList.add('visible');
        }}
    }});
}}, {{ threshold: 0.1 }});

document.querySelectorAll('.stat-card, .finding-card, .mitre-card').forEach(el => observer.observe(el));
</script>
</body>
</html>"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report_html)

    return output_path
