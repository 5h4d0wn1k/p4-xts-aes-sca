#!/usr/bin/env python3
"""P4 — XTS-AES CPA Engine: unit tests with key-rank recovery assertion."""
import math
import os
import random
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "firmware"))

from cpa_engine import (
    _SBOX,
    _hw,
    correlation_at_sample,
    compute_intermediate_vectors,
    cpa_attack_single_byte,
    generate_traces,
    leakage_hw_sbox,
    pearson_correlation,
    simulate_trace,
)


class TestSbox(unittest.TestCase):
    def test_sbox_length(self):
        self.assertEqual(len(_SBOX), 256)

    def test_sbox_known_values(self):
        self.assertEqual(_SBOX[0x00], 0x63)
        self.assertEqual(_SBOX[0xFF], 0x16)
        self.assertEqual(_SBOX[0x01], 0x7C)


class TestHammingWeight(unittest.TestCase):
    def test_hw_zero(self):
        self.assertEqual(_hw(0), 0)

    def test_hw_ff(self):
        self.assertEqual(_hw(0xFF), 8)

    def test_hw_one(self):
        self.assertEqual(_hw(0x01), 1)

    def test_hw_8(self):
        self.assertEqual(_hw(0x80), 1)


class TestLeakageModel(unittest.TestCase):
    def test_leakage_range(self):
        for key in range(0, 256, 16):
            for pt in range(0, 256, 16):
                hw = leakage_hw_sbox(key, pt)
                self.assertGreaterEqual(hw, 0)
                self.assertLessEqual(hw, 8)

    def test_deterministic(self):
        self.assertEqual(leakage_hw_sbox(0xA7, 0x42), leakage_hw_sbox(0xA7, 0x42))


class TestSimulateTrace(unittest.TestCase):
    def test_trace_length(self):
        rng = random.Random(0)
        trace = simulate_trace(0xA7, 0x42, rng, snr_db=20.0, n_samples=100)
        self.assertEqual(len(trace), 100)

    def test_deterministic_trace(self):
        t1 = simulate_trace(0xA7, 0x42, random.Random(42), snr_db=20.0, n_samples=50)
        t2 = simulate_trace(0xA7, 0x42, random.Random(42), snr_db=20.0, n_samples=50)
        self.assertEqual(t1, t2)


class TestPearsonCorrelation(unittest.TestCase):
    def test_perfect_positive(self):
        self.assertAlmostEqual(pearson_correlation([1, 2, 3], [2, 4, 6]), 1.0, places=6)

    def test_perfect_negative(self):
        self.assertAlmostEqual(pearson_correlation([1, 2, 3], [3, 2, 1]), -1.0, places=6)

    def test_no_correlation(self):
        self.assertAlmostEqual(pearson_correlation([1, 1, 1], [2, 3, 4]), 0.0, places=6)

    def test_empty(self):
        self.assertEqual(pearson_correlation([], []), 0.0)

    def test_single_element(self):
        self.assertEqual(pearson_correlation([1], [2]), 0.0)


class TestIntermediateVectors(unittest.TestCase):
    def test_vector_length(self):
        pts = [0x00, 0x01, 0x02, 0xFF]
        vecs = compute_intermediate_vectors(pts, 0xA7)
        self.assertEqual(len(vecs), 4)

    def test_vector_values(self):
        pts = [0x00]
        vecs = compute_intermediate_vectors(pts, 0x00)
        expected = _hw(_SBOX[0x00 ^ 0x00])
        self.assertEqual(vecs[0], expected)


class TestCPAKeyRankRecovery(unittest.TestCase):
    """Core test: CPA engine must recover the correct key at rank #1."""

    def test_rank_1_with_30_traces(self):
        secret_key = 0xA7
        rng = random.Random(42)
        traces, plaintexts = generate_traces(secret_key, 30, rng, snr_db=18.0)
        result = cpa_attack_single_byte(traces, plaintexts)
        self.assertEqual(result["correct_key"], secret_key)
        self.assertEqual(result["correct_key_rank"], 1)

    def test_rank_1_with_50_traces(self):
        secret_key = 0x3B
        rng = random.Random(123)
        traces, plaintexts = generate_traces(secret_key, 50, rng, snr_db=20.0)
        result = cpa_attack_single_byte(traces, plaintexts)
        self.assertEqual(result["correct_key"], secret_key)
        self.assertEqual(result["correct_key_rank"], 1)

    def test_high_correlation(self):
        secret_key = 0xA7
        rng = random.Random(42)
        traces, plaintexts = generate_traces(secret_key, 50, rng, snr_db=18.0)
        result = cpa_attack_single_byte(traces, plaintexts)
        self.assertGreater(result["correct_key_corr"], 0.5)

    def test_rank_progression_exists(self):
        secret_key = 0xA7
        rng = random.Random(42)
        traces, plaintexts = generate_traces(secret_key, 40, rng, snr_db=18.0)
        result = cpa_attack_single_byte(traces, plaintexts)
        self.assertGreater(len(result["rank_progression"]), 0)

    def test_different_key_byte(self):
        secret_key = 0x42
        rng = random.Random(99)
        traces, plaintexts = generate_traces(secret_key, 40, rng, snr_db=20.0)
        result = cpa_attack_single_byte(traces, plaintexts)
        self.assertEqual(result["correct_key"], secret_key)
        self.assertEqual(result["correct_key_rank"], 1)

    def test_full_80_trace_run(self):
        """Full regression test matching the documented demo parameters."""
        secret_key = 0xA7
        rng = random.Random(42)
        traces, plaintexts = generate_traces(secret_key, 80, rng, snr_db=18.0)
        result = cpa_attack_single_byte(traces, plaintexts)
        self.assertEqual(result["correct_key"], secret_key)
        self.assertEqual(result["correct_key_rank"], 1)
        self.assertGreater(result["correct_key_corr"], 0.9)


class TestGenerateTraces(unittest.TestCase):
    def test_trace_count(self):
        rng = random.Random(0)
        traces, pts = generate_traces(0xA7, 10, rng)
        self.assertEqual(len(traces), 10)
        self.assertEqual(len(pts), 10)

    def test_plaintext_range(self):
        rng = random.Random(0)
        _, pts = generate_traces(0xA7, 100, rng)
        for pt in pts:
            self.assertGreaterEqual(pt, 0)
            self.assertLessEqual(pt, 255)


if __name__ == "__main__":
    unittest.main()
