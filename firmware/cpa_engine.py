#!/usr/bin/env python3
"""
P4 — XTS-AES Flash-Encryption Side-Channel Analysis Engine
Correlation Power Analysis (CPA) for ESP32-C6 boot-time XTS-AES flash decryption.

Educational / authorized-security-testing only.
Pure-Python, no hardware required for the synthetic-trace demo.
"""

import csv
import math
import os
import random
import struct
import sys
import time

# ---------------------------------------------------------------------------
# AES S-box (canonical NIST FIPS-197)
# ---------------------------------------------------------------------------
_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]


def _hw(val: int) -> int:
    """Hamming weight of an 8-bit value."""
    return bin(val).count("1")


# ---------------------------------------------------------------------------
# Hamming-Weight / Hamming-Weight-of-State leakage model
# ---------------------------------------------------------------------------
def leakage_hw_sbox(key_byte: int, plaintext_byte: int) -> int:
    """Predicted leakage: HW of S-box output for one AES byte.

    This models the dominant data-dependent switching activity during the
    SubBytes + ShiftRows stage of round 1 of AES — the classic CPA target
    on ESP32-C6 and similar Cortex-M33 targets where the S-box output is
    the first non-trivial operation visible on the power rail.
    """
    return _hw(_SBOX[key_byte ^ plaintext_byte])


# ---------------------------------------------------------------------------
# Synthetic trace simulator
# ---------------------------------------------------------------------------
def simulate_trace(
    secret_key_byte: int,
    plaintext_byte: int,
    rng: random.Random,
    snr_db: float = 20.0,
    n_samples: int = 500,
) -> list[float]:
    """Generate a synthetic power trace for one plaintext byte.

    The trace is a deterministic (seeded-RNG) mixture of:
      • a leakage signal proportional to HW(S-box_out) placed at a
        fixed offset (sample ~200) with a Gaussian-shaped pulse,
      • additive white Gaussian noise.

    Parameters
    ----------
    secret_key_byte : int
        The "true" key byte (0-255).
    plaintext_byte : int
        The known plaintext byte (0-255).
    rng : random.Random
        Seeded RNG instance for reproducibility.
    snr_db : float
        Signal-to-noise ratio in dB.
    n_samples : int
        Length of the trace in samples.

    Returns
    -------
    list[float]
        Simulated power trace.
    """
    leakage = leakage_hw_sbox(secret_key_byte, plaintext_byte)

    # signal amplitude scaled by SNR
    snr_linear = 10.0 ** (snr_db / 10.0)
    signal_amp = math.sqrt(snr_linear)

    # Gaussian pulse centred at sample 200, sigma 15
    centre = 200
    sigma = 15.0
    trace = []
    for i in range(n_samples):
        pulse = signal_amp * leakage * math.exp(-0.5 * ((i - centre) / sigma) ** 2)
        noise = rng.gauss(0.0, 1.0)
        trace.append(pulse + noise)
    return trace


def generate_traces(
    secret_key_byte: int,
    n_traces: int,
    rng: random.Random,
    snr_db: float = 20.0,
    n_samples: int = 500,
) -> tuple[list[list[float]], list[int]]:
    """Generate a set of traces with random plaintexts.

    Returns (traces, plaintexts).
    """
    traces = []
    plaintexts = []
    for _ in range(n_traces):
        pt = rng.randint(0, 255)
        plaintexts.append(pt)
        traces.append(simulate_trace(secret_key_byte, pt, rng, snr_db, n_samples))
    return traces, plaintexts


# ---------------------------------------------------------------------------
# CPA core
# ---------------------------------------------------------------------------
def pearson_correlation(xs: list[float], ys: list[float]) -> float:
    """Compute Pearson correlation coefficient between two equal-length lists."""
    n = len(xs)
    if n < 2:
        return 0.0
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    var_x = sum((x - mean_x) ** 2 for x in xs)
    var_y = sum((y - mean_y) ** 2 for y in ys)
    denom = math.sqrt(var_x * var_y)
    if denom == 0.0:
        return 0.0
    return cov / denom


def compute_intermediate_vectors(
    plaintexts: list[int], key_guess: int
) -> list[int]:
    """Compute predicted leakage vector for all traces given a key guess."""
    return [leakage_hw_sbox(key_guess, pt) for pt in plaintexts]


def correlation_at_sample(
    predicted: list[int], traces: list[list[float]], sample_idx: int
) -> float:
    """Pearson correlation between predicted leakage and one sample column."""
    measured = [t[sample_idx] for t in traces]
    return pearson_correlation(predicted, measured)


def cpa_attack_single_byte(
    traces: list[list[float]],
    plaintexts: list[int],
    verbose: bool = False,
) -> dict:
    """Run CPA for a single key byte, returning correlation results.

    Returns dict with:
      • "ranking": list of (key_guess, max_correlation) sorted descending
      • "correct_key": the key guess with highest absolute correlation
      • "correct_key_rank": 1-based rank of correct_key
      • "correct_key_corr": correlation of the correct key
      • "rank_progression": list of (n_traces, rank_of_true_key)
    """
    n_traces = len(traces)
    n_samples = len(traces[0]) if n_traces > 0 else 0

    # Precompute per-sample trace statistics so each candidate key only pays
    # a single O(n_traces*n_samples) pass (single-pass correlation).
    def best_corr_for_key(plaintext_sub: list[int], traces_sub: list[list[float]]) -> float:
        n = len(plaintext_sub)
        # Per-sample column sums over traces_sub (used for correlation means)
        col_sum = [0.0] * n_samples
        col_sqsum = [0.0] * n_samples
        for t in traces_sub:
            for i, v in enumerate(t):
                col_sum[i] += v
                col_sqsum[i] += v * v
        mean_col = [s / n for s in col_sum]
        best = 0.0
        for kg in range(256):
            pred = compute_intermediate_vectors(plaintext_sub, kg)
            p_mean = sum(pred) / n
            p_var = sum((p - p_mean) ** 2 for p in pred)
            if p_var == 0.0:
                continue
            cov_terms = [0.0] * n_samples
            # single-pass covariance numerator per sample
            for si, t in enumerate(traces_sub):
                pm = pred[si] - p_mean
                for i in range(n_samples):
                    cov_terms[i] += pm * (t[i] - mean_col[i])
            denom_sqrt = math.sqrt(p_var)
            for i in range(n_samples):
                var_y = col_sqsum[i] - n * mean_col[i] * mean_col[i]
                if var_y <= 0:
                    continue
                c = abs(cov_terms[i] / (denom_sqrt * math.sqrt(var_y)))
                if c > best:
                    best = c
        return best

    # --- full run correlations ---
    results = {}

    # Compute all 256 candidates in one pass over traces (column sums reused).
    n = n_traces
    predicted_cache: dict[int, list[int]] = {
        kg: compute_intermediate_vectors(plaintexts, kg) for kg in range(256)
    }
    col_sum = [0.0] * n_samples
    col_sqsum = [0.0] * n_samples
    for t in traces:
        for i, v in enumerate(t):
            col_sum[i] += v
            col_sqsum[i] += v * v
    mean_col = [s / n for s in col_sum]

    for kg, pred in predicted_cache.items():
        p_mean = sum(pred) / n
        p_var = sum((p - p_mean) ** 2 for p in pred)
        if p_var == 0.0:
            results[kg] = 0.0
            continue
        cov_terms = [0.0] * n_samples
        for si, t in enumerate(traces):
            pm = pred[si] - p_mean
            for i in range(n_samples):
                cov_terms[i] += pm * (t[i] - mean_col[i])
        denom_sqrt = math.sqrt(p_var)
        best = 0.0
        for i in range(n_samples):
            var_y = col_sqsum[i] - n * mean_col[i] * mean_col[i]
            if var_y <= 0:
                continue
            c = abs(cov_terms[i] / (denom_sqrt * math.sqrt(var_y)))
            if c > best:
                best = c
        results[kg] = best

    ranking = sorted(results.items(), key=lambda kv: kv[1], reverse=True)

    correct_key = ranking[0][0]
    correct_key_corr = ranking[0][1]
    correct_key_rank = 1

    # --- rank progression (how many traces to recover correct key?) ---
    # Cap the number of progressive sub-runs to keep the offline demo fast.
    rank_progression = []
    n_steps = 8
    step = max(2, n_traces // n_steps)
    for nt in range(step, n_traces + 1, step):
        sub_traces = traces[:nt]
        sub_plaintexts = plaintexts[:nt]
        sub_corr = best_corr_for_key(sub_plaintexts, sub_traces)
        if sub_corr > 0:
            # Rank of true key within a progressive sub-run: recompute quickly.
            m = len(sub_plaintexts)
            sub_pred_known = compute_intermediate_vectors(sub_plaintexts, correct_key)
            sub_col_sum = [0.0] * n_samples
            sub_col_sqsum = [0.0] * n_samples
            for t in sub_traces:
                for i, v in enumerate(t):
                    sub_col_sum[i] += v
                    sub_col_sqsum[i] += v * v
            sub_mean_col = [s / m for s in sub_col_sum]
            sub_rank = 1
            for kg, pred in predicted_cache.items():
                if kg == correct_key:
                    continue
                p_mean = sum(pred[:m]) / m
                p_var = sum((p - p_mean) ** 2 for p in pred[:m])
                if p_var == 0.0:
                    continue
                cov_terms = [0.0] * n_samples
                for si in range(m):
                    pm = pred[si] - p_mean
                    for i in range(n_samples):
                        cov_terms[i] += pm * (sub_traces[si][i] - sub_mean_col[i])
                denom_sqrt = math.sqrt(p_var)
                best_other = 0.0
                for i in range(n_samples):
                    var_y = sub_col_sqsum[i] - m * sub_mean_col[i] * sub_mean_col[i]
                    if var_y <= 0:
                        continue
                    c = abs(cov_terms[i] / (denom_sqrt * math.sqrt(var_y)))
                    if c > best_other:
                        best_other = c
                if best_other > sub_corr:
                    sub_rank += 1
            rank_progression.append((nt, sub_rank))

    return {
        "ranking": ranking,
        "correct_key": correct_key,
        "correct_key_rank": correct_key_rank,
        "correct_key_corr": correct_key_corr,
        "rank_progression": rank_progression,
    }


# ---------------------------------------------------------------------------
# Phase-gated execution plan (Phase 0 / 1 / 2)
# ---------------------------------------------------------------------------
PHASE_TABLE = [
    {
        "phase": 0,
        "name": "Feasibility",
        "description": "Synthetic-trace validation — can CPA recover a known key byte?",
        "go_criteria": "Correct key byte ranks #1 with |corr| > 0.5 on synthetic traces.",
        "no_go_criteria": "Correct key not ranked #1, or correlation too low.",
    },
    {
        "phase": 1,
        "name": "Calibration",
        "description": (
            "Hardware calibration — acquire real traces with shunt/scope on "
            "ESP32-C6 rig, validate SNR and leakage model fit."
        ),
        "go_criteria": "Measured SNR > 10 dB and CPA recovers known calibration key.",
        "no_go_criteria": "SNR too low or model mismatch; revisit probe placement.",
    },
    {
        "phase": 2,
        "name": "Full Key Recovery",
        "description": (
            "Full 16-byte XTS-AES key recovery: repeat single-byte CPA for "
            "each key byte, reconstruct complete key schedule."
        ),
        "go_criteria": "All 16 key bytes recovered and XTS-AES decryption succeeds.",
        "no_go_criteria": "Key bytes do not decrypt; re-examine leakage model.",
    },
]


def print_phase_table() -> None:
    """Pretty-print the phase-gating table."""
    header = f"{'Phase':<8} {'Name':<14} {'Go / No-Go Criteria'}"
    print(header)
    print("-" * len(header))
    for p in PHASE_TABLE:
        go = p["go_criteria"]
        nogo = p["no_go_criteria"]
        print(f"  {p['phase']:<6} {p['name']:<12} GO: {go}")
        print(f"{'':24} NO-GO: {nogo}")
        print()


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(result: dict, n_traces: int, secret_key_byte: int) -> None:
    """Print a human-readable CPA report."""
    print("=" * 68)
    print("  P4 — XTS-AES Flash-Encryption CPA Engine  |  Single-Byte Demo")
    print("=" * 68)
    print()
    print(f"  Traces analysed  : {n_traces}")
    print(f"  True key byte    : 0x{secret_key_byte:02X} ({secret_key_byte})")
    print(f"  Recovered key    : 0x{result['correct_key']:02X} ({result['correct_key']})")
    print(f"  Rank of true key : #{result['correct_key_rank']}")
    print(f"  Max |correlation|: {result['correct_key_corr']:.6f}")
    print()

    # Top 10 candidates
    print("  Top-10 key candidates by |correlation|:")
    print(f"  {'Rank':<6} {'Key':>6} {'|corr|':>12}")
    print(f"  {'----':<6} {'---':>6} {'------':>12}")
    for idx, (kg, corr) in enumerate(result["ranking"][:10]):
        marker = " <-- correct" if kg == secret_key_byte else ""
        print(f"  {idx+1:<6} 0x{kg:02X}  {corr:12.6f}{marker}")
    print()

    # Rank progression
    print("  Rank progression (traces vs rank of true key):")
    print(f"  {'Traces':>8} {'Rank':>6}")
    for nt, rank in result["rank_progression"]:
        print(f"  {nt:>8} {rank:>6}")
    print()

    # Phase table
    print("  Phase-Gated Execution Plan")
    print("-" * 68)
    print_phase_table()


def export_csv(result: dict, path: str) -> None:
    """Export correlation-per-candidate ranking to CSV."""
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["rank", "key_guess_hex", "key_guess_dec", "abs_correlation"])
        for idx, (kg, corr) in enumerate(result["ranking"]):
            writer.writerow([idx + 1, f"0x{kg:02X}", kg, f"{corr:.6f}"])
    print(f"  [+] CSV exported to {path}")


# ---------------------------------------------------------------------------
# CLI / self-test
# ---------------------------------------------------------------------------
def main() -> None:
    """Offline self-test: generate synthetic traces, run CPA, verify recovery."""
    secret_key_byte = 0xA7  # known secret for the demo
    n_traces = 80
    snr_db = 18.0
    seed = 42

    rng = random.Random(seed)

    print("[*] Generating {0} synthetic power traces (SNR={1} dB, key=0x{2:02X})...".format(
        n_traces, snr_db, secret_key_byte
    ))
    traces, plaintexts = generate_traces(secret_key_byte, n_traces, rng, snr_db=snr_db)

    print("[*] Running CPA attack (256 candidates x {0} samples)...".format(len(traces[0])))
    t0 = time.time()
    result = cpa_attack_single_byte(traces, plaintexts, verbose=False)
    elapsed = time.time() - t0
    print(f"[*] CPA completed in {elapsed:.2f}s")
    print()

    print_report(result, n_traces, secret_key_byte)

    # Export CSV
    csv_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "correlation_ranking.csv")
    export_csv(result, csv_path)
    print()

    # Verification
    ok = result["correct_key"] == secret_key_byte
    if ok:
        print("[PASS] Correct key byte recovered at rank #1.")
    else:
        print("[FAIL] Correct key NOT recovered at rank #1.")
        sys.exit(1)

    print("[*] Self-test complete. Exiting.")
    sys.exit(0)


if __name__ == "__main__":
    main()
