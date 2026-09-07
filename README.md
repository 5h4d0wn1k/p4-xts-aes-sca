# P4 — XTS-AES Side-Channel CPA Engine

Correlation Power Analysis (CPA) engine for studying boot-time XTS-AES flash decryption on the ESP32-C6.

## Overview

This project implements a complete single-key-byte CPA engine in pure Python to support a feasibility-grade side-channel study of XTS-AES flash decryption (see `RESEARCH_PORTFOLIO.md` in the wireless-security-toolkit docs). It:

- Models the AES-128 leakage (Hamming weight of the SubBytes output) for a target key byte
- Simulates synthetic power traces with controllable SNR (no oscilloscope/hardware required)
- Runs a full CPA attack ranking all 256 key candidates by absolute Pearson correlation
- Reports the rank progression (how many traces are needed to recover the correct key byte)
- Gates the real-hardware effort behind a Phase 0/1/2 go/no-go execution plan
- Exports the correlation ranking to CSV

## Features

- Standard-library-only implementation (`math`, `random`, `csv`, `time`, `os`, `sys`)
- Deterministic trace simulator with configurable SNR
- Single-pass correlation over all trace samples for each key candidate
- Top-10 key-candidate ranking with "correct key" marker
- Rank-progression curve (traces vs rank of true key)
- Phase-gated execution plan for the hardware acquisition campaign
- Offline self-test that verifies correct key recovery at rank #1

## Installation

```bash
cd p4-xts-aes-sca
# No external dependencies required — pure Python stdlib
python3 run_demo.py
```

## Usage

```bash
# Run the full offline self-test (synthetic traces, known key byte)
python3 run_demo.py

# Print rank of known key byte (fast, ~10 traces)
python3 run_demo.py rank

# Custom key byte, trace count, SNR
python3 run_demo.py rank --key 0x42 --traces 50 --snr 20.0

# Show all CLI options
python3 run_demo.py --help
python3 run_demo.py rank --help

# Run unit tests (includes key-rank recovery assertions)
python3 -m unittest discover -s tests -v
```

Programmatic use:

```python
from cpa_engine import generate_traces, cpa_attack_single_byte

rng = random.Random(42)
traces, plaintexts = generate_traces(0xA7, 80, rng, snr_db=18.0)
result = cpa_attack_single_byte(traces, plaintexts)
print(f"Rank: {result['correct_key_rank']}, Key: 0x{result['correct_key']:02X}")
```

## Mathematical Background

### CPA Leakage Model

The attack targets the AES SubBytes output during round 1. For a single key byte $k$ and known plaintext byte $p$:

$$\ell = \mathrm{HW}(\mathrm{SBOX}[k \oplus p])$$

where $\mathrm{HW}$ is the Hamming weight (number of set bits) and $\mathrm{SBOX}$ is the AES S-box. This models the dominant data-dependent switching activity on the power rail during SubBytes + ShiftRows.

### Correlation Attack

For each candidate key $k' \in \{0, \ldots, 255\}$, compute predicted leakage:

$$h_{k'} = \mathrm{HW}(\mathrm{SBOX}[k' \oplus p_i]) \quad \forall i$$

Then compute the Pearson correlation between $h_{k'}$ and measured power samples across all traces:

$$r_{k', j} = \frac{\sum_i (h_{k', i} - \bar{h})(t_{i,j} - \bar{t}_j)}{\sqrt{\sum_i (h_{k', i} - \bar{h})^2 \cdot \sum_i (t_{i,j} - \bar{t}_j)^2}}$$

where $t_{i,j}$ is sample $j$ of trace $i$. The key candidate with the highest $|r|$ at any sample point is the recovered key.

### Rank Recovery

The CPA output ranks all 256 candidates by $|r|_{\max}$. When the correct key $k$ has $|r|_{\max}$ higher than all incorrect candidates, it is "recovered at rank #1". The engine asserts this as the success criterion.

### XTS-AES Context

XTS-AES (NIST SP 800-38E) is a tweakable block cipher mode for storage encryption. On the ESP32-C6, the boot-time flash decryption uses XTS-AES-128. The side-channel target is the first AES-128 block operation during the XTS decryption, where the S-box output leakage is most visible.

## Example Output

```
[*] Generating 80 synthetic power traces (SNR=18.0 dB, key=0xA7)...
[*] Running CPA attack (256 candidates x 500 samples)...

  P4 — XTS-AES Flash-Encryption CPA Engine  |  Single-Byte Demo
  Traces analysed  : 80
  True key byte    : 0xA7 (167)
  Recovered key    : 0xA7 (167)
  Rank of true key : #1
  Max |correlation|: 0.997319

  Top-10 key candidates by |correlation|:
  Rank   Key   |corr|
  ----   ---   ------
  1    0xA7   0.997319 <-- correct
  ...

  [PASS] Correct key byte recovered at rank #1.
```

## Research Framing

This is the analysis tooling for the **P4** research portfolio item (ESP32-C6 XTS-AES flash-encryption side channel). The software engine, leakage model, and CPA core are fully exercised offline here. Hardware trace acquisition (shunt resistor + oscilloscope >= 100 MS/s, 2ch, GPIO trigger) and the Phase 0/1/2 campaign are run separately once the lab rig is available. A second devkit is held in reserve for key recovery if the first becomes unresponsive.

## Live Lab Test Plan

| Phase | Description | Go / No-Go Criteria | Status |
|-------|-------------|---------------------|--------|
| Phase 0 | Synthetic-trace CPA (this tool) | Key recovered at rank #1, \|corr\| > 0.5 | DONE |
| Phase 1 | Hardware calibration | Measured SNR > 10 dB, CPA recovers known calibration key | PENDING |
| Phase 2 | Full 16-byte key recovery | All 16 bytes recovered, XTS-AES decryption succeeds | PENDING |

## Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Key recovery (synthetic) | Rank #1 | Rank #1 |
| Max correlation (80 traces) | > 0.9 | 0.997 |
| Test pass rate | 100% | 100% |
| Demo exit code | 0 | 0 |
| Rank recovery traces needed | < 20 | 10 |

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the device owner before performing side-channel measurements
- Use only on devices you own or have explicit authorization to test
- This tool is designed for research on your own lab hardware only

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Export/Import Controls**: Cryptography and side-channel tooling may be subject to export regulations (EAR)
- **State Laws**: Many states have additional computer crime and data-protection statutes

### Acceptable Use
- Research on devices you own (authorized lab bench)
- Academic side-channel research in controlled lab environments
- Security education and training
- Funding open trace corpora for reproducible research

### Prohibited Use
- Measuring or extracting keys from devices you do not own
- Attacks on infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial deployment without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
