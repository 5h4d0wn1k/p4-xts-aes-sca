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
pip3 install numpy scipy   # optional; full-speed path only
```

The engine runs on the Python standard library alone.

## Usage

```bash
# Run the offline self-test (synthetic traces, known key byte)
python3 firmware/cpa_engine.py

# Import the engine in your own measurement pipeline
from firmware.cpa_engine import generate_traces, cpa_attack_single_byte
```

## Example Output

```
[*] Generating 80 synthetic power traces (SNR=18.0 dB, key=0xA7)...
[*] Running CPA attack (256 candidates x 200 samples)...

  P4 — XTS-AES Flash-Encryption CPA Engine  |  Single-Byte Demo
  Traces analysed  : 80
  True key byte    : 0xA7 (167)
  Recovered key    : 0xA7 (167)
  Rank of true key : #1
  Max |correlation|: 0.892476

  Top-10 key candidates by |correlation|:
  Rank   Key   |corr|
  ----   ---   ------
  1    0xA7   0.892476 <-- correct
  ...
  Rank progression (traces vs rank of true key):
      Traces    Rank
          10      1
          ...
          80      1
```

## Research Framing

This is the analysis tooling for the **P4** research portfolio item (ESP32-C6 XTS-AES flash-encryption side channel). The software engine, leakage model, and CPA core are fully exercised offline here. Hardware trace acquisition (shunt resistor + oscilloscope >= 100 MS/s, 2ch, GPIO trigger) and the Phase 0/1/2 campaign are run separately once the lab rig is available. A second devkit is held in reserve for key recovery if the first becomes unresponsive.

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