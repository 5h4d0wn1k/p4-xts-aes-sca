> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# P4 — XTS-AES Side-Channel CPA Engine

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/p4-xts-aes-sca)
![Last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/p4-xts-aes-sca)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/p4-xts-aes-sca)

Pure-Python **Correlation Power Analysis (CPA)** engine for studying boot-time **XTS-AES flash decryption** on the ESP32-C6 — synthetic power-trace generation, single-key-byte key recovery, and rank-progression analysis, all offline with zero hardware dependencies.

## Why

Modern IoT hardware encrypts storage with modes like **XTS-AES (NIST SP 800-38E)**, but cryptographic strength can leak through physical channels. This project demos how a **side-channel attack** models AES-S-box Hamming-weight leakage and recovers a key byte by correlation, without needing an oscilloscope: traces are simulated with controllable SNR. It is an educational feasibility study for timing/EM leakage measurement — the analysis tooling for the ESP32-C6 flash-decryption research portfolio — gated behind a Phase 0/1/2 go/no-go plan for hardware acquisition in your own lab only.

## Features

- **Stdlib-only CPA core** (`math`, `random`, `csv`) in `firmware/cpa_engine.py`.
- **Deterministic trace simulator** with configurable SNR (no oscilloscope needed).
- **Single-pass Pearson correlation** over all trace samples for each of 256 key candidates.
- **Top-10 ranking** with correct-key marker and **rank-progression curve**.
- **Phase-gated execution plan** (Phase 0 synthetic → Phase 1 calibration → Phase 2 full key recovery).
- **CSV export** of the correlation ranking.

## Quickstart

```bash
# Run the full offline self-test (synthetic traces, known key byte)
python3 run_demo.py

# Print rank of a known key byte (fast, ~10 traces)
python3 run_demo.py rank

# Custom key byte, trace count, SNR
python3 run_demo.py rank --key 0x42 --traces 50 --snr 20.0

# Show all CLI options
python3 run_demo.py --help
```

Programmatic use (bundled in the same directory as `firmware/cpa_engine.py`):

```python
from cpa_engine import generate_traces, cpa_attack_single_byte

rng = random.Random(42)
traces, plaintexts = generate_traces(0xA7, 80, rng, snr_db=18.0)
result = cpa_attack_single_byte(traces, plaintexts)
print(result["correct_key_rank"])
```

```bash
# Run unit tests (include key-rank recovery assertions)
python3 -m unittest discover -s tests -v
```

## Project structure

```
p4-xts-aes-sca/
├── firmware/cpa_engine.py  # CPA attack + trace simulator (stdlib)
├── papers/references.md    # side-channel references
├── run_demo.py             # offline demo & rank CLI
├── tests/                  # unittest suite
└── ETHICS.md, SCOPE.md     # authorized-use rules
```

## Documentation

- [ETHICS.md](ETHICS.md) — authorized-use policy
- [SCOPE.md](SCOPE.md) — lab scope
- [SECURITY.md](SECURITY.md) — security policy
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide
- [papers/references.md](papers/references.md) — references

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). This is a research tool for authorized lab work only.

## License

MIT. See [LICENSE](LICENSE).