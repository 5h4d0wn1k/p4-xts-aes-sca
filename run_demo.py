#!/usr/bin/env python3
"""P4 — CLI for XTS-AES CPA Engine.

Subcommands:
    demo    Run full offline demo (default)
    rank    Print rank of known key byte and exit
"""
import argparse
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "firmware"))


def _run_rank(args):
    from cpa_engine import cpa_attack_single_byte, generate_traces

    secret_key_byte = args.key
    n_traces = args.traces
    snr_db = args.snr
    seed = args.seed

    rng = random.Random(seed)
    traces, plaintexts = generate_traces(secret_key_byte, n_traces, rng, snr_db=snr_db)
    result = cpa_attack_single_byte(traces, plaintexts)

    rank = result["correct_key_rank"]
    recovered = result["correct_key"]
    corr = result["correct_key_corr"]

    print(f"key_byte=0x{secret_key_byte:02X}")
    print(f"recovered=0x{recovered:02X}")
    print(f"rank={rank}")
    print(f"correlation={corr:.6f}")
    return 0 if rank == 1 else 1


def _run_demo(args):
    from cpa_engine import main as cpa_main
    cpa_main()
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="cpa_cli",
        description="P4 — XTS-AES Flash-Encryption CPA Engine CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # demo (default)
    sub.add_parser("demo", help="Run full offline CPA demo")

    # rank
    rank_p = sub.add_parser("rank", help="Print rank of known key byte")
    rank_p.add_argument("--key", type=lambda x: int(x, 0), default=0xA7,
                        help="Known secret key byte (default: 0xA7)")
    rank_p.add_argument("--traces", type=int, default=80,
                        help="Number of synthetic traces (default: 80)")
    rank_p.add_argument("--snr", type=float, default=18.0,
                        help="Signal-to-noise ratio in dB (default: 18.0)")
    rank_p.add_argument("--seed", type=int, default=42,
                        help="RNG seed (default: 42)")

    args = parser.parse_args()

    if args.command == "rank":
        sys.exit(_run_rank(args))
    else:
        sys.exit(_run_demo(args))


if __name__ == "__main__":
    main()
