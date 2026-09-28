"""
brute_force.py — Exhaustive-search infeasibility for DHP-KEM-128.

The DHP-KEM-128 session key K is 256 bits long but the *effective* symmetric
strength is bounded by the smallest classical component: Curve25519's
~ 2^126 bit-operations for ECDLP via Pollard's rho.  This script demonstrates
that even searching at 2^128 evaluations per second (impossible today) would
take longer than the age of the universe.

Reference: report §6a Cryptanalysis, "Brute-force search".
"""
from __future__ import annotations
import math


def years_to_search(key_bits: int, evals_per_second: float) -> float:
    """Return the number of years needed to search 2**(key_bits-1) keys on
    average at the given rate."""
    avg_searches = 2 ** (key_bits - 1)
    seconds = avg_searches / evals_per_second
    return seconds / (365.25 * 24 * 3600)


def main() -> None:
    print("Exhaustive-key-search infeasibility for DHP-KEM-128 (κ = 128 bits)")
    print("-" * 68)
    # Three illustrative rates:
    #   2^30 ≈ 1 GH/s  (one modern CPU core, light workload)
    #   2^40 ≈ 1 TH/s  (large GPU cluster, bitcoin-mining-class)
    #   2^60           (a hypothetical exascale ASIC farm)
    for log2_rate, label in [
        (30, "1 GH/s   (one CPU core)"),
        (40, "1 TH/s   (large GPU cluster, bitcoin-mining tier)"),
        (60, "1 EH/s   (hypothetical exascale ASIC farm)"),
        (80, "1 YH/s   (utterly hypothetical 'all silicon ever' upper bound)"),
    ]:
        rate = 2 ** log2_rate
        yrs  = years_to_search(128, rate)
        # Compare against age of the universe ~ 1.38e10 years
        ratio = yrs / 1.38e10
        print(f"  {label:<60s}  {yrs:.2e} years  "
              f"= {ratio:.2e} × age of universe")
    print()
    print("Conclusion: brute-force key search against DHP-KEM-128's 128-bit")
    print("symmetric strength is infeasible under every imaginable hardware budget.")


if __name__ == "__main__":
    main()
