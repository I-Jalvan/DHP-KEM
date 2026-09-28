"""
bench.py
========

Microbenchmarks for the DHP-KEM reference implementation.

Reports median, mean, and stddev wall-clock times (in milliseconds) for
KeyGen, Encap, and Decap, across the two implemented parameter sets.
Numbers are intended for illustrative comparison only; absolute speeds
are dominated by pure-Python ML-KEM, NOT by the DHP-KEM combiner or
transcript-hash logic.

A C / Rust / Go implementation using a constant-time ML-KEM library
would be approximately 100-1000x faster on the post-quantum component.

Usage
-----
    cd code/
    python -m benchmarks.bench           # default: 100 iterations per op
    python -m benchmarks.bench --iters 500
"""
import argparse
import statistics
import time

import dhp_kem


def bench_one(label: str, fn, iters: int) -> dict:
    """Time `fn` `iters` times and return summary statistics."""
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - t0) * 1000.0)  # ms
    return {
        "op":       label,
        "iters":    iters,
        "median_ms": statistics.median(samples),
        "mean_ms":   statistics.mean(samples),
        "stddev_ms": statistics.stdev(samples) if iters > 1 else 0.0,
    }


def run_for(ps_name: str, iters: int):
    """Benchmark KeyGen / Encap / Decap for one parameter set."""
    ps = dhp_kem.get(ps_name)
    print(f"\n=== {ps_name}  ({ps.classical_curve} + {ps.mlkem_variant.value}) ===")
    print(f"  Hash:  {ps.hash_name}     Tier:  {ps.nca_tier}     |K|: {ps.L}")

    # KeyGen
    kg = bench_one("KeyGen", lambda: dhp_kem.keygen(ps), iters)

    # Encap (needs a public key — generate ONE and reuse)
    kp = dhp_kem.keygen(ps)
    enc = bench_one("Encap",  lambda: dhp_kem.encap(ps, kp.pk), iters)

    # Decap (needs a fresh ciphertext each time, otherwise the result is cached
    # at the C level by ML-KEM; we generate one per iteration outside the timer)
    ciphertexts = [dhp_kem.encap(ps, kp.pk)[0] for _ in range(iters)]
    decap_iter = iter(ciphertexts)
    dec = bench_one("Decap",
                    lambda: dhp_kem.decap(ps, kp.sk, next(decap_iter)),
                    iters)

    for row in (kg, enc, dec):
        print(f"  {row['op']:<8s} median={row['median_ms']:8.3f} ms   "
              f"mean={row['mean_ms']:8.3f} ms   "
              f"stddev={row['stddev_ms']:7.3f} ms")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=100,
                    help="iterations per measurement (default 100)")
    args = ap.parse_args()
    print("DHP-KEM microbenchmarks  (pure-Python reference implementation)")
    print(f"Iterations per measurement: {args.iters}")
    run_for("DHP-KEM-128", args.iters)
    run_for("DHP-KEM-256", args.iters)
    print()
    print("NOTE: these timings reflect a pure-Python ML-KEM library and are")
    print("approximately 100-1000x slower than an optimised constant-time")
    print("C/Rust/Go implementation.")
