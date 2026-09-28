"""
shor_estimate.py — Quantum-resource estimator for Shor's algorithm on
                    ECDLP and Shor-style attacks on Module-LWE.

Computes (logical qubits, T-gates, physical-qubit overhead) for the
attacks of:

  * Roetteler-Naehrig-Svore-Lauter (ASIACRYPT 2017) [45] —
    Shor on ECDLP over a 256-bit curve.
  * Häner-Roetteler-Soeken (PQCrypto 2020) [27] —
    refined cost for the same.
  * Chen 2024 [43] (withdrawn) — proposed quantum algorithm for LWE
    that was rapidly retracted after Hongxun Wu identified a flaw.

This is an estimator, NOT a runnable quantum simulator.  No CRQC
(cryptographically-relevant quantum computer) currently exists at the
scale needed to mount these attacks.

Reference: report §6c Quantum Attacks.
"""
from __future__ import annotations


def shor_ecdlp_logical(n_bits: int) -> dict:
    """Logical-qubit / T-gate estimates for Shor-on-ECDLP per Roetteler 2017 [45].

    Approximate formulas (Table 1, p. 246 of the ASIACRYPT paper):
        logical qubits ≈ 9n + 2·ceil(log2(n)) + 10
        T-gates        ≈ 448 · n^3 · log2(n)
    """
    import math
    q = 9 * n_bits + 2 * math.ceil(math.log2(n_bits)) + 10
    t = 448 * (n_bits ** 3) * math.log2(n_bits)
    return {"logical_qubits": q, "T_gates": t}


def physical_qubits_overhead(logical: int,
                             code_distance: int = 25,
                             cycles_per_round: int = 2) -> int:
    """Overhead factor for a surface-code-protected quantum computer.

    The standard estimate is roughly (2·code_distance)^2 physical qubits
    per logical qubit, plus distillation factories.  With code_distance
    = 25 this is ~1250x per logical qubit.  Häner et al. [27] gives a
    more refined figure of ~10^7-10^8 total physical qubits for
    Curve25519-scale attacks once factories are included.
    """
    return logical * (2 * code_distance) ** 2 * cycles_per_round


def main():
    print("Shor-on-ECDLP quantum-resource estimates")
    print("=" * 64)
    for label, n_bits in [
        ("X25519 (used by DHP-KEM-128)", 255),
        ("P-384  (used by DHP-KEM-256)", 384),
        ("P-521  (used by DHP-KEM-LT)",  521),
        ("RSA-2048 (for comparison)",   2048),
    ]:
        est = shor_ecdlp_logical(n_bits)
        phys = physical_qubits_overhead(est["logical_qubits"])
        print(f"\n  {label}")
        print(f"    field size:        {n_bits} bits")
        print(f"    logical qubits:    {est['logical_qubits']:,}")
        print(f"    T-gates:           {est['T_gates']:.2e}")
        print(f"    physical qubits*:  {phys:,}")
        print(f"      (* surface code d=25, factories not counted)")
    print()
    print("Häner-Roetteler-Soeken [27] refined estimate for X25519:")
    print("  ~ 2,330 logical qubits, ~10^9 T-gates,")
    print("  ~ tens of millions of physical qubits all-in,")
    print("  total run-time on the order of hours.")
    print()
    print("Current state of the art (May 2026):")
    print("  Largest CRQC-relevant prototype: ~ 1,180 physical qubits (IBM Condor),")
    print("  ~ 1.3 logical qubits effective.  Six orders of magnitude shy of what")
    print("  is needed to attack X25519 — and many more orders shy of attacking")
    print("  RSA-2048.  See report §6c for full context.")
    print()
    print("On Module-LWE:")
    print("  Quantum sieving (Laarhoven [44]) gives 2^{0.265β} cost; for ML-KEM-768")
    print("  this is approximately 2^{164} quantum operations — comparable to the")
    print("  cost of finding an AES-160 key by quantum brute force.")
    print()
    print("  Chen 2024 [43] briefly claimed a polynomial-time quantum LWE algorithm,")
    print("  withdrawn within days after Wu identified a flaw in step 9.  The")
    print("  corrected version does NOT break Kyber-class parameters.")


if __name__ == "__main__":
    main()
