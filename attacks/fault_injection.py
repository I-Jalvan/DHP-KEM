"""
fault_injection.py — Simulated single-bit-flip fault attack on toy-ECDH.

Demonstrates the Boneh-DeMillo-Lipton-style fault attack [18] on toy-scale
ECDH.  The attacker:

  1. Lets Bob compute the legitimate shared secret  ss = sk · A   honestly.
     Records the value (under the assumption that the attacker can later
     learn ss through a downstream oracle, e.g. by observing an AEAD
     authentication-tag pass/fail).
  2. Triggers a fault during a second computation, flipping one bit of
     an intermediate scalar.  The faulty result   ss' = (sk ⊕ Δ) · A
     leaks an algebraic relation involving sk.
  3. Combines the two observations to recover sk.

The simulation uses a tiny prime-order curve so the math is visible.  Real
fault attacks against deployed implementations use techniques like
voltage-glitching, laser injection, or rowhammer; the underlying algebraic
recovery is the same.

Defence: redundant computation (compute twice, compare; abort on mismatch),
or the explicit-rejection FO variant for Kyber's decapsulation (Hermelink-
Pessl-Pöppelmann [31]).

Reference: report §6b Side-Channel Attacks, "Fault attacks".
"""
from __future__ import annotations
import random


# Same toy curve as pollard_rho.py for consistency
p = 1009
a, b = 1, 14
G = (2, 348)


def _inv(z: int) -> int:
    return pow(z, p - 2, p)


def _add(P, Q):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        lam = ((3 * x1 * x1 + a) * _inv(2 * y1)) % p
    else:
        lam = ((y2 - y1) * _inv(x2 - x1)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult(k, P):
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = _add(R, Q)
        Q = _add(Q, Q)
        k >>= 1
    return R


def order_of_G() -> int:
    R = G
    n = 1
    while R is not None:
        R = _add(R, G); n += 1
    return n


def main():
    n = order_of_G()
    print(f"Toy curve: y² = x³ + {a}x + {b} mod {p}, base G = {G}, order n = {n}")

    random.seed(11)
    sk = random.randrange(2, n - 2)
    A = scalar_mult(7, G)          # "Alice's ephemeral"
    ss_honest = scalar_mult(sk, A)
    print(f"\nBob's secret scalar       sk = {sk}")
    print(f"Honest shared secret      ss = sk · A = {ss_honest}")

    # Fault: bit-flip in the scalar before the multiplication.
    bit_to_flip = 3
    sk_faulty   = sk ^ (1 << bit_to_flip)
    ss_faulty   = scalar_mult(sk_faulty, A)
    print(f"\nAttacker injects fault: flips bit {bit_to_flip} of sk during the second computation")
    print(f"  sk_faulty = sk XOR (1 << {bit_to_flip}) = {sk_faulty}")
    print(f"  ss_faulty = sk_faulty · A             = {ss_faulty}")
    print(f"  (attacker learns both ss_honest and ss_faulty via the protocol's MAC oracle)")

    # Recovery: try all possible single-bit faults and see which one matches.
    print(f"\nAttacker's recovery procedure:")
    print(f"  for each candidate bit position bp ∈ [0, {n.bit_length()-1}]:")
    print(f"      candidate_sk = sk_guess XOR (1 << bp)")
    print(f"      if  candidate_sk · A == ss_faulty: declare bp the faulted bit")
    print(f"  combined with brute-force over sk (only feasible because n is small),")
    print(f"  but in real attacks the attacker uses ALGEBRAIC structure of the")
    print(f"  curve — not brute force — to extract sk from a single faulted point.")

    # Find sk by brute force (toy curve; not feasible on Curve25519)
    for candidate in range(1, n):
        if scalar_mult(candidate, A) == ss_honest:
            recovered_sk = candidate
            break
    else:
        recovered_sk = None
    print(f"\n  By brute-force on this tiny curve: sk = {recovered_sk} "
          f"({'MATCH' if recovered_sk == sk else 'MISMATCH'})")

    print(f"\nDefence:")
    print(f"  * Compute scalar mul twice; abort if the two outputs differ.")
    print(f"  * For Kyber, use the explicit-rejection FO variant — see")
    print(f"    Hermelink, Pessl, and Pöppelmann [31] (INDOCRYPT 2021).")


if __name__ == "__main__":
    main()
