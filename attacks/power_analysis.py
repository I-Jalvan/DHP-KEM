"""
power_analysis.py — Simulated Simple Power Analysis (SPA) on a non-constant-time
                     conditional add.

This is a SIMULATION, not a real power-trace attack.  Real DPA requires
oscilloscope traces of an embedded device.  The simulation replaces the
oscilloscope with a "power model": we synthesise a fake trace where each
operation contributes a known amount of "power" plus Gaussian noise.

Two implementations of double-and-add scalar multiplication are simulated:

  1. naive_double_and_add(k, P): on each bit of k, EITHER does (double)
     OR (double, then add).  The number of operations is bit-dependent,
     so the synthesised trace's length-modulated-by-Hamming-weight is
     trivially distinguishable.  SPA recovers k by counting "spikes".

  2. constant_time_montgomery_ladder(k, P): always does one double AND one
     add per bit, conditionally swapping registers via constant-time
     bitwise operations.  The synthesised trace is independent of k.

We compare the resulting traces and show that an attacker with a power
model + the public key Q = k·G can recover k from the naive trace but
not from the constant-time trace.

This is the cleaned-up textbook case; real DPA attacks on Kyber (Pessl-
Primas [28]; Ngo et al. [29]) target the much subtler leakage of the
number-theoretic transform during decapsulation.

Reference: report §6b Side-Channel Attacks, "Power analysis (SPA/DPA)".
"""
from __future__ import annotations
import random


# Operation power costs (arbitrary units, illustrative only)
COST_DOUBLE = 10
COST_ADD    = 14
NOISE_SIGMA = 0.5   # measurement noise


def naive_double_and_add(k: int, gen_trace: bool = True) -> tuple[int, list]:
    """Process k MSB-to-LSB.  Each '1' bit triggers a Double AND an Add;
       each '0' bit only a Double.  This is the textbook SPA-vulnerable
       implementation."""
    R = 0  # placeholder for the point
    trace = []
    for bit in bin(k)[2:]:        # MSB-to-LSB; no leading "0b"
        trace.append(("DBL", _noisy(COST_DOUBLE)))   # always double
        R = R * 2
        if bit == "1":
            trace.append(("ADD", _noisy(COST_ADD)))  # only add if bit set
            R = R + 1
    return R, trace


def constant_time_ladder(k: int, n_bits: int, gen_trace: bool = True) -> tuple[int, list]:
    """Montgomery-ladder-style: every bit causes exactly one DBL and one ADD,
       with the order chosen by a constant-time swap.  The cost sequence
       is independent of the bits of k."""
    R0, R1 = 0, 1                # ladder registers
    trace = []
    bits = bin(k)[2:].rjust(n_bits, "0")   # fixed-width to leak no length info
    for bit in bits:
        # Constant-time conditional swap (illustrative, not real):
        if bit == "0":
            # R1 = R0 + R1;  R0 = 2*R0
            trace.append(("DBL", _noisy(COST_DOUBLE)))
            trace.append(("ADD", _noisy(COST_ADD)))
        else:
            # R0 = R0 + R1;  R1 = 2*R1
            trace.append(("DBL", _noisy(COST_DOUBLE)))
            trace.append(("ADD", _noisy(COST_ADD)))
    return R0, trace


def _noisy(x: float) -> float:
    return x + random.gauss(0, NOISE_SIGMA)


def recover_bits_from_naive_trace(trace) -> str:
    """Reconstruct the secret bits from an SPA trace of naive_double_and_add."""
    bits = []
    i = 0
    while i < len(trace):
        op = trace[i][0]
        assert op == "DBL"
        # If the next operation is ADD, this bit was 1; otherwise it was 0.
        if i + 1 < len(trace) and trace[i + 1][0] == "ADD":
            bits.append("1")
            i += 2
        else:
            bits.append("0")
            i += 1
    return "".join(bits)


def main():
    random.seed(0xC0FFEE)
    n_bits = 16
    secret_k = random.randrange(1 << (n_bits - 1), 1 << n_bits)
    print(f"Secret scalar k = {secret_k} = {bin(secret_k)} (length {n_bits} bits)")
    print()

    # Attack 1 — naive code
    _, trace_naive = naive_double_and_add(secret_k)
    bits_recovered = recover_bits_from_naive_trace(trace_naive)
    print(f"NAIVE double-and-add:")
    print(f"  trace length          = {len(trace_naive)} ops "
          f"(differs by k's Hamming weight!)")
    print(f"  recovered k from SPA  = {int(bits_recovered, 2)} "
          f"= {bin(int(bits_recovered, 2))}")
    print(f"  match                 = {int(bits_recovered, 2) == secret_k}")

    # Attack 2 — constant-time code
    print()
    _, trace_ct = constant_time_ladder(secret_k, n_bits)
    op_seq = "".join("D" if t[0] == "DBL" else "A" for t in trace_ct)
    print(f"CONSTANT-TIME ladder:")
    print(f"  trace length          = {len(trace_ct)} ops "
          f"(EXACTLY 2·n_bits, independent of k)")
    print(f"  operation sequence    = {op_seq}")
    print(f"  recovered k from SPA  = (no exploitable structure)")

    print()
    print("Conclusion: SPA recovers k from the naive trace in O(n_bits) operations;")
    print("the constant-time ladder leaks no scalar bits via op-count or sequence.")
    print()
    print("Real DPA attacks on Kyber (Pessl-Primas [28]; Ngo et al. [29]) target")
    print("the secret-coefficient-dependent NTT and require ~ 10^4 - 10^6 traces.")
    print("Defence requires d-th-order masking (d ≥ 3 in practice; see §7 of report).")


if __name__ == "__main__":
    main()
