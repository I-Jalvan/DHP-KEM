"""
pollard_rho.py — Pollard's rho algorithm on a TOY ECDLP curve.

Solves the elliptic-curve discrete-log problem `Q = k·G` on a small
prime-order curve in O(sqrt(n)) operations (Pollard 1978; Teske 1998).
The same algorithm is the asymptotically-best classical attack on
Curve25519's ECDLP, where n ≈ 2^252 and so sqrt(n) ≈ 2^126 — far beyond
current computing capabilities.

The toy curve used here is:
    E:  y² = x³ + x + 14  over F_p where p = 1009
    G = (2, 348)
    n = 1013  (prime — verified)

The script:
  1. Picks a random secret k ∈ [1, n-1]
  2. Computes Q = k·G honestly
  3. Runs Pollard's rho with Floyd's cycle-finding to recover k
  4. Confirms the recovered k matches

Run-time: well under 1 second on any laptop.  This is purely an
illustration of the algorithm; nothing about real DHP-KEM-128 security
is affected.

Reference: report §6a Cryptanalysis, "Pollard's rho on ECDLP".
"""
from __future__ import annotations
import random
from typing import Optional


# ---- Toy curve parameters ------------------------------------------------
p = 1009                 # small prime field
a, b = 1, 14             # E: y² = x³ + ax + b
G = (2, 348)             # base point (verified to lie on E, prime order)


def _on_curve(P: Optional[tuple[int, int]]) -> bool:
    if P is None: return True
    x, y = P
    return (y * y - (x*x*x + a*x + b)) % p == 0


def _inv(z: int) -> int:
    """Modular inverse mod p via Fermat's little theorem."""
    return pow(z, p - 2, p)


def add(P: Optional[tuple[int, int]],
        Q: Optional[tuple[int, int]]) -> Optional[tuple[int, int]]:
    """Elliptic-curve point addition on E."""
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None  # point at infinity
    if P == Q:
        lam = ((3 * x1 * x1 + a) * _inv(2 * y1)) % p
    else:
        lam = ((y2 - y1) * _inv(x2 - x1)) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def scalar_mult(k: int, P: Optional[tuple[int, int]]):
    """Compute k·P by double-and-add."""
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R


def order_of_G() -> int:
    """Compute the order of G by repeated addition (works because the
    curve is tiny)."""
    R = G
    n = 1
    while R is not None:
        R = add(R, G)
        n += 1
    return n


# ---- Pollard's rho -------------------------------------------------------

def _partition(P: tuple[int, int]) -> int:
    """Three-way partition function (mod 3) on the x-coordinate."""
    return P[0] % 3 if P is not None else 0


def _f(R, A_acc, B_acc, Q, n):
    """The 'iteration' function used by rho — Pollard-style partition."""
    part = _partition(R)
    if part == 0:
        return add(R, G), (A_acc + 1) % n, B_acc
    if part == 1:
        return add(R, R), (2 * A_acc) % n, (2 * B_acc) % n
    return add(R, Q), A_acc, (B_acc + 1) % n


def pollard_rho_dl(Q, n, max_iters: int = 200_000) -> Optional[int]:
    """Solve  Q = k·G  for k mod n  via Floyd-tortoise-and-hare cycle finding."""
    R1, a1, b1 = G, 1, 0           # tortoise
    R2, a2, b2 = R1, a1, b1
    R2, a2, b2 = _f(R2, a2, b2, Q, n)  # hare starts one step ahead
    for step in range(max_iters):
        R1, a1, b1 = _f(R1, a1, b1, Q, n)
        R2, a2, b2 = _f(R2, a2, b2, Q, n)
        R2, a2, b2 = _f(R2, a2, b2, Q, n)
        if R1 == R2:
            # We have   a1 G + b1 Q  =  a2 G + b2 Q
            # ⇒   (b1 - b2) k  ≡  (a2 - a1)  mod n
            num = (a2 - a1) % n
            den = (b1 - b2) % n
            if den == 0:
                return None
            k = (num * pow(den, -1, n)) % n
            return k
    return None


# ---- Driver --------------------------------------------------------------

def main():
    assert _on_curve(G), "Base point G must lie on E"
    print(f"Toy curve E: y² = x³ + {a}x + {b}  over  F_{p}")
    print(f"Base point G = {G}")
    n = order_of_G()
    print(f"Order of G: n = {n}")
    print()
    # Generate a random secret k and the corresponding public Q
    random.seed(42)
    k_true = random.randint(2, n - 2)
    Q = scalar_mult(k_true, G)
    print(f"Secret scalar (the attacker wants to find):  k = {k_true}")
    print(f"Public point Q = k·G:                        Q = {Q}")
    print()
    print("Running Pollard's rho ...")
    k_found = pollard_rho_dl(Q, n)
    if k_found is None:
        print("  rho failed within iteration budget (try increasing max_iters)")
        return
    print(f"  Recovered k = {k_found}")
    if k_found == k_true:
        print("  Success — k_found == k_true.")
    else:
        # rho recovers k mod n; verify by re-multiplying
        if scalar_mult(k_found, G) == Q:
            print("  k_found · G = Q  (correct, but representative differs)")
        else:
            print("  ERROR: k_found does not satisfy k·G = Q")

    print()
    print("Scaling to Curve25519 (n ≈ 2^252):")
    print("  expected sqrt(n) ≈ 2^126 iterations  ≈  10^38 group operations")
    print("  ≈ 10^25 years at 10^13 operations/second  (>> age of universe)")


if __name__ == "__main__":
    main()
