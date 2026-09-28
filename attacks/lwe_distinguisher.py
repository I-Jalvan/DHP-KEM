"""
lwe_distinguisher.py — A short-vector distinguisher attack on a TOY LWE instance.

This script illustrates the *dual attack* (Section 6a of the report) by
running it against a tiny LWE instance where it actually succeeds.  The
algorithm is:

  1. Generate an LWE sample (A, b = A·s + e mod q) with small modulus
     q, small dimension n, and small error.
  2. Find a short vector v in the dual lattice {v : A^T v = 0 mod q} by
     brute search (tiny dimensions only).
  3. Compute <v, b> mod q.  If b is a real LWE sample with small e, then
     <v, b> = <v, e> is also "small mod q".  If b is uniformly random,
     <v, b> is uniformly distributed.  The distinguisher therefore checks
     whether <v, b> mod q lies in a "small" interval.

ML-KEM-768 uses n = 768·3 = 2304 unknowns and q = 3329; the LWE-Estimator
[24] reports BKZ-619 with sieving costing 2^181 classical bit-operations
to mount the same attack on real parameters.  This toy version with n=8
is solvable in a few milliseconds on a laptop.

Reference: report §6a Cryptanalysis, "Module-LWE / lattice attacks".
"""
from __future__ import annotations
import random
from itertools import product


# Toy parameters
N      = 4        # number of unknowns (smaller for tractable brute search)
M      = 16       # number of LWE samples
Q      = 31       # modulus (small prime)
SIGMA  = 1        # error bound (small integer Gaussian, |e_i| ≤ SIGMA)


def gen_lwe(n: int, m: int, q: int, sigma: int, seed: int):
    """Generate (A, b, s, e) with b = A·s + e mod q."""
    rng = random.Random(seed)
    A = [[rng.randrange(q) for _ in range(n)] for _ in range(m)]
    s = [rng.randrange(q) for _ in range(n)]      # secret (could be small)
    e = [rng.randint(-sigma, sigma) for _ in range(m)]
    b = [(sum(A[i][j] * s[j] for j in range(n)) + e[i]) % q for i in range(m)]
    return A, b, s, e


def find_short_dual_vector(A, n, m, q, sigma_bound: int):
    """Brute-force search for v ∈ {-1,0,1}^m such that v^T · A = 0 mod q."""
    from itertools import combinations
    for support_size in (3, 4, 5, 6, 7, 8):
        for support in combinations(range(m), support_size):
            for signs in product((-1, 1), repeat=support_size):
                v = [0] * m
                for idx, s in zip(support, signs):
                    v[idx] = s
                row = [sum(v[i] * A[i][j] for i in range(m)) % q
                       for j in range(n)]
                if all(r == 0 for r in row):
                    return v
    return None


def main():
    print(f"Toy LWE instance:  n={N}, m={M}, q={Q}, σ={SIGMA}")
    A, b, s, e = gen_lwe(N, M, Q, SIGMA, seed=1)
    print(f"  secret s = {s}")
    print(f"  errors e = {e}")
    print()
    print("Searching for a short vector in the row-kernel of A^T mod q ...")
    v = find_short_dual_vector(A, N, M, Q, SIGMA)
    if v is None:
        print("  (none found in the search budget; try larger support size)")
        return
    print(f"  found v with Hamming weight {sum(1 for x in v if x)}: {v}")
    print()
    inner_b = sum(v[i] * b[i] for i in range(M)) % Q
    # Recentre to (-q/2, q/2]
    inner_b_centered = inner_b if inner_b <= Q // 2 else inner_b - Q
    inner_e = sum(v[i] * e[i] for i in range(M)) % Q
    inner_e_centered = inner_e if inner_e <= Q // 2 else inner_e - Q
    print(f"  <v, b> mod q = {inner_b} (centred: {inner_b_centered})")
    print(f"  <v, e> mod q = {inner_e} (centred: {inner_e_centered})")
    print()
    # Distinguisher: |centred| ≤ |v|_1 · σ
    bound = sum(abs(x) for x in v) * SIGMA
    print(f"  expected |<v, e>| ≤ |v|_1 · σ = {bound}")
    if abs(inner_b_centered) <= bound:
        print("  => Statistic falls in the LWE region; distinguisher says 'LWE'.")
    else:
        print("  => Statistic outside LWE region; distinguisher says 'uniform'.")
    # Repeat against a *uniform-random* "b" to show the contrast:
    rng = random.Random(7)
    b_unif = [rng.randrange(Q) for _ in range(M)]
    inner_u = sum(v[i] * b_unif[i] for i in range(M)) % Q
    inner_u_centered = inner_u if inner_u <= Q // 2 else inner_u - Q
    print(f"\n  control: <v, uniform-random b> centred = {inner_u_centered}")
    print(f"           bound = {bound}  ⇒  "
          f"{'inside (false positive)' if abs(inner_u_centered) <= bound else 'outside (correctly rejected)'}")

    print()
    print("On real ML-KEM-768 (n=2304, q=3329) the analogous attack uses BKZ-619")
    print("with quantum-amplified sieving and costs ≈ 2^181 classical bit-operations")
    print("(LWE-Estimator [24] under core-SVP heuristic).")


if __name__ == "__main__":
    main()
