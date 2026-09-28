"""
test_timing.py
==============

A *minimal* timing-sanity check on the combiner.

THIS IS NOT A SUBSTITUTE for proper constant-time verification.
Verifying that a cryptographic implementation runs in constant time
requires tools such as:

  *  CT-Verif  (Almeida-Barbosa-Barthe-Dupressoir, USENIX 2016)
  *  ctgrind   (Langley, 2010)
  *  Binsec/Rel (Daniel-Bardin-Rezk, EuroS&P 2020)
  *  dudect    (Reparaz-Balasch-Verbauwhede, DATE 2017)

See §8 and §9.2 of the report.  Any production deployment of DHP-KEM
MUST run one or more of those verifiers on the compiled binary, against
the actual secret keys, not on this Python reference implementation.

What this test DOES do
----------------------
We time `combine()` on many calls with two different secret-key patterns
(all-zeros vs all-ones) and check that the timing distributions are
visually indistinguishable in their summary statistics.  A *real*
constant-time bug would still produce a large statistical difference;
this catches very obvious cases (e.g. an `if ss_ec == 0: return ...`
shortcut) without raising false alarms from JIT noise.

We DELIBERATELY use a loose 30%-ish tolerance because:
  * Python's wall-clock has tens-of-microseconds jitter.
  * The combiner does ~ 100 µs of work, so a relative-difference
    threshold tighter than 10–20% is dominated by noise.
  * Strict statistical testing belongs in a separate fuzzer/dudect run,
    not in a unit-test file.

If this test EVER fails, that's a strong signal of a leaking branch —
not a flaky test.
"""
import statistics
import time
import unittest

import dhp_kem


N_TRIALS  = 500   # per pattern; total = 2 * N_TRIALS combiner invocations
WARMUP    = 50
TOLERANCE = 0.30  # median-of-pattern-A within ±30% of median-of-pattern-B


def _time_combine(ss_pattern: bytes, n: int) -> list[float]:
    """Return n wall-clock times (in seconds) for combine() runs."""
    ps = dhp_kem.get("DHP-KEM-128")
    ss_ec  = ss_pattern[:32]
    ss_lwe = ss_pattern[32:64]
    T      = b"\x00" * 48
    ctx    = b"timing-sanity"
    times = []
    for _ in range(WARMUP):
        dhp_kem.combiner.combine(ps, ss_ec, ss_lwe, T, ctx)
    for _ in range(n):
        t0 = time.perf_counter()
        dhp_kem.combiner.combine(ps, ss_ec, ss_lwe, T, ctx)
        times.append(time.perf_counter() - t0)
    return times


class TimingSanityTests(unittest.TestCase):

    def test_combiner_does_not_leak_via_obvious_branch(self):
        """combine() timings for all-zero vs all-one secrets must overlap."""
        ts_zero = _time_combine(b"\x00" * 64, N_TRIALS)
        ts_ones = _time_combine(b"\xFF" * 64, N_TRIALS)
        med_zero = statistics.median(ts_zero)
        med_ones = statistics.median(ts_ones)
        ratio = med_zero / med_ones if med_ones > 0 else float("inf")

        # Report numbers regardless of pass/fail for debugging:
        msg = (f"\n   median(all-zero)  = {med_zero*1e6:.2f} µs"
               f"\n   median(all-ones)  = {med_ones*1e6:.2f} µs"
               f"\n   ratio              = {ratio:.3f}"
               f"\n   tolerance          = ±{TOLERANCE*100:.0f}%")
        # We only fail if the ratio is *wildly* out of band — > TOLERANCE.
        self.assertTrue(
            (1 - TOLERANCE) < ratio < (1 + TOLERANCE),
            f"combine() timing differs by > {TOLERANCE*100:.0f}% across "
            f"secret patterns — possible non-constant-time bug.{msg}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
