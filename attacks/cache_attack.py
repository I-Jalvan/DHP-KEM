"""
cache_attack.py — Conceptual simulation of a Flush+Reload cache-timing attack.

This is an EDUCATIONAL SIMULATION, not a real cache-side-channel exploit.
A real Flush+Reload requires:
   * shared memory between attacker and victim (e.g. shared library)
   * the clflush x86 instruction to evict cache lines
   * a high-resolution time-stamp counter (RDTSC)

What we model
-------------
A naive S-box lookup function `naive_lookup(key, idx)` accesses memory
location `key[idx]`.  An attacker who can observe which cache lines were
fetched can deduce `idx` (and thus indirectly leak the key byte that
selected `idx`).  We simulate the cache effect by:

  * pre-flagging "cached" lines based on whether the victim accessed them
  * timing a "reload" by returning a fixed FAST_NS if cached, SLOW_NS if not

The constant-time alternative `masked_lookup(key, idx)` reads ALL S-box
entries and computes the selected one via bitwise masking.  Every cache
line is accessed regardless of `idx`, so the cache state leaks no
information.

Reference: report §6b Side-Channel Attacks, "Cache and microarchitectural
attacks (Flush+Reload, Prime+Probe)".
"""
from __future__ import annotations
import random


CACHE_LINE_BYTES = 64
SBOX_SIZE = 256
FAST_NS = 60     # cache HIT
SLOW_NS = 250    # cache MISS


# ----- A toy S-box (just a permutation, AES-like for illustration) ---------
random.seed(0xACE5BAD)
SBOX = list(range(SBOX_SIZE))
random.shuffle(SBOX)


def naive_lookup(idx: int) -> int:
    """Direct memory access — leaks `idx` (and therefore part of the secret)
       through the cache state."""
    return SBOX[idx]


def masked_lookup(idx: int) -> int:
    """Read every entry; arithmetic-mask out the right one.
       Constant-cache-pattern."""
    result = 0
    for i, entry in enumerate(SBOX):
        # mask is all-1s if i == idx, else all-0s
        mask = -int(i == idx) & 0xFF
        result |= entry & mask
    return result


def simulate_cache_after_victim_access(victim_idx: int) -> set:
    """Return the set of cache lines that are HOT (recently accessed) after
       the victim function ran with index `victim_idx`."""
    if victim_idx is None:
        return set()
    line = (victim_idx * 1) // (CACHE_LINE_BYTES // 1)   # 1-byte entries
    return {line}


def simulate_reload_time(cached_lines: set, query_line: int) -> int:
    """Return the (simulated) reload-time for `query_line`."""
    return FAST_NS if query_line in cached_lines else SLOW_NS


def main():
    print("Flush+Reload simulation against naive_lookup and masked_lookup")
    print("=" * 70)

    # Attacker objective: find which idx the victim used
    random.seed(2026)
    victim_idx = random.randrange(SBOX_SIZE)
    print(f"\nVictim (secretly) calls lookup({victim_idx}) ...")

    # --- Attack on naive ---
    naive_lookup(victim_idx)
    cached = simulate_cache_after_victim_access(victim_idx)
    attacker_guess = None
    fastest_time = SLOW_NS
    for candidate in range(SBOX_SIZE):
        line = candidate
        t = simulate_reload_time(cached, line)
        if t < fastest_time:
            fastest_time = t
            attacker_guess = candidate
    print(f"\nNAIVE lookup:")
    print(f"  attacker measures reload time for every line in [0, {SBOX_SIZE}-1]")
    print(f"  fastest line is line {attacker_guess} ({fastest_time} ns)")
    print(f"  recovered idx = {attacker_guess}   "
          f"({'MATCH' if attacker_guess == victim_idx else 'MISS'})")

    # --- Attack on masked ---
    # Pretend ALL 256 lines now look hot (because masked_lookup touched them all).
    cached_all = set(range(SBOX_SIZE))
    masked_lookup(victim_idx)
    times = [simulate_reload_time(cached_all, line) for line in range(SBOX_SIZE)]
    distinct = sorted(set(times))
    print(f"\nMASKED lookup:")
    print(f"  attacker measures reload time for every line — distinct values: {distinct} ns")
    print(f"  ALL lines were touched -> no exploitable structure")

    print()
    print("Mitigations (report §7 Mitigation):")
    print("  * Always avoid secret-dependent memory addresses.")
    print("  * Bit-sliced or vectorised constant-time S-box implementations.")
    print("  * Hardware: dedicated cache-partitioning extensions (Intel CAT).")


if __name__ == "__main__":
    main()
