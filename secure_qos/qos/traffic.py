"""ON/OFF traffic generation. Traces are generated once per (mix, seed) and reused for every scheduler."""
import numpy as np
from .config import *

def gen_source(rng, p, T):
    """Packet times of one ON/OFF source on [0, T). Returns (times, number_of_state_changes)."""
    gap = 8.0 * p["size"] / p["peak"]                       # spacing while ON
    on = rng.random() < p["on"] / (p["on"] + p["off"])      # stationary initial state
    t, chunks, changes = 0.0, [], 0
    while t < T:
        d = rng.exponential(p["on"] if on else p["off"])
        if on:
            n = int(np.ceil(d / gap))
            ts = t + gap * np.arange(n)
            chunks.append(ts[ts < min(t + d, T)])
        t += d; on = not on; changes += 1
    return (np.concatenate(chunks) if chunks else np.empty(0)), changes

def build_trace(counts, attackers, seed, T):
    """Return dict of arrays sorted by arrival time: t, size(payload), cls(true), mark(claimed), auth(bool)."""
    ts, cls, size, mark, auth, changes = [], [], [], [], [], 0
    def add(arr, c, sz, m, a):
        ts.append(arr); cls.append(np.full(len(arr), c, np.int8)); size.append(np.full(len(arr), sz, np.int32))
        mark.append(np.full(len(arr), m, np.int8)); auth.append(np.full(len(arr), a, bool))
    for c, n in zip((VOICE, VIDEO, DATA), counts):
        for s in range(n):
            arr, ch = gen_source(np.random.default_rng([seed, c, s]), TRAFFIC[c], T); changes += ch
            add(arr, c, TRAFFIC[c]["size"], c, True)
    for s in range(attackers):
        arr, ch = gen_source(np.random.default_rng([seed, ATTACKER, s]), ATTACKER_PROFILE, T); changes += ch
        add(arr, ATTACKER, ATTACKER_PROFILE["size"], VOICE, False)   # claims the voice (high-priority) mark
    t = np.concatenate(ts); order = np.argsort(t, kind="stable")
    cat = lambda x: np.concatenate(x)[order]
    return dict(t=t[order], cls=cat(cls), size=cat(size), mark=cat(mark), auth=cat(auth), state_changes=changes)
