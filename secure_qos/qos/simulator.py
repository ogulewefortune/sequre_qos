"""Discrete-event simulation of one 10 Mbps bottleneck link with a pluggable scheduler and optional HMAC check.

Events: packet arrival, packet departure. (Source ON/OFF state changes are generated ahead of time in
traffic.py so that every scheduler sees the identical trace; their count is recorded in the results.)
Tie rule: when a departure and an arrival have the same timestamp, the departure is processed first.
"""
import numpy as np
from collections import Counter
from .config import *
from .schedulers import SCHEDULERS
from . import security as sec

def maxmin(offered, weights, cap):
    """Weighted max-min fair allocation of `cap` among demands `offered` (used for the Jain index)."""
    alloc = [0.0] * len(offered); active = set(range(len(offered))); rem = cap
    while active and rem > 1e-9:
        wsum = sum(weights[i] for i in active)
        share = {i: rem * weights[i] / wsum for i in active}
        sat = [i for i in active if offered[i] - alloc[i] <= share[i] + 1e-12]
        if not sat:
            for i in active: alloc[i] += share[i]
            break
        for i in sat:
            rem -= offered[i] - alloc[i]; alloc[i] = offered[i]; active.discard(i)
    return alloc

def jain(x):
    s = sum(x); q = sum(v * v for v in x)
    return (s * s) / (len(x) * q) if q > 0 else 1.0

def run(trace, sched, K, security=False, t_ver_us=1.0, T=120.0, warmup=10.0, log=None):
    n = len(trace["t"])
    t_orig = trace["t"].tolist(); payload = trace["size"].tolist(); cls = trace["cls"].tolist()
    mark = trace["mark"].tolist(); auth = trace["auth"].tolist()
    wire = [s + TAG_BYTES for s in payload] if security else payload
    tver = t_ver_us * 1e-6 if security else 0.0
    S = SCHEDULERS[sched](K, wire)
    INF = float("inf"); W = warmup
    cur, cur_start, dep_t = -1, 0.0, INF
    cnt = [0] * 4; area = [0.0] * 4; last = 0.0; busy = 0.0
    gen = [0] * 4; gen_pay = [0] * 4; tx = [0] * 4; drop = [0] * 4
    tx_wire = [0] * 4; tx_pay = [0] * 4
    waits = [[] for _ in range(4)]; resp = [[] for _ in range(4)]
    reasons = Counter(); sec_ok = 0; sec_bad = 0
    qidx = [0] * n; hp_bytes = 0; hp_att = 0
    tot_tx = tot_drop = 0; i = 0
    while True:
        nxt = t_orig[i] + tver if i < n else INF
        if cur >= 0 and dep_t <= nxt:                      # ---- departure (wins ties)
            t = dep_t; kind = "dep"
        elif i < n:
            t = nxt; kind = "arr"
        else:
            break
        lo = last if last > W else W; hi = t if t < T else T
        if hi > lo:
            d = hi - lo
            for c in range(4): area[c] += cnt[c] * d
            if cur >= 0: busy += d
        last = t
        if kind == "dep":
            j = cur; c = cls[j]; cur = -1; dep_t = INF; tot_tx += 1
            if W <= t_orig[j] < T:
                tx[c] += 1; waits[c].append(cur_start - t_orig[j]); resp[c].append(t - t_orig[j])
            if W <= t < T:
                tx_wire[c] += wire[j]; tx_pay[c] += payload[j]
                if qidx[j] == VOICE:                       # served from the high-priority (voice) queue
                    hp_bytes += wire[j]
                    if c == ATTACKER: hp_att += wire[j]
            if log is not None: log.append((t, "DEP", j))
        else:                                              # ---- arrival
            j = i; i += 1; c = cls[j]; inw = W <= t_orig[j] < T; qi = mark[j]
            if inw: gen[c] += 1; gen_pay[c] += payload[j]
            if security:
                hdr = sec.header(0, mark[j], j & 0xFFFFFFFF, payload[j])
                tag = sec.make_tag(SECURITY_KEY, hdr) if auth[j] else sec.forged_tag()
                if sec.verify(SECURITY_KEY, hdr, tag):
                    if inw: sec_ok += 1
                else:
                    qi = DATA                              # unauthorized marking -> reclassified to lowest class
                    if inw: sec_bad += 1; reasons[(c, "AUTH_FAIL_RECLASSIFIED")] += 1
            qidx[j] = qi
            if log is not None: log.append((t, "ARR", j))
            if S.enqueue(j, qi): cnt[c] += 1
            else:
                tot_drop += 1
                if inw: drop[c] += 1; reasons[(c, "BUFFER_FULL")] += 1
                if log is not None: log.append((t, "DROP", j))
        if cur < 0:                                        # link idle -> start next packet
            j = S.dequeue()
            if j is not None:
                cnt[cls[j]] -= 1; cur = j; cur_start = t; dep_t = t + 8.0 * wire[j] / C_BPS
    Tm = T - W
    res = dict(sched=sched, K=K, security=int(security), packets_total=n, conservation_ok=int(n == tot_tx + tot_drop),
               state_changes=trace["state_changes"], util=busy / Tm, sec_ok=sec_ok, sec_bad=sec_bad)
    groups = {CLASS_NAMES[c]: [c] for c in range(4) if gen[c] > 0}
    groups["all"] = [c for c in range(4) if gen[c] > 0]
    for g, cs in groups.items():
        w = [x for c in cs for x in waits[c]]; d = [x for c in cs for x in resp[c]]
        G = sum(gen[c] for c in cs); X = sum(tx[c] for c in cs)
        res[f"{g}_gen"] = G; res[f"{g}_tx"] = X; res[f"{g}_drop"] = sum(drop[c] for c in cs)
        res[f"{g}_W_ms"] = 1e3 * float(np.mean(w)) if w else float("nan")
        res[f"{g}_D_ms"] = 1e3 * float(np.mean(d)) if d else float("nan")
        res[f"{g}_D95_ms"] = 1e3 * float(np.percentile(d, 95)) if d else float("nan")
        res[f"{g}_Dmax_ms"] = 1e3 * float(np.max(d)) if d else float("nan")
        res[f"{g}_loss"] = res[f"{g}_drop"] / G if G else float("nan")
        res[f"{g}_Q"] = sum(area[c] for c in cs) / Tm
        res[f"{g}_S_mbps"] = 8 * sum(tx_wire[c] for c in cs) / Tm / 1e6
        res[f"{g}_goodput_mbps"] = 8 * sum(tx_pay[c] for c in cs) / Tm / 1e6
    # fairness over the three legitimate classes: x_c = throughput / weighted max-min fair share
    off = [8 * gen_pay[c] / Tm for c in range(3)]
    if security: off = [o * (1 + TAG_BYTES / TRAFFIC[c]["size"]) for c, o in enumerate(off)]
    thr = [8 * tx_wire[c] / Tm for c in range(3)]
    fair = maxmin(off, WFQ_WEIGHTS, C_BPS)
    res["jain"] = jain([thr[c] / fair[c] if fair[c] > 0 else 1.0 for c in range(3)])
    for c in range(3): res[f"{CLASS_NAMES[c]}_share"] = thr[c] / max(sum(thr), 1e-9)
    res["attacker_hp_share"] = hp_att / max(hp_bytes, 1) if gen[ATTACKER] else 0.0
    res["reasons"] = {f"{CLASS_NAMES[c]}:{r}": v for (c, r), v in reasons.items()}
    return res
