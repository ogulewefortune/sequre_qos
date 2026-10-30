"""Run studies E1-E4, save raw results (with parameters and seeds), summaries, tables, and figures.
Usage: python run_experiments.py [--duration 300] [--warmup 10] [--seeds 1 2 3] [--quick]"""
import argparse, json, os, time
import numpy as np, pandas as pd
from scipy import stats
from qos.config import *
from qos.traffic import build_trace
from qos.simulator import run
import security_demo

ap = argparse.ArgumentParser()
ap.add_argument("--duration", type=float, default=300.0); ap.add_argument("--warmup", type=float, default=10.0)
ap.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3]); ap.add_argument("--out", default="results")
ap.add_argument("--quick", action="store_true", help="30 s runs for a fast smoke test")
a = ap.parse_args()
if a.quick: a.duration, a.warmup = 30.0, 5.0
os.makedirs(a.out, exist_ok=True)
T, W = a.duration, a.warmup
SCHEDS = ["fifo", "spq", "drr", "wfq"]
t_ver = security_demo.demo(os.path.join(a.out, "security_demo.txt"))   # measured verification time (us)

specs = []   # (exp, label, sched, counts, attackers, K, security, seed)
for rho in (0.3, 0.6, 0.9, 1.1):
    for s in SCHEDS:
        for sd in a.seeds: specs.append(("E1", f"rho{rho}", s, mix_for_rho(rho), 0, 100, False, sd))
for K in (10, 25, 50, 100, 200):
    for sd in a.seeds: specs.append(("E2", "rho0.9", "drr", mix_for_rho(0.9), 0, K, False, sd))
for s in ("spq", "drr"):
    for sd in a.seeds:
        specs.append(("E3", "no_attack", s, mix_for_rho(0.9), 0, 100, False, sd))
        specs.append(("E3", "attack_secoff", s, mix_for_rho(0.9), 10, 100, False, sd))
        specs.append(("E3", "attack_secon", s, mix_for_rho(0.9), 10, 100, True, sd))
for cond, counts in (("equal_mix_1.1", mix_for_rho(1.1)), ("data_flood", (20, 20, 93))):
    for s in ("drr", "wfq"):
        for sd in a.seeds: specs.append(("E4", cond, s, counts, 0, 100, False, sd))

rows, cache, t0 = [], {}, time.time()
for n, (exp, label, s, counts, att, K, sec, sd) in enumerate(specs, 1):
    key = (counts, att, sd)
    if key not in cache:
        cache.clear(); cache[key] = build_trace(counts, att, sd, T)
    r = run(cache[key], s, K, security=sec, t_ver_us=t_ver, T=T, warmup=W)
    assert r["conservation_ok"] == 1
    r.update(exp=exp, label=label, seed=sd, n_voice=counts[0], n_video=counts[1], n_data=counts[2], attackers=att,
             rho_offered=offered_rho(counts, att), duration=T, warmup=W, t_ver_us=t_ver if sec else 0.0,
             drr_quanta=str(DRR_QUANTA), wfq_weights=str(WFQ_WEIGHTS), buf_split=str(BUFFER_SPLIT))
    r["reasons"] = json.dumps(r["reasons"]); rows.append(r)
    if n % 10 == 0 or n == len(specs): print(f"  {n}/{len(specs)} runs  ({time.time()-t0:.0f}s)", flush=True)
df = pd.DataFrame(rows); df.to_csv(os.path.join(a.out, "raw_runs.csv"), index=False)

# ---------- summaries: mean and 95% CI (t distribution) over seeds
METRICS = [f"{g}_{m}" for g in ("voice", "video", "data", "attacker", "all") for m in ("W_ms", "D_ms", "D95_ms", "Dmax_ms", "loss", "Q", "S_mbps", "goodput_mbps")] \
          + ["util", "jain", "voice_share", "video_share", "data_share", "attacker_hp_share", "sec_ok", "sec_bad"]
def summarize(d, keys):
    out = []
    for k, g in d.groupby(keys, sort=False):
        row = dict(zip(keys, k if isinstance(k, tuple) else (k,))); n = len(g); row["n_seeds"] = n
        for m in METRICS:
            if m in g and g[m].notna().any():
                v = g[m].astype(float); row[m] = v.mean()
                row[m + "_ci"] = stats.t.ppf(0.975, n - 1) * v.std(ddof=1) / np.sqrt(n) if n > 1 else float("nan")
        out.append(row)
    return pd.DataFrame(out)
S = {e: summarize(df[df.exp == e], ["label", "sched", "K", "security"]) for e in ("E1", "E2", "E3", "E4")}
for e, s in S.items(): s.to_csv(os.path.join(a.out, f"summary_{e}.csv"), index=False)

# ---------- markdown tables
def f(row, m, p=2, scale=1.0):
    return f"{row[m]*scale:.{p}f} ± {row[m+'_ci']*scale:.{p}f}"
md = [f"# Results (duration {T:.0f} s, warm-up {W:.0f} s, seeds {a.seeds}; mean ± 95% CI)\n"]
md.append("## E1 – mean response time D (ms) and loss (%) per class, K=100\n")
md.append("| load | sched | D voice | D video | D data | loss voice % | loss video % | loss data % | util | Dmax data (ms) |\n|---|---|---|---|---|---|---|---|---|---|")
for _, r in S["E1"].iterrows():
    md.append(f"| {r.label[3:]} | {r.sched.upper()} | {f(r,'voice_D_ms')} | {f(r,'video_D_ms')} | {f(r,'data_D_ms')} | {f(r,'voice_loss',2,100)} | {f(r,'video_loss',2,100)} | {f(r,'data_loss',2,100)} | {r.util:.3f} | {r.data_Dmax_ms:.0f} |")
md.append("\n## E1 – waiting time W (ms), queue length Q (packets) and throughput S (Mbps)\n")
md.append("| load | sched | W voice | W video | W data | Q voice | Q video | Q data | S voice | S video | S data |\n|---|---|---|---|---|---|---|---|---|---|---|")
for _, r in S["E1"].iterrows():
    md.append(f"| {r.label[3:]} | {r.sched.upper()} | {r.voice_W_ms:.2f} | {r.video_W_ms:.2f} | {r.data_W_ms:.2f} | {r.voice_Q:.2f} | {r.video_Q:.2f} | {r.data_Q:.2f} | {r.voice_S_mbps:.3f} | {r.video_S_mbps:.3f} | {r.data_S_mbps:.3f} |")
md.append("\n## E2 – buffer study (DRR, rho=0.9)\n")
md.append("| K | D voice | D video | D data | loss voice % | loss video % | loss data % | loss all % | D all |\n|---|---|---|---|---|---|---|---|---|")
for _, r in S["E2"].iterrows():
    md.append(f"| {int(r.K)} | {f(r,'voice_D_ms')} | {f(r,'video_D_ms')} | {f(r,'data_D_ms')} | {f(r,'voice_loss',2,100)} | {f(r,'video_loss',2,100)} | {f(r,'data_loss',2,100)} | {f(r,'all_loss',2,100)} | {f(r,'all_D_ms')} |")
md.append("\n## E3 – security study (legit rho=0.9 + 10 attackers marking video-sized packets as voice, K=100)\n")
md.append("| sched | case | attacker share of HP-queue bytes | D voice (ms) | D video (ms) | D data (ms) | loss data % | data goodput (Mbps) | sec accepted | sec reclassified |\n|---|---|---|---|---|---|---|---|---|---|")
for _, r in S["E3"].iterrows():
    md.append(f"| {r.sched.upper()} | {r.label} | {r.attacker_hp_share:.3f} | {f(r,'voice_D_ms')} | {f(r,'video_D_ms')} | {f(r,'data_D_ms')} | {f(r,'data_loss',2,100)} | {r.data_goodput_mbps:.3f} | {r.sec_ok:.0f} | {r.sec_bad:.0f} |")
md.append("\n## E4 – DRR vs WFQ\n")
md.append("| condition | sched | D95 voice | D95 video | D95 data | loss all % | Jain | share v/vid/d |\n|---|---|---|---|---|---|---|---|")
for _, r in S["E4"].iterrows():
    md.append(f"| {r.label} | {r.sched.upper()} | {f(r,'voice_D95_ms')} | {f(r,'video_D95_ms')} | {f(r,'data_D95_ms')} | {f(r,'all_loss',2,100)} | {f(r,'jain',3)} | {r.voice_share:.2f}/{r.video_share:.2f}/{r.data_share:.2f} |")
open(os.path.join(a.out, "tables.md"), "w").write("\n".join(md) + "\n")

# ---------- figures (grayscale-safe: markers + line styles)
import matplotlib; matplotlib.use("Agg"); import matplotlib.pyplot as plt
plt.rcParams.update({"font.family": "serif", "font.size": 7, "axes.linewidth": 0.5, "lines.linewidth": 0.9, "lines.markersize": 3})
MK = {"fifo": ("o", "-"), "spq": ("s", "--"), "drr": ("^", "-."), "wfq": ("D", ":")}
E1 = S["E1"].assign(rho=lambda d: d.label.str[3:].astype(float)); cls3 = ["voice", "video", "data"]
for metric, ylabel, fn, scale, logy in (("D_ms", "Mean response time (ms)", "fig_e1_delay", 1, True), ("loss", "Packet loss (%)", "fig_e1_loss", 100, False)):
    fig, ax = plt.subplots(1, 3, figsize=(7.16, 2.0), sharey=False)
    for k, c in enumerate(cls3):
        for s in SCHEDS:
            d = E1[E1.sched == s].sort_values("rho"); m, l = MK[s]
            ax[k].errorbar(d.rho, d[f"{c}_{metric}"] * scale, yerr=d[f"{c}_{metric}_ci"] * scale, marker=m, ls=l, color="k", capsize=1.5, elinewidth=0.4, label=s.upper())
        ax[k].set_title(c.capitalize()); ax[k].set_xlabel("Offered load ρ"); ax[k].set_xticks([0.3, 0.6, 0.9, 1.1])
        if logy: ax[k].set_yscale("log")
        ax[k].grid(alpha=0.3, lw=0.3)
    ax[0].set_ylabel(ylabel); ax[0].legend(frameon=False, fontsize=6); fig.tight_layout(); fig.savefig(os.path.join(a.out, fn + ".png"), dpi=300); plt.close(fig)

E2 = S["E2"].sort_values("K"); fig, ax = plt.subplots(figsize=(3.5, 2.5))
for c, (m, l) in zip(cls3, (("o", "-"), ("s", "--"), ("^", ":"))):
    ax.plot(E2[f"{c}_loss"] * 100, E2[f"{c}_D_ms"], marker=m, ls=l, color="k", label=c)
    for _, r in E2.iterrows(): ax.annotate(int(r.K), (r[f"{c}_loss"] * 100, r[f"{c}_D_ms"]), fontsize=5, xytext=(2, 2), textcoords="offset points")
ax.set_xlabel("Packet loss (%)"); ax.set_ylabel("Mean response time (ms)"); ax.legend(frameon=False); ax.grid(alpha=0.3, lw=0.3)
ax.set_title("DRR, ρ=0.9; labels = total buffer K", fontsize=6); fig.tight_layout(); fig.savefig(os.path.join(a.out, "fig_e2_buffer.png"), dpi=300); plt.close(fig)

E3 = S["E3"]; fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.0)); cases = ["no_attack", "attack_secoff", "attack_secon"]; hat = ["", "///", "..."]
for ax_i, (metric, yl, scale) in enumerate((("attacker_hp_share", "Attacker share of high-priority bytes", 1), ("voice_D_ms", "Voice mean response time (ms)", 1))):
    for si, s in enumerate(("spq", "drr")):
        for ci, cse in enumerate(cases):
            r = E3[(E3.sched == s) & (E3.label == cse)].iloc[0]
            ax[ax_i].bar(si * 4 + ci, r[metric] * scale, yerr=r.get(metric + "_ci", 0) if metric != "attacker_hp_share" else 0, color="w", edgecolor="k", hatch=hat[ci], lw=0.5, label=cse if si == 0 else None, capsize=1.5)
    ax[ax_i].set_xticks([1, 5]); ax[ax_i].set_xticklabels(["SPQ", "DRR"]); ax[ax_i].set_ylabel(yl)
ax[0].legend(frameon=False, fontsize=5.5); fig.tight_layout(); fig.savefig(os.path.join(a.out, "fig_e3_security.png"), dpi=300); plt.close(fig)

E4 = S["E4"]; fig, ax = plt.subplots(1, 2, figsize=(7.16, 2.0), sharey=False)
for k, cond in enumerate(("equal_mix_1.1", "data_flood")):
    for si, s in enumerate(("drr", "wfq")):
        r = E4[(E4.label == cond) & (E4.sched == s)].iloc[0]
        for ci, c in enumerate(cls3):
            ax[k].bar(ci * 3 + si, r[f"{c}_D95_ms"], yerr=r[f"{c}_D95_ms_ci"], color="w", edgecolor="k", hatch="///" if s == "wfq" else "", lw=0.5, capsize=1.5, label=s.upper() if ci == 0 else None)
    ax[k].set_xticks([0.5, 3.5, 6.5]); ax[k].set_xticklabels(cls3); ax[k].set_title(cond.replace("_", " ")); ax[k].set_ylabel("95th-percentile response time (ms)")
ax[0].legend(frameon=False); fig.tight_layout(); fig.savefig(os.path.join(a.out, "fig_e4_drr_wfq.png"), dpi=300); plt.close(fig)
print("done in %.0fs; outputs in %s/" % (time.time() - t0, a.out))
