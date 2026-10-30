# Secure QoS Network Design – Simulator (ESOF 4310 / ESOF 5333, Fall 2026)

Discrete-event simulator of one 10 Mbps bottleneck gateway carrying voice, video and data, with
FIFO, SPQ, DRR and WFQ schedulers and an HMAC-based authenticated priority-marking security study.

## Install and run
```bash
python3 -m venv .venv && source .venv/bin/activate      # optional
pip install -r requirements.txt                          # Python 3.10+
python -m unittest discover -s tests -v                  # 16 verification tests (about 4 s)
python run_experiments.py --quick --out results_quick    # smoke test, 30 s runs (about 40 s)
python run_experiments.py                                # full study: 300 s runs, seeds 1 2 3 (about 6-10 min on 1 core)
python security_demo.py                                  # packet-level security demonstration only
```
Options: `--duration`, `--warmup`, `--seeds`, `--out`. Everything is deterministic given the seeds.

## Layout
| Path | Purpose |
|---|---|
| `qos/config.py` | Constants and **all design choices** (buffer split, DRR quanta, WFQ weights, tag size, source mixes) |
| `qos/traffic.py` | Exponential ON/OFF sources; one trace per (mix, seed), shared by all schedulers |
| `qos/schedulers.py` | FIFO, SPQ, DRR (deficit round robin), WFQ (self-clocked fair queueing virtual time) |
| `qos/security.py` | HMAC-SHA-256 truncated to 128 bits (Python `hmac`), verification micro-benchmark |
| `qos/simulator.py` | Event loop, packet accounting, metrics (W, D, D95, loss, Q, S, goodput, utilization, Jain) |
| `run_experiments.py` | Studies E1-E4, raw CSV, summaries (mean, 95% CI), `tables.md`, figures |
| `tests/test_qos.py` | Hand-checked scheduler, timing, buffer, conservation, tie and security tests |
| `results/` | `raw_runs.csv` (every parameter and seed), `summary_E*.csv`, `tables.md`, `fig_*.png`, `security_demo.txt` |

## Model summary
* Link C = 10 Mbps, non-preemptive; transmission time s = 8L/C (L includes the 16 B tag when security is on).
* Event types: packet arrival and packet departure. **Same-timestamp rule: departure before arrival**, then packet index.
* ON/OFF source state changes are pre-generated (so every scheduler gets the identical trace); their count is stored in `state_changes`.
* Total buffer K packets: FIFO one queue of K; SPQ/DRR/WFQ split K = 20% voice / 50% video / 30% data. Full queue = tail drop; every drop/reclassification is recorded with its reason (`BUFFER_FULL`, `AUTH_FAIL_RECLASSIFIED`).
* Warm-up 10 s discarded. Packets are counted if they arrive in [warm-up, T); the queue is drained after T so no delay bias. Throughput counts departures in the window.
* Offered load rho and source mixes: 20/14/11 voice/video/data sources at rho=0.3, scaled x2, x3, x3.667 for 0.6, 0.9, 1.1 (actual 0.30, 0.60, 0.90, 1.09).
* DRR quanta 1000/2000/1500 B; WFQ weights 2/4/3 (same ratio). SPQ order voice > video > data.
* Jain index: x_c = throughput_c / weighted max-min fair share of the class's measured offered rate (weights 2:4:3); this avoids penalising an under-subscribed class.
* Security study: authorized sources append a 16 B HMAC tag over (source, mark, sequence, length). Attackers send video-sized packets marked voice with a forged tag. The gateway recomputes the tag; failures are reclassified to the data queue. Verification delay uses the measured host time.
* Statistics: mean and 95% CI over 3 seeds, t distribution (t = 4.303, 2 d.o.f.).

## Known limitations (state these in the report)
Open-loop sources (no TCP feedback), single hop, no propagation delay or L2/IP headers, shared-key HMAC (no per-sender identity,
replay only guarded by a sequence number), WFQ uses SCFQ virtual time (an approximation of exact GPS-based WFQ), verification time
is a Python micro-benchmark rather than gateway hardware, and only 3 seeds.

## Attribution
Written for the course project with AI assistance (Claude). Libraries: numpy, pandas, scipy, matplotlib, Python standard library.
Add your group's contribution statement here as required by the rubric.
