"""Hand-checkable verification tests. Run: python -m unittest discover -s tests -v"""
import sys, os, unittest
import numpy as np
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from qos.config import *
from qos.schedulers import FIFO, SPQ, DRR, WFQ
from qos.simulator import run, maxmin, jain
from qos.traffic import build_trace
from qos import security as sec

def mk(times, sizes=None, cls=None, mark=None, auth=None):
    n = len(times)
    return dict(t=np.array(times, float), size=np.array(sizes or [1000] * n, np.int32),
                cls=np.array(cls or [0] * n, np.int8), mark=np.array(mark or (cls or [0] * n), np.int8),
                auth=np.array(auth or [True] * n, bool), state_changes=0)

class Calc(unittest.TestCase):
    def test_tx_time(self):
        self.assertAlmostEqual(8 * 120 / C_BPS, 96e-6); self.assertAlmostEqual(8 * 1000 / C_BPS, 800e-6)
        self.assertAlmostEqual(8 * 583 / C_BPS, 466.4e-6); self.assertAlmostEqual(8 * TAG_BYTES / C_BPS, 12.8e-6)
    def test_offered_load(self):
        self.assertAlmostEqual(offered_rho((20, 14, 11)), 0.3005, places=3)
        self.assertAlmostEqual(offered_rho(mix_for_rho(1.1)), 1.0945, places=3)
    def test_buffer_split_sums_to_K(self):
        for K in (10, 25, 50, 100, 200): self.assertEqual(sum(split_buffer(K)), K)
    def test_maxmin_and_jain(self):
        self.assertEqual(maxmin([1, 1, 10], [1, 1, 1], 6), [1, 1, 4]); self.assertAlmostEqual(jain([1, 1, 1]), 1.0)

class Sched(unittest.TestCase):
    def test_fifo_order_and_drop(self):
        f = FIFO(2, [100] * 5)
        self.assertTrue(f.enqueue(0, 0)); self.assertTrue(f.enqueue(1, 2)); self.assertFalse(f.enqueue(2, 1))
        self.assertEqual([f.dequeue(), f.dequeue(), f.dequeue()], [0, 1, None])
    def test_spq_priority(self):
        s = SPQ(100, [100] * 3); s.enqueue(0, 2); s.enqueue(1, 1); s.enqueue(2, 0)
        self.assertEqual([s.dequeue() for _ in range(3)], [2, 1, 0])
    def test_drr_hand_sequence(self):
        d = DRR(100, [500] * 8, quanta=(1000, 1000, 1000))
        for k in range(4): d.enqueue(k, 0)
        for k in range(4, 8): d.enqueue(k, 1)
        self.assertEqual([d.dequeue() for _ in range(8)], [0, 1, 4, 5, 2, 3, 6, 7])
    def test_wfq_weighted_service(self):
        w = WFQ(100, [100] * 12, weights=(2, 1, 1))
        for k in range(8): w.enqueue(k, 0)
        for k in range(8, 12): w.enqueue(k, 1)
        order = [w.dequeue() for _ in range(6)]
        self.assertEqual([0 if o < 8 else 1 for o in order], [0, 0, 1, 0, 0, 1])
    def test_per_class_buffer_full(self):
        s = SPQ(10, [100] * 10)           # caps (2,5,3)
        self.assertTrue(s.enqueue(0, 0)); self.assertTrue(s.enqueue(1, 0)); self.assertFalse(s.enqueue(2, 0))

class Sim(unittest.TestCase):
    def test_tie_departure_before_arrival(self):
        log = []; run(mk([0.0, 0.0008]), "fifo", 10, T=1, warmup=0, log=log)
        order = [(e[1], e[2]) for e in log]
        self.assertLess(order.index(("DEP", 0)), order.index(("ARR", 1)))
    def test_hand_trace_delays(self):
        # two 1000 B packets at t=0 -> second waits 800 us, responses 800 us and 1600 us
        r = run(mk([0.0, 0.0]), "fifo", 10, T=1, warmup=0)
        self.assertAlmostEqual(r["voice_W_ms"], 0.4); self.assertAlmostEqual(r["voice_D_ms"], 1.2)
    def test_buffer_drop_logged(self):
        r = run(mk([0.0] * 5), "fifo", 2, T=1, warmup=0)        # 1 in service + 2 queued, 2 dropped
        self.assertEqual(r["all_drop"], 2); self.assertEqual(r["reasons"]["voice:BUFFER_FULL"], 2)
    def test_conservation_all_schedulers(self):
        tr = build_trace(mix_for_rho(1.1), 0, 7, 20)
        for s in ("fifo", "spq", "drr", "wfq"):
            self.assertEqual(run(tr, s, 50, T=20, warmup=2)["conservation_ok"], 1, s)
    def test_underload_throughput_matches_offered(self):
        tr = build_trace(mix_for_rho(0.3), 0, 3, 120)
        r = run(tr, "fifo", 100, T=120, warmup=10)
        self.assertAlmostEqual(r["all_S_mbps"] / 10, 0.30, delta=0.03); self.assertEqual(r["all_loss"], 0.0)

class Security(unittest.TestCase):
    def test_valid_accepted_modified_rejected(self):
        h = sec.header(1, 0, 5, 120); t = sec.make_tag(SECURITY_KEY, h)
        self.assertTrue(sec.verify(SECURITY_KEY, h, t))
        self.assertFalse(sec.verify(SECURITY_KEY, sec.header(1, 0, 5, 121), t))     # modified length
        self.assertFalse(sec.verify(SECURITY_KEY, sec.header(1, 1, 5, 120), t))     # modified class mark
        self.assertFalse(sec.verify(SECURITY_KEY, h, sec.forged_tag()))             # forged tag
        self.assertEqual(len(t), 16)
    def test_forged_voice_mark_reclassified(self):
        tr = build_trace(mix_for_rho(0.9), 10, 2, 40)
        off = run(tr, "spq", 100, security=False, T=40, warmup=5); on = run(tr, "spq", 100, security=True, T=40, warmup=5)
        self.assertGreater(off["attacker_hp_share"], 0.2); self.assertEqual(on["attacker_hp_share"], 0.0)
        self.assertGreater(on["sec_bad"], 0); self.assertGreater(on["sec_ok"], 0)

if __name__ == "__main__":
    unittest.main()
