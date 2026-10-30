"""Packet schedulers. All share one API: enqueue(i, q) -> accepted?, dequeue() -> packet index or None.
Packets are identified by integer index into the trace arrays; sizes are on-the-wire bytes."""
from collections import deque
from .config import *

class FIFO:
    name = "fifo"
    def __init__(self, K, sizes, **kw):
        self.K, self.q = K, deque()
    def enqueue(self, i, qi):
        if len(self.q) >= self.K: return False
        self.q.append(i); return True
    def dequeue(self):
        return self.q.popleft() if self.q else None

class _Multi:
    def __init__(self, K, sizes, **kw):
        self.caps = split_buffer(K); self.qs = [deque() for _ in range(3)]; self.sizes = sizes
    def enqueue(self, i, qi):
        if len(self.qs[qi]) >= self.caps[qi]: return False
        self.qs[qi].append(i); self._on_enqueue(i, qi); return True
    def _on_enqueue(self, i, qi): pass

class SPQ(_Multi):
    name = "spq"
    def dequeue(self):
        for q in self.qs:                      # voice, then video, then data
            if q: return q.popleft()
        return None

class DRR(_Multi):
    name = "drr"
    def __init__(self, K, sizes, quanta=DRR_QUANTA, **kw):
        super().__init__(K, sizes); self.quanta = quanta
        self.deficit = [0, 0, 0]; self.cur = 0; self.visiting = False
    def _advance(self):
        self.cur = (self.cur + 1) % 3; self.visiting = False
    def dequeue(self):
        if not any(self.qs): return None
        while True:
            q = self.cur
            if self.qs[q]:
                if not self.visiting:
                    self.deficit[q] += self.quanta[q]; self.visiting = True
                head = self.qs[q][0]
                if self.sizes[head] <= self.deficit[q]:
                    self.deficit[q] -= self.sizes[head]; pkt = self.qs[q].popleft()
                    if not self.qs[q]:
                        self.deficit[q] = 0; self._advance()
                    return pkt
                self._advance()
            else:
                self.deficit[q] = 0; self._advance()

class WFQ(_Multi):
    """Packet WFQ using self-clocked fair queueing (Golestani, INFOCOM 1994) virtual time:
    V = finish tag of the packet in service; F = max(F_prev, V) + L / weight."""
    name = "wfq"
    def __init__(self, K, sizes, weights=WFQ_WEIGHTS, **kw):
        super().__init__(K, sizes); self.w = weights
        self.tag = {}; self.last = [0.0, 0.0, 0.0]; self.V = 0.0
    def _on_enqueue(self, i, qi):
        f = max(self.last[qi], self.V) + self.sizes[i] / self.w[qi]
        self.last[qi] = f; self.tag[i] = f
    def dequeue(self):
        best, bq = None, -1
        for qi in range(3):
            if self.qs[qi]:
                f = self.tag[self.qs[qi][0]]
                if best is None or f < best: best, bq = f, qi     # ties -> lower class index
        if bq < 0:
            self.V = 0.0; self.last = [0.0, 0.0, 0.0]; self.tag.clear(); return None   # idle: reset
        self.V = best; i = self.qs[bq].popleft(); self.tag.pop(i, None); return i

SCHEDULERS = {"fifo": FIFO, "spq": SPQ, "drr": DRR, "wfq": WFQ}
