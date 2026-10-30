"""Packet-level demonstration of the security study (valid accepted, modified/forged rejected, measured cost)."""
import os, sys
from qos import security as sec
from qos.config import *

def demo(path):
    key = SECURITY_KEY; lines = []
    h = sec.header(src_id=7, mark=VOICE, seq=1, length=120); tag = sec.make_tag(key, h)
    lines.append(f"[1] VALID  voice packet (src 7, mark=voice, seq 1, 120 B), tag={tag.hex()[:16]}...  -> accepted: {sec.verify(key, h, tag)}")
    h2 = sec.header(7, VOICE, 1, 121)
    lines.append(f"[2] MODIFIED packet (length changed 120->121, same tag)                            -> accepted: {sec.verify(key, h2, tag)}  (rejected)")
    h3 = sec.header(7, VIDEO, 1, 120)
    lines.append(f"[3] MODIFIED priority mark (voice->video, same tag)                              -> accepted: {sec.verify(key, h3, tag)}  (rejected)")
    ha = sec.header(99, VOICE, 1, 1000)
    lines.append(f"[4] UNAUTHORIZED source claims voice mark, forged random tag                       -> accepted: {sec.verify(key, ha, sec.forged_tag())}  (reclassified to data queue)")
    us = sec.benchmark_verify_us()
    lines.append("")
    lines.append(f"Tag overhead: {TAG_BYTES} B per packet -> extra transmission time {8*TAG_BYTES/C_BPS*1e6:.1f} us at 10 Mbps")
    for c in (VOICE, VIDEO, DATA):
        L = TRAFFIC[c]["size"]
        lines.append(f"  {CLASS_NAMES[c]:5s}: {L} B -> {L+TAG_BYTES} B  (+{100*TAG_BYTES/L:.1f}% bytes, {8*L/C_BPS*1e6:.1f} -> {8*(L+TAG_BYTES)/C_BPS*1e6:.1f} us)")
    lines.append(f"Measured HMAC recompute+compare time (gateway verification) on this host (Python hmac): {us:.2f} us/packet")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    open(path, "w").write("\n".join(lines) + "\n"); print("\n".join(lines)); return us

if __name__ == "__main__":
    demo(os.path.join("results", "security_demo.txt"))
