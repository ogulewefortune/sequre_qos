"""Authenticated priority marking using HMAC-SHA-256 truncated to 128 bits (Python standard-library hmac)."""
import hmac, hashlib, os, struct, time
from .config import SECURITY_KEY, TAG_BYTES

def header(src_id, mark, seq, length):
    return struct.pack("!IBIH", src_id, mark, seq, length)

def make_tag(key, hdr):
    return hmac.digest(key, hdr, hashlib.sha256)[:TAG_BYTES]

def verify(key, hdr, tag):
    return hmac.compare_digest(make_tag(key, hdr), tag)

def forged_tag():
    return os.urandom(TAG_BYTES)

def benchmark_verify_us(n=200_000):
    """Measured per-packet verification time on this host (microseconds)."""
    hdr = header(1, 0, 1, 120); tag = make_tag(SECURITY_KEY, hdr); t0 = time.perf_counter()
    for _ in range(n): verify(SECURITY_KEY, hdr, tag)
    return (time.perf_counter() - t0) / n * 1e6
