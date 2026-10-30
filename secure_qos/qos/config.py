"""Fixed project constants and the reference traffic table (course brief, Table 2)."""
C_BPS = 10_000_000            # bottleneck link capacity, bits per second (fixed by the brief)
CLASS_NAMES = ["voice", "video", "data", "attacker"]   # index 3 only exists in the security study
VOICE, VIDEO, DATA, ATTACKER = 0, 1, 2, 3

# peak rate (bps), mean ON (s), mean OFF (s), packet size (bytes)
TRAFFIC = {
    VOICE: dict(peak=64_000,  on=0.36, off=0.64, size=120),
    VIDEO: dict(peak=384_000, on=0.29, off=0.71, size=1000),
    DATA:  dict(peak=256_000, on=0.35, off=0.65, size=583),
}
# An attacker behaves like a video source (same rate/size) but marks its packets as voice.
ATTACKER_PROFILE = TRAFFIC[VIDEO]

# ---- design choices (justify these in the report) ----
BUFFER_SPLIT = (0.2, 0.5, 0.3)        # share of K given to voice, video, data queues
DRR_QUANTA = (1000, 2000, 1500)       # bytes per visit; each >= largest packet (1000 B)
WFQ_WEIGHTS = (2.0, 4.0, 3.0)         # same ratio as DRR quanta -> fair DRR/WFQ comparison
TAG_BYTES = 16                        # HMAC-SHA-256 truncated to 128 bits (RFC 4868)
SECURITY_KEY = b"polarnova-shared-demo-key-DO-NOT-USE-IN-PRODUCTION"

# source counts (voice, video, data) per target load; others scale from the 0.3 mix 20:14:11
BASE_MIX = (20, 14, 11)
BASE_RHO = 0.3

def mix_for_rho(rho):
    k = rho / BASE_RHO
    return tuple(int(round(n * k)) for n in BASE_MIX)

def offered_rho(counts, attackers=0):
    r = 0.0
    for c, n in zip((VOICE, VIDEO, DATA), counts):
        p = TRAFFIC[c]; r += n * p["peak"] * p["on"] / (p["on"] + p["off"])
    p = ATTACKER_PROFILE
    r += attackers * p["peak"] * p["on"] / (p["on"] + p["off"])
    return r / C_BPS

def split_buffer(K):
    """Divide total buffer K among three class queues so the sum is exactly K."""
    v = max(1, int(K * BUFFER_SPLIT[0])); d = max(1, int(K * BUFFER_SPLIT[2]))
    return (v, K - v - d, d)
