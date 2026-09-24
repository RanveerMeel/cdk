#!/usr/bin/env python3
"""Train the public CDKLM1 demo model (message priority: ROUTINE vs URGENT).

This is a deliberately tiny, synthetic, neutral task used to exercise CDK's
integer inference runtime (user/ml) end to end. It is NOT a production model
and contains no private data.

Pure Python, no dependencies, deterministic. Writes:
  user/models/priority-demo.cdklm    the quantized model
  user/models/priority-demo.vectors  expected outputs, computed here by an
                                     independent Python implementation of the
                                     featurizer and integer inference; the
                                     Rust tests must reproduce them exactly.

Usage: tools/train_demo_model.py
"""

import math
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_MODEL = ROOT / "user/models/priority-demo.cdklm"
OUT_VECTORS = ROOT / "user/models/priority-demo.vectors"

N_FEATURES = 128
LABELS = ["ROUTINE", "URGENT"]

ROUTINE = [
    "weekly report attached for review",
    "lunch menu for friday",
    "reminder: team meeting next tuesday",
    "please find the minutes from today",
    "the office will be closed on the holiday",
    "new coffee machine in the kitchen",
    "draft agenda for next month",
    "thanks for the update, looks good",
    "quarterly newsletter is out",
    "sharing the slides from the talk",
    "parking lot resurfacing next week",
    "welcome our new team member",
    "photos from the offsite",
    "documentation has been updated",
    "invoice paid, no action needed",
    "library books due at the end of the month",
    "training session recording available",
    "reminder to submit timesheets by friday",
]
URGENT = [
    "server down, production outage now",
    "urgent: database not responding",
    "fire alarm in building b evacuate",
    "critical security patch needed today",
    "outage affecting all customers",
    "payment system failing right now",
    "urgent call me immediately",
    "power failure in the data center",
    "site is down please respond asap",
    "critical error in checkout, fix now",
    "network down across the office",
    "emergency: water leak in server room",
    "production deploy broke login",
    "respond immediately, system crash",
    "backup job failed, data at risk",
    "incident: api returning errors",
    "urgent: disk full on main server",
    "security breach detected, act now",
]
HELD_OUT = [
    ("monthly newsletter and photos", "ROUTINE"),
    ("meeting notes from tuesday", "ROUTINE"),
    ("office closed friday for the holiday", "ROUTINE"),
    ("thanks, the slides look good", "ROUTINE"),
    ("new documentation for the api", "ROUTINE"),
    ("URGENT: production server down!", "URGENT"),
    ("login broken, respond now", "URGENT"),
    ("database outage, call immediately", "URGENT"),
    ("critical: payment errors right now", "URGENT"),
    ("emergency in the server room", "URGENT"),
]


def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def trigram_features(text: str, n: int = N_FEATURES) -> list:
    """Independent re-implementation of cdk_ml::text::hashed_trigrams."""
    raw = text.encode("ascii", "replace")[:512]
    norm = bytearray(b" ")
    for b in raw:
        c = chr(b)
        norm.append(ord(c.lower()) if c.isascii() and c.isalnum() else ord(" "))
    norm.append(ord(" "))
    x = [0] * n
    for i in range(len(norm) - 2):
        x[fnv1a32(bytes(norm[i : i + 3])) % n] = 255
    return x


def train(samples, epochs=400, lr=0.5, l2=1e-3, seed=7):
    rng = random.Random(seed)
    k = len(LABELS)
    w = [[0.0] * N_FEATURES for _ in range(k)]
    b = [0.0] * k
    data = [([v / 255.0 for v in trigram_features(t)], y) for t, y in samples]
    for _ in range(epochs):
        rng.shuffle(data)
        for x, y in data:
            z = [b[c] + sum(wi * xi for wi, xi in zip(w[c], x)) for c in range(k)]
            m = max(z)
            e = [math.exp(v - m) for v in z]
            s = sum(e)
            p = [v / s for v in e]
            for c in range(k):
                g = p[c] - (1.0 if c == y else 0.0)
                b[c] -= lr * g
                for i in range(N_FEATURES):
                    if x[i]:
                        w[c][i] -= lr * (g * x[i] + l2 * w[c][i])
    return w, b


def quantize(w, b):
    w_scale = max(abs(v) for row in w for v in row) / 127.0
    wq = [[max(-127, min(127, round(v / w_scale))) for v in row] for row in w]
    # Integer logit = bias_q + sum(wq * x_q) with x_q = 255 * x, so one real
    # logit unit equals 255 / w_scale integer units.
    bq = [round(v * 255.0 / w_scale) for v in b]
    scale_micro = round(w_scale / 255.0 * 1e6)
    return wq, bq, scale_micro


def serialize(wq, bq, scale_micro) -> bytes:
    out = bytearray(b"CDKLM1\0\0")
    out += struct.pack("<HBBI", N_FEATURES, len(LABELS), 1, scale_micro)
    for label in LABELS:
        out += label.encode().ljust(16, b"\0")
    for v in bq:
        out += struct.pack("<i", v)
    for row in wq:
        out += bytes((v & 0xFF) for v in row)
    return bytes(out)


def int_logits(wq, bq, x):
    return [bq[c] + sum(wi * xi for wi, xi in zip(wq[c], x)) for c in range(len(LABELS))]


def main():
    samples = [(t, 0) for t in ROUTINE] + [(t, 1) for t in URGENT]
    w, b = train(samples)
    wq, bq, scale_micro = quantize(w, b)
    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    OUT_MODEL.write_bytes(serialize(wq, bq, scale_micro))

    lines = [
        "# text<TAB>label<TAB>integer logits (from tools/train_demo_model.py)",
    ]
    correct = 0
    cases = [(t, LABELS[y]) for t, y in samples[:4]] + HELD_OUT
    for text, expected in cases:
        z = int_logits(wq, bq, trigram_features(text))
        best = max(range(len(z)), key=lambda c: (z[c], -c))
        correct += LABELS[best] == expected
        lines.append(f"{text}\t{LABELS[best]}\t{','.join(str(v) for v in z)}")
    OUT_VECTORS.write_text("\n".join(lines) + "\n")
    held = sum(
        LABELS[max(range(2), key=lambda c: (int_logits(wq, bq, trigram_features(t))[c], -c))] == e
        for t, e in HELD_OUT
    )
    print(
        f"wrote {OUT_MODEL.relative_to(ROOT)} ({OUT_MODEL.stat().st_size} bytes), "
        f"held-out accuracy {held}/{len(HELD_OUT)}, vectors {len(cases)}"
    )


if __name__ == "__main__":
    main()
