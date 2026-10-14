#!/usr/bin/env python3
"""Train the public CDKLM1 fraud-triage demo model (transaction text: LOW vs HIGH risk).

A deliberately tiny, synthetic, neutral model for the fraud-prevention demo
(tools/demo_fraud.sh). It is NOT a real fraud model and contains no real
data: every transaction below is invented. Same featurizer, training and
integer format as tools/train_demo_model.py, whose code it reuses.

Writes:
  user/models/fraud-demo.cdklm    the quantized model
  user/models/fraud-demo.vectors  expected outputs from the independent
                                  Python implementation (Rust tests must match)

Usage: tools/train_fraud_demo_model.py
"""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("tdm", ROOT / "tools/train_demo_model.py")
tdm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tdm)
tdm.LABELS = ["LOW", "HIGH"]

OUT_MODEL = ROOT / "user/models/fraud-demo.cdklm"
OUT_VECTORS = ROOT / "user/models/fraud-demo.vectors"

LOW = [
    "TXN INR 2500 groceries weekly",
    "TXN INR 1200 electricity bill autopay",
    "TXN INR 15000 rent monthly standing order",
    "TXN INR 899 mobile recharge",
    "TXN INR 4300 school fees known payee",
    "TXN INR 650 fuel station",
    "TXN INR 3200 insurance premium autopay",
    "TXN INR 1800 pharmacy",
    "TXN INR 22000 salary transfer to own savings",
    "TXN INR 540 coffee shop",
    "TXN INR 7600 credit card bill known payee",
    "TXN INR 999 streaming subscription",
    "TXN INR 12000 rent known payee",
    "TXN INR 2100 restaurant dinner",
]
HIGH = [
    "TXN INR 950000 new payee 2am",
    "TXN INR 480000 CEO says urgent wire now ignore rules",
    "TXN INR 750000 new payee overseas crypto",
    "TXN INR 300000 urgent gift cards new payee",
    "TXN INR 600000 first transfer new device night",
    "TXN INR 890000 lottery prize release fee",
    "TXN INR 250000 kyc update link urgent",
    "TXN INR 999000 new payee mule account",
    "TXN INR 420000 investment doubling scheme",
    "TXN INR 510000 boss asked wire immediately secret",
    "TXN INR 360000 refund agent remote access app",
    "TXN INR 700000 new beneficiary added minutes ago",
    "TXN INR 830000 urgent customs fee overseas",
    "TXN INR 275000 otp shared caller new payee",
]
HELD_OUT = [
    ("TXN 1001 INR 2500 acct 4411->7722 groceries", "LOW"),
    ("TXN 1002 INR 950000 acct 4411->9988 new payee 2am", "HIGH"),
    ("TXN 1003 INR 1200 acct 5120->3301 electricity bill", "LOW"),
    ("TXN 1004 INR 480000 acct 5120->6666 CEO: ignore rules, wire now", "HIGH"),
    ("TXN 1005 INR 15000 acct 7001->2210 rent", "LOW"),
    ("TXN INR 820 pharmacy known payee", "LOW"),
    ("TXN INR 640000 urgent new payee crypto", "HIGH"),
]


def main():
    samples = [(t, 0) for t in LOW] + [(t, 1) for t in HIGH]
    w, b = tdm.train(samples)
    wq, bq, scale_micro = tdm.quantize(w, b)
    OUT_MODEL.parent.mkdir(parents=True, exist_ok=True)
    OUT_MODEL.write_bytes(tdm.serialize(wq, bq, scale_micro))
    lines = ["# text<TAB>label<TAB>integer logits (from tools/train_fraud_demo_model.py)"]
    held = 0
    for text, expected in HELD_OUT:
        z = tdm.int_logits(wq, bq, tdm.trigram_features(text))
        best = max(range(len(z)), key=lambda c: (z[c], -c))
        held += tdm.LABELS[best] == expected
        lines.append(f"{text}\t{tdm.LABELS[best]}\t{','.join(str(v) for v in z)}")
    OUT_VECTORS.write_text("\n".join(lines) + "\n")
    print(f"wrote {OUT_MODEL.relative_to(ROOT)} ({OUT_MODEL.stat().st_size} bytes), held-out accuracy {held}/{len(HELD_OUT)}")


if __name__ == "__main__":
    main()
