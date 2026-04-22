"""
backend/ml/synthetic_data.py
──────────────────────────────
Generates a realistic labelled dataset for bootstrapping the ML models.

Normal users
─────────────
  • Login duration:  2000–15000 ms  (Gaussian around 6000)
  • Keystroke interval: 80–250 ms
  • Mouse events: 5–50
  • Typing speed: 25–80 WPM
  • Rarely new device / new IP

Fraudulent patterns (6 archetypes)
────────────────────────────────────
  1. Autofill / bot:     duration < 300 ms, zero keystrokes
  2. Credential stuffing: new device + new IP + unusual hour
  3. Same-device stealer: known device BUT behaviour deviation
  4. Impossible travel:  geo_distance > 2000 km
  5. Large transaction:  amount_normalised > 8
  6. Mixed:              combination of moderate signals
"""

from __future__ import annotations

import numpy as np
import pandas as pd


RNG = np.random.default_rng(42)


def generate_training_data(n_samples: int = 5000):
    """
    Returns
    ───────
    X : ndarray (n_samples, 10) — feature matrix
    y : ndarray (n_samples,)    — labels  0=legit, 1=fraud
    """
    n_fraud  = int(n_samples * 0.08)   # 8% fraud rate
    n_legit  = n_samples - n_fraud

    legit  = _generate_legit(n_legit)
    fraud  = _generate_fraud(n_fraud)

    X = np.vstack([legit, fraud])
    y = np.concatenate([np.zeros(n_legit), np.ones(n_fraud)])

    # Shuffle
    idx = RNG.permutation(len(y))
    return X[idx], y[idx]


# ── Legitimate sessions ───────────────────────────────────────────
def _generate_legit(n: int) -> np.ndarray:
    rows = []
    for _ in range(n):
        dur       = max(500, RNG.normal(6000, 2000))
        ki        = max(50,  RNG.normal(130, 40))
        mouse     = int(RNG.normal(20, 8))
        wpm       = max(10,  RNG.normal(45, 12))
        new_dev   = 0 if RNG.random() > 0.05 else 1
        new_ip    = 0 if RNG.random() > 0.08 else 1
        uniq_hr   = 0 if RNG.random() > 0.07 else 1
        geo       = abs(RNG.normal(0, 30))
        autofill  = 0
        amt_norm  = max(0, RNG.normal(1.0, 0.3))
        rows.append([dur, ki, mouse, wpm, new_dev, new_ip, uniq_hr, geo, autofill, amt_norm])
    return np.array(rows)


# ── Fraudulent sessions ───────────────────────────────────────────
def _generate_fraud(n: int) -> np.ndarray:
    rows = []
    archetypes = ["autofill", "cred_stuff", "same_device", "travel", "large_tx", "mixed"]
    weights    = [0.25,        0.20,          0.20,          0.15,    0.10,       0.10]

    for _ in range(n):
        atype = RNG.choice(archetypes, p=weights)

        if atype == "autofill":
            dur      = RNG.uniform(50, 250)
            ki       = 0.0
            mouse    = 0
            wpm      = 0.0
            new_dev  = int(RNG.random() > 0.5)
            new_ip   = int(RNG.random() > 0.4)
            uniq_hr  = int(RNG.random() > 0.5)
            geo      = abs(RNG.normal(0, 50))
            autofill = 1
            amt_norm = max(0, RNG.normal(1.2, 0.4))

        elif atype == "cred_stuff":
            dur      = RNG.uniform(200, 800)
            ki       = RNG.uniform(20, 60)
            mouse    = int(RNG.uniform(0, 3))
            wpm      = RNG.uniform(5, 20)
            new_dev  = 1
            new_ip   = 1
            uniq_hr  = 1
            geo      = RNG.uniform(500, 3000)
            autofill = int(RNG.random() > 0.5)
            amt_norm = max(0, RNG.normal(2, 1))

        elif atype == "same_device":
            # Device is known — but behaviour is anomalous
            dur      = RNG.uniform(100, 400)
            ki       = RNG.uniform(15, 50)   # suspiciously fast
            mouse    = int(RNG.uniform(0, 5))
            wpm      = RNG.uniform(100, 200) # too fast
            new_dev  = 0                     # same device!
            new_ip   = 0                     # same IP!
            uniq_hr  = int(RNG.random() > 0.4)
            geo      = abs(RNG.normal(0, 20))
            autofill = int(RNG.random() > 0.6)
            amt_norm = max(0, RNG.normal(3, 1.5))

        elif atype == "travel":
            dur      = max(500, RNG.normal(5000, 2000))
            ki       = max(50,  RNG.normal(120, 40))
            mouse    = int(RNG.normal(15, 8))
            wpm      = max(10,  RNG.normal(40, 10))
            new_dev  = int(RNG.random() > 0.3)
            new_ip   = 1
            uniq_hr  = int(RNG.random() > 0.5)
            geo      = RNG.uniform(2000, 15000)
            autofill = 0
            amt_norm = max(0, RNG.normal(1.5, 0.5))

        elif atype == "large_tx":
            dur      = max(500, RNG.normal(5500, 1500))
            ki       = max(50,  RNG.normal(115, 35))
            mouse    = int(RNG.normal(18, 7))
            wpm      = max(10,  RNG.normal(42, 10))
            new_dev  = int(RNG.random() > 0.4)
            new_ip   = int(RNG.random() > 0.4)
            uniq_hr  = int(RNG.random() > 0.6)
            geo      = abs(RNG.normal(0, 60))
            autofill = int(RNG.random() > 0.6)
            amt_norm = RNG.uniform(8, 30)

        else:  # mixed
            dur      = RNG.uniform(150, 600)
            ki       = RNG.uniform(20, 80)
            mouse    = int(RNG.uniform(0, 8))
            wpm      = RNG.uniform(20, 80)
            new_dev  = int(RNG.random() > 0.4)
            new_ip   = int(RNG.random() > 0.4)
            uniq_hr  = int(RNG.random() > 0.4)
            geo      = RNG.uniform(100, 800)
            autofill = int(RNG.random() > 0.5)
            amt_norm = max(0, RNG.normal(3, 2))

        rows.append([dur, ki, mouse, wpm, new_dev, new_ip, uniq_hr, geo, autofill, amt_norm])

    return np.array(rows)


# ── CSV export (for documentation / Jupyter notebooks) ───────────
def export_csv(path: str = "sample_dataset.csv", n: int = 2000) -> None:
    from backend.ml.model_manager import FEATURE_NAMES
    X, y = generate_training_data(n)
    df = pd.DataFrame(X, columns=FEATURE_NAMES)
    df["label"] = y.astype(int)
    df.to_csv(path, index=False)
    print(f"Saved {len(df)} rows to {path}")


if __name__ == "__main__":
    export_csv("../../database/sample_dataset.csv")
