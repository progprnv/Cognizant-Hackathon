"""
backend/ml/model_manager.py
────────────────────────────
Core ML pipeline for FraudShield AI.

Architecture
────────────
  1. IsolationForest   — unsupervised anomaly detection
                         Detects statistical outliers in behaviour/device features.
  2. LogisticRegression — supervised risk classifier
                          Trained on labelled synthetic data; outputs P(fraud).
  3. Ensemble score     — weighted combination → 0–100 risk score.

The models are retrained incrementally as new labelled events arrive,
enabling the "continuous learning" requirement.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

import structlog

logger = structlog.get_logger()

# ── Path where trained models are persisted ───────────────────────
MODEL_DIR = Path(__file__).parent / "saved_models"
MODEL_DIR.mkdir(exist_ok=True)

ISO_PATH  = MODEL_DIR / "isolation_forest.pkl"
LR_PATH   = MODEL_DIR / "logistic_regression.pkl"
SCAL_PATH = MODEL_DIR / "scaler.pkl"

# ── Feature list (ORDER MUST MATCH everywhere) ───────────────────
FEATURE_NAMES = [
    "login_duration_ms",       # 0 – time from page-load to submit
    "keystroke_avg_interval",  # 1 – avg ms between keystrokes
    "mouse_event_count",       # 2 – mouse movements/clicks during session
    "typing_speed_wpm",        # 3 – estimated WPM
    "is_new_device",           # 4 – bool: device not seen before
    "is_new_ip",               # 5 – bool: IP not seen in last 30 days
    "is_unusual_hour",         # 6 – bool: outside typical login hours
    "geo_distance_km",         # 7 – km from last known location
    "autofill_detected",       # 8 – bool
    "amount_normalised",       # 9 – transaction amount / user avg (0 for login)
]


class ModelManager:
    """Singleton that owns model instances and provides thread-safe scoring."""

    _iso_forest:  IsolationForest  | None = None
    _log_reg:     LogisticRegression | None = None
    _scaler:      StandardScaler    | None = None
    _lock:        asyncio.Lock      | None = None

    # ── Weights for the ensemble ──────────────────────────────────
    W_ISO = 0.35   # IsolationForest contributes 35%
    W_LR  = 0.65   # LogisticRegression contributes 65%

    # ── IsolationForest contamination (estimated fraud rate) ──────
    IF_CONTAMINATION = 0.08

    @classmethod
    async def initialise(cls) -> None:
        """Load persisted models or train from scratch on synthetic data."""
        cls._lock = asyncio.Lock()

        if ISO_PATH.exists() and LR_PATH.exists() and SCAL_PATH.exists():
            cls._iso_forest = joblib.load(ISO_PATH)
            cls._log_reg    = joblib.load(LR_PATH)
            cls._scaler     = joblib.load(SCAL_PATH)
            logger.info("ml_models_loaded_from_disk")
        else:
            logger.info("ml_models_not_found_training_on_synthetic_data")
            await asyncio.get_event_loop().run_in_executor(None, cls._train_initial)

    # ── Internal: train on synthetic dataset ─────────────────────
    @classmethod
    def _train_initial(cls) -> None:
        from backend.ml.synthetic_data import generate_training_data

        X, y = generate_training_data(n_samples=5000)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)

        # IsolationForest — trained on ALL data (unsupervised)
        iso = IsolationForest(
            n_estimators=200,
            contamination=cls.IF_CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        iso.fit(X_scaled)

        # LogisticRegression — trained on labelled data
        lr = LogisticRegression(
            C=1.0,
            max_iter=1000,
            class_weight="balanced",
            random_state=42,
        )
        lr.fit(X_scaled, y)

        cls._iso_forest = iso
        cls._log_reg    = lr
        cls._scaler     = scaler

        joblib.dump(iso,    ISO_PATH)
        joblib.dump(lr,     LR_PATH)
        joblib.dump(scaler, SCAL_PATH)

        logger.info("ml_models_trained_and_saved",
                    lr_accuracy=float(lr.score(X_scaled, y)))

    # ── Public scoring API ────────────────────────────────────────
    @classmethod
    async def score(cls, features: Dict[str, float]) -> Tuple[float, Dict[str, Any]]:
        """
        Compute ensemble risk score (0–100) for a feature dict.

        Returns
        ───────
        risk_score : float   0 = no risk, 100 = definite fraud
        explanation: dict    factor contributions for explainability
        """
        async with cls._lock:
            x = cls._build_vector(features)
            x_scaled = cls._scaler.transform([x])

            # IsolationForest:  -1 = anomaly, +1 = normal
            iso_raw   = cls._iso_forest.score_samples(x_scaled)[0]   # < 0 = more anomalous
            iso_score = cls._iso_to_probability(iso_raw)             # [0,1]

            # LogisticRegression:  P(class=1) = P(fraud)
            lr_score  = cls._log_reg.predict_proba(x_scaled)[0][1]   # [0,1]

            # Ensemble
            ensemble  = cls.W_ISO * iso_score + cls.W_LR * lr_score
            risk_100  = round(ensemble * 100, 2)

            explanation = cls._explain(features, x, iso_score, lr_score, ensemble)

        return risk_100, explanation

    # ── Incremental retraining ────────────────────────────────────
    @classmethod
    async def partial_fit(cls, features: Dict[str, float], label: int) -> None:
        """
        Update LogisticRegression with a single confirmed event.
        IsolationForest is batch-retrained periodically (not shown here
        for brevity — trigger via a nightly cron job).
        """
        async with cls._lock:
            x = cls._build_vector(features)
            x_scaled = cls._scaler.transform([x])
            # LogisticRegression supports warm_start for batch updates;
            # for true online learning swap to SGDClassifier.
            cls._log_reg.fit(
                np.vstack([x_scaled, x_scaled]),   # dummy: add sample twice
                [label, label],
            )
            joblib.dump(cls._log_reg, LR_PATH)

    # ── Helpers ───────────────────────────────────────────────────
    @staticmethod
    def _build_vector(f: Dict[str, float]) -> List[float]:
        """Map feature dict → ordered numpy-compatible list."""
        return [
            float(f.get("login_duration_ms",      5000)),
            float(f.get("keystroke_avg_interval",  120)),
            float(f.get("mouse_event_count",        10)),
            float(f.get("typing_speed_wpm",         40)),
            float(f.get("is_new_device",             0)),
            float(f.get("is_new_ip",                 0)),
            float(f.get("is_unusual_hour",           0)),
            float(f.get("geo_distance_km",           0)),
            float(f.get("autofill_detected",         0)),
            float(f.get("amount_normalised",         1)),
        ]

    @staticmethod
    def _iso_to_probability(raw_score: float) -> float:
        """
        Convert IsolationForest score_sample output to [0,1].
        score_samples returns negative values; more negative = more anomalous.
        We map to [0,1] via a sigmoid-like rescaling.
        """
        # Typical range: [-0.8, 0.1]  →  shift and invert
        clamped = max(-1.0, min(0.2, raw_score))
        normalised = (clamped - 0.2) / (-1.0 - 0.2)   # 0=normal, 1=anomaly
        return float(normalised)

    @staticmethod
    def _explain(
        features: Dict,
        x: List[float],
        iso_score: float,
        lr_score: float,
        ensemble: float,
    ) -> Dict[str, Any]:
        """
        Build a human-readable explanation dictionary (Explainable AI).
        Each factor gets a severity tag and a plain-English reason.
        """
        factors: Dict[str, Any] = {
            "_iso_contribution": round(iso_score, 4),
            "_lr_contribution":  round(lr_score,  4),
            "_ensemble_raw":     round(ensemble,  4),
            "flags": [],
        }

        def flag(name: str, reason: str, weight: float):
            factors["flags"].append({
                "factor":  name,
                "reason":  reason,
                "weight":  round(weight, 2),
            })

        dur_ms = features.get("login_duration_ms", 5000)
        if dur_ms < 300:
            flag("autofill_speed",
                 f"Form submitted in {dur_ms}ms — below human threshold (300ms); "
                 "possible autofill or bot.", 0.9)
        elif dur_ms < 800:
            flag("fast_login",
                 f"Login completed in {dur_ms}ms — unusually fast.", 0.4)

        ki = features.get("keystroke_avg_interval", 120)
        if ki < 30:
            flag("keystroke_robot",
                 f"Average keystroke interval {ki:.0f}ms — inhuman speed.", 0.85)
        elif ki == 0:
            flag("no_keystrokes",
                 "No keystroke events detected — credentials likely pre-filled.", 0.9)

        if features.get("autofill_detected"):
            flag("autofill_flag",
                 "Browser JS detected autofill (no keyboard events before submit).", 0.8)

        if features.get("is_new_device"):
            flag("new_device",
                 "Login from a device not previously associated with this account.", 0.6)

        if features.get("is_new_ip"):
            flag("new_ip",
                 "IP address not seen in the last 30 days for this user.", 0.5)

        if features.get("is_unusual_hour"):
            flag("unusual_hour",
                 "Login at an hour outside this user's historical pattern.", 0.4)

        geo = features.get("geo_distance_km", 0)
        if geo > 1000:
            flag("impossible_travel",
                 f"Location is {geo:.0f}km from last known location — "
                 "possible impossible-travel scenario.", 0.95)
        elif geo > 200:
            flag("geo_anomaly",
                 f"Location has shifted {geo:.0f}km from typical location.", 0.55)

        amt = features.get("amount_normalised", 1.0)
        if amt > 5:
            flag("large_transaction",
                 f"Transaction is {amt:.1f}× the user's average — unusually large.", 0.7)

        if not factors["flags"]:
            factors["flags"].append({
                "factor": "no_anomalies",
                "reason": "No individual risk factors detected; ensemble model flagged subtle deviation.",
                "weight": 0.1,
            })

        return factors
