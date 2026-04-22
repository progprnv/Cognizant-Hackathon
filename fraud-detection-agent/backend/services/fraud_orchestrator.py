"""
backend/services/fraud_orchestrator.py
───────────────────────────────────────
Central orchestrator that coordinates all agents for a single event.

Flow for a LOGIN request:
─────────────────────────
  1. DeviceAgent.analyse()       → device features
  2. BehavioralAgent.analyse()   → behavioural features
  3. SessionAgent.analyse()      → geo / travel features
  4. Build unified feature dict
  5. ModelManager.score()        → risk score + explanation
  6. DecisionEngine.decide()     → ALLOW / OTP / BLOCK
  7. Persist event + update profiles
  8. If HIGH → publish alert
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, Optional

import structlog
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.core.config import settings
from backend.ml.model_manager import ModelManager
from backend.models.orm_models import (
    BehavioralProfile, DeviceProfile, FraudAlert,
    LoginEvent, TransactionEvent, User,
)
from backend.models.schemas import (
    BehavioralSignals, DeviceFingerprint, LoginRequest,
    RiskResult, TransactionRequest,
)
from backend.services.behavioral_agent import BehavioralAgent
from backend.services.decision_engine import DecisionEngine
from backend.services.device_agent import DeviceAgent
from backend.services.session_agent import SessionAgent

logger = structlog.get_logger()


class FraudOrchestrator:
    """Stateless orchestrator — each method receives a DB session."""

    # ════════════════════════════════════════════════════════════
    # LOGIN ASSESSMENT
    # ════════════════════════════════════════════════════════════
    @staticmethod
    async def assess_login(
        req: LoginRequest,
        ip_address: str,
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """
        Full pipeline for a login attempt.

        Returns
        ───────
        {
          "event_id":     str,
          "user":         User | None,
          "risk_result":  RiskResult,
          "decision":     str,
        }
        """
        t0 = time.perf_counter()

        # ── Resolve user ──────────────────────────────────────────
        result = await db.execute(
            select(User).where(User.username == req.username)
        )
        user: Optional[User] = result.scalars().first()

        user_id = user.id if user else None

        # ── Load user's profiles ──────────────────────────────────
        behavioral_profile = None
        device_profiles = []
        last_login = None

        if user:
            bp = await db.execute(
                select(BehavioralProfile).where(BehavioralProfile.user_id == user_id)
            )
            behavioral_profile = bp.scalars().first()

            dp = await db.execute(
                select(DeviceProfile).where(DeviceProfile.user_id == user_id)
            )
            device_profiles = list(dp.scalars().all())

            le = await db.execute(
                select(LoginEvent)
                .where(LoginEvent.user_id == user_id)
                .order_by(LoginEvent.timestamp.desc())
                .limit(1)
            )
            last_login = le.scalars().first()

        # ── 1. Device Agent ───────────────────────────────────────
        device_result = DeviceAgent.analyse(
            req.device, ip_address, device_profiles
        )

        # ── 2. Behavioral Agent ───────────────────────────────────
        behav_features = BehavioralAgent.analyse(
            req.behavioral, behavioral_profile
        )

        # ── 3. Session / Context Agent ────────────────────────────
        session_result = await SessionAgent.analyse(
            ip_address, behavioral_profile, last_login
        )

        # ── 4. Build feature dict ─────────────────────────────────
        features = {
            **behav_features,
            "is_new_device":     1.0 if device_result["is_new_device"] else 0.0,
            "is_new_ip":         1.0 if session_result["is_new_ip"] else 0.0,
            "geo_distance_km":   session_result["geo_distance_km"],
            "amount_normalised": 0.0,  # login has no amount
        }

        # Boost risk if same-device anomaly detected
        if device_result["same_device_anomaly"]:
            features["is_new_device"] = 0.8   # treat as partially new

        # ── 5. ML Scoring ─────────────────────────────────────────
        risk_score, explanation = await ModelManager.score(features)

        # ── 6. Decision ───────────────────────────────────────────
        risk_label, decision = DecisionEngine.decide(risk_score)

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        risk_result = RiskResult(
            risk_score=risk_score,
            risk_label=risk_label,
            decision=decision,
            risk_factors=explanation,
            response_ms=elapsed_ms,
        )

        # ── 7. Persist login event ────────────────────────────────
        event = LoginEvent(
            user_id=user_id,
            username_attempted=req.username,
            ip_address=ip_address,
            user_agent=req.device.user_agent,
            device_id=device_result["device_id"],
            screen_res=req.device.screen_res,
            os_info=device_result["os_info"],
            browser_info=device_result["browser_info"],
            country=session_result["country"],
            city=session_result["city"],
            latitude=session_result["latitude"],
            longitude=session_result["longitude"],
            login_duration_ms=req.behavioral.login_duration_ms,
            keystroke_intervals=req.behavioral.keystroke_intervals,
            mouse_event_count=req.behavioral.mouse_event_count,
            autofill_detected=features["autofill_detected"] > 0,
            typing_speed_wpm=features["typing_speed_wpm"],
            risk_score=risk_score,
            risk_label=risk_label,
            decision=decision,
            risk_factors=explanation,
            success=(decision == "ALLOW"),
        )
        db.add(event)

        # ── 8. Update profiles (only if user exists & decision != BLOCK)
        if user and decision != "BLOCK":
            await _update_profiles(
                db, user_id, req, device_result,
                session_result, behavioral_profile, ip_address,
            )

        # ── 9. New device record ──────────────────────────────────
        if user and device_result["is_new_device"]:
            db.add(DeviceProfile(
                user_id=user_id,
                device_id=device_result["device_id"],
                user_agent=req.device.user_agent,
                os_info=device_result["os_info"],
                browser_info=device_result["browser_info"],
                screen_res=req.device.screen_res,
            ))

        # ── 10. Alert if HIGH ─────────────────────────────────────
        if risk_label == "HIGH":
            alert = FraudAlert(
                user_id=user_id,
                event_type="LOGIN",
                event_id=event.id,
                risk_score=risk_score,
                risk_factors=explanation,
            )
            db.add(alert)
            await DecisionEngine.publish_alert(
                user_id, "LOGIN", event.id, risk_score, explanation
            )

        await db.flush()

        logger.info(
            "login_assessed",
            user=req.username,
            score=risk_score,
            decision=decision,
            ms=elapsed_ms,
        )

        return {
            "event_id":    event.id,
            "user":        user,
            "risk_result": risk_result,
            "decision":    decision,
        }

    # ════════════════════════════════════════════════════════════
    # TRANSACTION ASSESSMENT
    # ════════════════════════════════════════════════════════════
    @staticmethod
    async def assess_transaction(
        req: TransactionRequest,
        ip_address: str,
        db: AsyncSession,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()

        result = await db.execute(
            select(User).where(User.id == req.user_id)
        )
        user: Optional[User] = result.scalars().first()
        if not user:
            return {
                "transaction_id": "",
                "risk_result": RiskResult(
                    risk_score=100, risk_label="HIGH",
                    decision="BLOCK", risk_factors={"error": "user_not_found"},
                ),
            }

        # Load profiles
        bp = await db.execute(
            select(BehavioralProfile).where(BehavioralProfile.user_id == user.id)
        )
        behavioral_profile = bp.scalars().first()

        dp = await db.execute(
            select(DeviceProfile).where(DeviceProfile.user_id == user.id)
        )
        device_profiles = list(dp.scalars().all())

        le = await db.execute(
            select(LoginEvent)
            .where(LoginEvent.user_id == user.id)
            .order_by(LoginEvent.timestamp.desc())
            .limit(1)
        )
        last_login = le.scalars().first()

        # Device
        device_result = DeviceAgent.analyse(req.device, ip_address, device_profiles)

        # Session
        session_result = await SessionAgent.analyse(
            ip_address, behavioral_profile, last_login
        )

        # Amount normalisation: tx amount / user's average
        from sqlalchemy import func as sqlfunc
        avg_q = await db.execute(
            select(sqlfunc.avg(TransactionEvent.amount))
            .where(TransactionEvent.user_id == user.id)
        )
        user_avg_amount = avg_q.scalar() or req.amount
        amount_normalised = req.amount / max(user_avg_amount, 0.01)

        features = {
            "login_duration_ms":      5000,   # not applicable for tx
            "keystroke_avg_interval":  120,
            "mouse_event_count":       10,
            "typing_speed_wpm":        40,
            "is_new_device":  1.0 if device_result["is_new_device"] else 0.0,
            "is_new_ip":      1.0 if session_result["is_new_ip"] else 0.0,
            "is_unusual_hour": 0.0,
            "geo_distance_km": session_result["geo_distance_km"],
            "autofill_detected": 0.0,
            "amount_normalised": amount_normalised,
        }

        risk_score, explanation = await ModelManager.score(features)
        risk_label, decision = DecisionEngine.decide(risk_score)
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        risk_result = RiskResult(
            risk_score=risk_score, risk_label=risk_label,
            decision=decision, risk_factors=explanation,
            response_ms=elapsed_ms,
        )

        event = TransactionEvent(
            user_id=user.id,
            amount=req.amount,
            currency=req.currency,
            recipient_id=req.recipient_id,
            transaction_type=req.transaction_type,
            ip_address=ip_address,
            device_id=device_result["device_id"],
            session_id=req.session_id,
            risk_score=risk_score,
            risk_label=risk_label,
            decision=decision,
            risk_factors=explanation,
            blocked=(decision == "BLOCK"),
        )
        db.add(event)

        if risk_label == "HIGH":
            alert = FraudAlert(
                user_id=user.id, event_type="TRANSACTION",
                event_id=event.id, risk_score=risk_score,
                risk_factors=explanation,
            )
            db.add(alert)
            await DecisionEngine.publish_alert(
                user.id, "TRANSACTION", event.id, risk_score, explanation
            )

        await db.flush()

        return {
            "transaction_id": event.id,
            "risk_result":    risk_result,
        }


# ── Profile update helper ─────────────────────────────────────────
async def _update_profiles(
    db: AsyncSession,
    user_id: str,
    req: LoginRequest,
    device_result: Dict,
    session_result: Dict,
    behavioral_profile: Optional[BehavioralProfile],
    ip_address: str,
) -> None:
    """Update behavioural + IP profiles after a legitimate login."""
    current_hour = datetime.utcnow().hour
    updates = BehavioralAgent.compute_profile_update(
        req.behavioral, behavioral_profile, current_hour
    )
    ips = SessionAgent.compute_ip_update(ip_address, behavioral_profile)

    if behavioral_profile:
        for k, v in updates.items():
            setattr(behavioral_profile, k, v)
        behavioral_profile.typical_ips = ips
        behavioral_profile.typical_countries = list(set(
            (behavioral_profile.typical_countries or []) + [session_result["country"]]
        ))[-10:]
    else:
        bp = BehavioralProfile(
            user_id=user_id,
            typical_ips=ips,
            typical_countries=[session_result["country"]],
            **updates,
        )
        db.add(bp)
