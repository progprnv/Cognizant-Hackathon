"""
backend/services/decision_engine.py
────────────────────────────────────
Decision Engine

Takes the ensemble risk score (0–100) and returns an action:
  LOW    (< 35)  →  ALLOW
  MEDIUM (35–70) →  OTP_REQUIRED
  HIGH   (> 70)  →  BLOCK + alert

Also dispatches fraud alerts to the database and optional webhook.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

import structlog

from backend.core.config import settings
from backend.core.redis_client import redis_client

logger = structlog.get_logger()


class DecisionEngine:

    @staticmethod
    def decide(risk_score: float) -> Tuple[str, str]:
        """
        Returns
        ───────
        (risk_label, decision)
        """
        if risk_score < settings.RISK_LOW_THRESHOLD:
            return "LOW", "ALLOW"
        elif risk_score < settings.RISK_HIGH_THRESHOLD:
            return "MEDIUM", "OTP_REQUIRED"
        else:
            return "HIGH", "BLOCK"

    @staticmethod
    async def publish_alert(
        user_id: Optional[str],
        event_type: str,
        event_id: str,
        risk_score: float,
        risk_factors: Dict[str, Any],
    ) -> None:
        """
        Push a real-time alert to:
          1. Redis pub/sub (consumed by the dashboard via SSE)
          2. External webhook (Slack / Teams) if configured
        """
        alert_payload = {
            "user_id":      user_id,
            "event_type":   event_type,
            "event_id":     event_id,
            "risk_score":   risk_score,
            "risk_factors": risk_factors,
            "timestamp":    datetime.utcnow().isoformat(),
        }

        # 1. Redis pub/sub for dashboard live feed
        try:
            await redis_client.publish(
                "fraud:alerts",
                json.dumps(alert_payload),
            )
            logger.info("alert_published", event_id=event_id, score=risk_score)
        except Exception as e:
            logger.error("alert_publish_failed", error=str(e))

        # 2. Webhook (fire and forget)
        if settings.ALERT_WEBHOOK_URL:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=2.0) as client:
                    await client.post(
                        settings.ALERT_WEBHOOK_URL,
                        json={
                            "text": (
                                f"🚨 *FraudShield Alert*\n"
                                f"Score: {risk_score} | Decision: BLOCK\n"
                                f"User: {user_id or 'unknown'}\n"
                                f"Event: {event_type} `{event_id}`"
                            ),
                        },
                    )
            except Exception as e:
                logger.warning("webhook_failed", error=str(e))
