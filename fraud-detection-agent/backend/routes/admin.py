"""
backend/routes/admin.py
Admin dashboard API endpoints:
  GET  /api/admin/alerts        - list fraud alerts
  PATCH /api/admin/alerts/{id}  - update alert status
  GET  /api/admin/users         - user risk summaries
  GET  /api/admin/events/login  - recent login events
  GET  /api/admin/events/tx     - recent transaction events
  GET  /api/admin/stats         - aggregated statistics
  GET  /api/admin/alerts/stream - SSE real-time alert stream
"""
import asyncio
import json
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from backend.core.database import get_db
from backend.core.redis_client import redis_client
from backend.models.orm_models import (
    FraudAlert, LoginEvent, TransactionEvent, User,
    DeviceProfile, BehavioralProfile,
)
from backend.models.schemas import AlertStatusUpdate, FraudAlertOut

router = APIRouter()


# ── Alerts ──────────────────────────────────────────────────────
@router.get("/alerts")
async def list_alerts(
    status: Optional[str] = None,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = select(FraudAlert).order_by(desc(FraudAlert.timestamp)).limit(limit)
    if status:
        q = q.where(FraudAlert.status == status.upper())
    result = await db.execute(q)
    alerts = result.scalars().all()
    return [FraudAlertOut.model_validate(a) for a in alerts]


@router.patch("/alerts/{alert_id}")
async def update_alert(
    alert_id: str,
    body: AlertStatusUpdate,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(FraudAlert).where(FraudAlert.id == alert_id))
    alert = result.scalars().first()
    if not alert:
        return {"error": "Alert not found"}
    alert.status = body.status
    alert.notes = body.notes
    return {"id": alert.id, "status": alert.status}


# ── User summaries ──────────────────────────────────────────────
@router.get("/users")
async def user_summaries(
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).limit(limit))
    users = result.scalars().all()
    summaries = []
    for u in users:
        logins = await db.execute(
            select(func.count(LoginEvent.id), func.avg(LoginEvent.risk_score))
            .where(LoginEvent.user_id == u.id)
        )
        total, avg_risk = logins.one()
        blocked = await db.execute(
            select(func.count(LoginEvent.id))
            .where(LoginEvent.user_id == u.id, LoginEvent.decision == "BLOCK")
        )
        blocked_count = blocked.scalar()
        devices = await db.execute(
            select(func.count(DeviceProfile.id))
            .where(DeviceProfile.user_id == u.id)
        )
        device_count = devices.scalar()
        last = await db.execute(
            select(LoginEvent.timestamp)
            .where(LoginEvent.user_id == u.id)
            .order_by(desc(LoginEvent.timestamp))
            .limit(1)
        )
        last_ts = last.scalar()
        summaries.append({
            "user_id": u.id,
            "username": u.username,
            "total_logins": total or 0,
            "blocked_logins": blocked_count or 0,
            "avg_risk_score": round(float(avg_risk or 0), 2),
            "last_login": last_ts,
            "known_devices": device_count or 0,
        })
    return summaries


# ── Login events ────────────────────────────────────────────────
@router.get("/events/login")
async def login_events(
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(LoginEvent).order_by(desc(LoginEvent.timestamp)).limit(limit)
    )
    events = result.scalars().all()
    return [{
        "id": e.id,
        "user_id": e.user_id,
        "username": e.username_attempted,
        "timestamp": e.timestamp,
        "ip": e.ip_address,
        "device_id": e.device_id,
        "country": e.country,
        "city": e.city,
        "risk_score": e.risk_score,
        "risk_label": e.risk_label,
        "decision": e.decision,
        "autofill": e.autofill_detected,
        "login_duration_ms": e.login_duration_ms,
        "risk_factors": e.risk_factors,
    } for e in events]


# ── Transaction events ──────────────────────────────────────────
@router.get("/events/tx")
async def tx_events(
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(TransactionEvent).order_by(desc(TransactionEvent.timestamp)).limit(limit)
    )
    events = result.scalars().all()
    return [{
        "id": e.id,
        "user_id": e.user_id,
        "timestamp": e.timestamp,
        "amount": e.amount,
        "currency": e.currency,
        "risk_score": e.risk_score,
        "risk_label": e.risk_label,
        "decision": e.decision,
        "blocked": e.blocked,
    } for e in events]


# ── Aggregated stats ────────────────────────────────────────────
@router.get("/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)):
    total_logins = (await db.execute(select(func.count(LoginEvent.id)))).scalar() or 0
    blocked_logins = (await db.execute(
        select(func.count(LoginEvent.id)).where(LoginEvent.decision == "BLOCK")
    )).scalar() or 0
    otp_logins = (await db.execute(
        select(func.count(LoginEvent.id)).where(LoginEvent.decision == "OTP_REQUIRED")
    )).scalar() or 0
    total_tx = (await db.execute(select(func.count(TransactionEvent.id)))).scalar() or 0
    blocked_tx = (await db.execute(
        select(func.count(TransactionEvent.id)).where(TransactionEvent.blocked == True)
    )).scalar() or 0
    open_alerts = (await db.execute(
        select(func.count(FraudAlert.id)).where(FraudAlert.status == "OPEN")
    )).scalar() or 0
    avg_risk = (await db.execute(select(func.avg(LoginEvent.risk_score)))).scalar() or 0
    total_users = (await db.execute(select(func.count(User.id)))).scalar() or 0

    return {
        "total_logins": total_logins,
        "blocked_logins": blocked_logins,
        "otp_logins": otp_logins,
        "allowed_logins": total_logins - blocked_logins - otp_logins,
        "total_transactions": total_tx,
        "blocked_transactions": blocked_tx,
        "open_alerts": open_alerts,
        "avg_risk_score": round(float(avg_risk), 2),
        "total_users": total_users,
    }


# ── SSE real-time alert stream ──────────────────────────────────
@router.get("/alerts/stream")
async def alert_stream():
    """Server-Sent Events endpoint for real-time fraud alerts."""
    async def event_generator():
        pubsub = redis_client.pubsub()
        await pubsub.subscribe("fraud:alerts")
        try:
            while True:
                message = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=1.0
                )
                if message and message["type"] == "message":
                    yield f"data: {message['data']}\n\n"
                else:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(0.5)
        finally:
            await pubsub.unsubscribe("fraud:alerts")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
