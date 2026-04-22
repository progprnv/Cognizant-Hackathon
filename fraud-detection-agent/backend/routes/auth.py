"""
backend/routes/auth.py
POST /api/auth/login    - risk-scored login
POST /api/auth/register - create test user
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel

from backend.core.database import get_db
from backend.models.orm_models import User
from backend.models.schemas import LoginRequest, LoginResponse
from backend.services.fraud_orchestrator import FraudOrchestrator
from backend.utils.auth_utils import verify_password, hash_password, create_access_token

router = APIRouter()


@router.post("/login", response_model=LoginResponse)
async def login(body: LoginRequest, request: Request, db: AsyncSession = Depends(get_db)):
    ip = body.ip_address or request.client.host
    result = await FraudOrchestrator.assess_login(body, ip, db)
    risk = result["risk_result"]
    user = result["user"]
    decision = result["decision"]

    if decision == "BLOCK":
        return LoginResponse(
            event_id=result["event_id"], user_id=user.id if user else None,
            access_token=None, risk=risk,
            message="Login blocked - suspicious activity detected.",
        )
    if decision == "OTP_REQUIRED":
        return LoginResponse(
            event_id=result["event_id"], user_id=user.id if user else None,
            access_token=None, risk=risk,
            message="Additional verification required. OTP sent.",
        )
    if not user or not verify_password(body.password, user.hashed_password):
        return LoginResponse(
            event_id=result["event_id"], user_id=None,
            access_token=None, risk=risk,
            message="Invalid credentials.",
        )
    token = create_access_token({"sub": user.id, "username": user.username})
    return LoginResponse(
        event_id=result["event_id"], user_id=user.id, access_token=token, risk=risk,
        message="Login successful.",
    )


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

@router.post("/register")
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)):
    existing = await db.execute(select(User).where(User.username == body.username))
    if existing.scalars().first():
        return {"error": "Username already taken"}
    user = User(
        username=body.username, email=body.email,
        hashed_password=hash_password(body.password),
    )
    db.add(user)
    await db.flush()
    return {"id": user.id, "username": user.username, "message": "User registered."}
