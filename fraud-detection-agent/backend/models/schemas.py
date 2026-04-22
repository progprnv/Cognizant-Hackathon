"""
backend/models/schemas.py
──────────────────────────
Pydantic v2 schemas for all API request bodies and response payloads.
These are separate from ORM models to keep serialisation concerns clean.
"""

from __future__ import annotations
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ═════════════════════════════════════════════════════════════════
# SHARED
# ═════════════════════════════════════════════════════════════════
class RiskResult(BaseModel):
    """Returned by every fraud-check endpoint."""
    risk_score:   float = Field(..., ge=0, le=100, description="0=safe, 100=definite fraud")
    risk_label:   str   = Field(..., pattern="^(LOW|MEDIUM|HIGH)$")
    decision:     str   = Field(..., pattern="^(ALLOW|OTP_REQUIRED|BLOCK)$")
    risk_factors: Dict[str, Any] = Field(default_factory=dict, description="Explainability")
    response_ms:  Optional[float] = None


# ═════════════════════════════════════════════════════════════════
# AUTH  (login)
# ═════════════════════════════════════════════════════════════════
class BehavioralSignals(BaseModel):
    """Collected by the browser and sent alongside credentials."""
    login_duration_ms:    int   = Field(..., ge=0, description="ms from page-load to submit")
    keystroke_intervals:  List[float] = Field(default_factory=list, description="ms between keystrokes")
    mouse_event_count:    int   = Field(default=0, ge=0)
    typing_speed_wpm:     Optional[float] = None
    autofill_suspected:   bool  = False  # hint from browser JS

    @field_validator("keystroke_intervals")
    @classmethod
    def cap_intervals(cls, v):
        return v[:500]  # never accept absurdly long lists


class DeviceFingerprint(BaseModel):
    """Collected by the browser fingerprinting script."""
    user_agent:   str
    screen_res:   str = Field(default="unknown", examples=["1920x1080"])
    timezone:     Optional[str] = None
    language:     Optional[str] = None
    device_id:    str  = Field(..., description="SHA-256 hash of stable device attributes")


class LoginRequest(BaseModel):
    username:    str
    password:    str
    behavioral:  BehavioralSignals
    device:      DeviceFingerprint
    ip_address:  Optional[str] = None   # populated server-side if missing


class LoginResponse(BaseModel):
    event_id:    str
    user_id:     Optional[str] = None   # populated on successful auth
    access_token: Optional[str] = None  # None if OTP_REQUIRED or BLOCK
    risk:        RiskResult
    message:     str


# ═════════════════════════════════════════════════════════════════
# TRANSACTIONS
# ═════════════════════════════════════════════════════════════════
class TransactionRequest(BaseModel):
    user_id:          str
    session_id:       str
    amount:           float = Field(..., gt=0)
    currency:         str   = Field(default="USD", min_length=3, max_length=3)
    recipient_id:     str
    transaction_type: str   = Field(default="TRANSFER")
    device:           DeviceFingerprint
    ip_address:       Optional[str] = None


class TransactionResponse(BaseModel):
    transaction_id: str
    risk:           RiskResult
    message:        str


# ═════════════════════════════════════════════════════════════════
# RISK  (standalone scoring endpoint)
# ═════════════════════════════════════════════════════════════════
class RiskScoreRequest(BaseModel):
    """Raw feature vector for direct ML scoring (useful for testing)."""
    login_duration_ms:       float
    keystroke_avg_interval:  float
    mouse_event_count:       int
    typing_speed_wpm:        float
    is_new_device:           bool
    is_new_ip:               bool
    is_unusual_hour:         bool
    geo_distance_km:         float
    autofill_detected:       bool
    amount:                  Optional[float] = 0.0


# ═════════════════════════════════════════════════════════════════
# ADMIN
# ═════════════════════════════════════════════════════════════════
class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(REVIEWED|DISMISSED)$")
    notes:  Optional[str] = None


class UserRiskSummary(BaseModel):
    user_id:          str
    username:         str
    total_logins:     int
    blocked_logins:   int
    avg_risk_score:   float
    last_login:       Optional[datetime]
    known_devices:    int


class FraudAlertOut(BaseModel):
    id:           str
    user_id:      Optional[str]
    event_type:   str
    timestamp:    datetime
    risk_score:   float
    risk_factors: Dict[str, Any]
    status:       str

    model_config = {"from_attributes": True}
