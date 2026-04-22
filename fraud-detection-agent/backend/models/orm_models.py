"""
backend/models/orm_models.py
─────────────────────────────
SQLAlchemy ORM definitions for every table used by FraudShield AI.

Tables
──────
  users                — registered users
  login_events         — every login attempt + risk result
  transaction_events   — every financial transaction + risk result
  device_profiles      — known devices per user
  behavioral_profiles  — rolling behavioural baseline per user
  fraud_alerts         — high-risk events requiring human review
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, JSON, String, Text, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from backend.core.database import Base


# ── Helpers ───────────────────────────────────────────────────────
def _uuid():
    return str(uuid.uuid4())


# ═════════════════════════════════════════════════════════════════
# 1.  USERS
# ═════════════════════════════════════════════════════════════════
class User(Base):
    __tablename__ = "users"

    id            = Column(String, primary_key=True, default=_uuid)
    username      = Column(String(64), unique=True, nullable=False, index=True)
    email         = Column(String(256), unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active     = Column(Boolean, default=True)
    is_admin      = Column(Boolean, default=False)
    created_at    = Column(DateTime, default=datetime.utcnow)

    # Relationships
    login_events       = relationship("LoginEvent",       back_populates="user")
    transaction_events = relationship("TransactionEvent", back_populates="user")
    device_profiles    = relationship("DeviceProfile",    back_populates="user")
    behavioral_profile = relationship("BehavioralProfile", back_populates="user", uselist=False)
    fraud_alerts       = relationship("FraudAlert",       back_populates="user")


# ═════════════════════════════════════════════════════════════════
# 2.  LOGIN EVENTS
# ═════════════════════════════════════════════════════════════════
class LoginEvent(Base):
    __tablename__ = "login_events"

    id            = Column(String, primary_key=True, default=_uuid)
    user_id       = Column(String, ForeignKey("users.id"), nullable=True, index=True)
    username_attempted = Column(String(64), nullable=False)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)

    # Device / Network signals
    ip_address    = Column(String(45))
    user_agent    = Column(Text)
    device_id     = Column(String(128))       # hashed fingerprint
    screen_res    = Column(String(20))
    os_info       = Column(String(128))
    browser_info  = Column(String(128))

    # Geo
    country       = Column(String(64))
    city          = Column(String(128))
    latitude      = Column(Float)
    longitude     = Column(Float)

    # Behavioural signals
    login_duration_ms  = Column(Integer)      # time from page-load to submit
    keystroke_intervals = Column(JSON)        # list[float] — ms between keystrokes
    mouse_event_count   = Column(Integer, default=0)
    autofill_detected   = Column(Boolean, default=False)
    typing_speed_wpm    = Column(Float)

    # Risk output
    risk_score    = Column(Float, nullable=False)
    risk_label    = Column(String(10))        # LOW | MEDIUM | HIGH
    decision      = Column(String(20))        # ALLOW | OTP_REQUIRED | BLOCK
    risk_factors  = Column(JSON)              # explainability dict
    success       = Column(Boolean)           # did auth ultimately succeed?

    user = relationship("User", back_populates="login_events")


# ═════════════════════════════════════════════════════════════════
# 3.  TRANSACTION EVENTS
# ═════════════════════════════════════════════════════════════════
class TransactionEvent(Base):
    __tablename__ = "transaction_events"

    id              = Column(String, primary_key=True, default=_uuid)
    user_id         = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)

    amount          = Column(Float, nullable=False)
    currency        = Column(String(3), default="USD")
    recipient_id    = Column(String(128))
    transaction_type = Column(String(32))     # TRANSFER | PAYMENT | WITHDRAWAL

    # Context
    ip_address      = Column(String(45))
    device_id       = Column(String(128))
    session_id      = Column(String(128))

    # Risk output
    risk_score      = Column(Float, nullable=False)
    risk_label      = Column(String(10))
    decision        = Column(String(20))
    risk_factors    = Column(JSON)
    blocked         = Column(Boolean, default=False)

    user = relationship("User", back_populates="transaction_events")


# ═════════════════════════════════════════════════════════════════
# 4.  DEVICE PROFILES  (known devices per user)
# ═════════════════════════════════════════════════════════════════
class DeviceProfile(Base):
    __tablename__ = "device_profiles"

    id          = Column(String, primary_key=True, default=_uuid)
    user_id     = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    device_id   = Column(String(128), nullable=False)    # hashed
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    trust_score = Column(Float, default=100.0)           # degrades on anomalies
    is_trusted  = Column(Boolean, default=True)

    # Snapshot of known good device characteristics
    user_agent  = Column(Text)
    os_info     = Column(String(128))
    browser_info = Column(String(128))
    screen_res  = Column(String(20))

    user = relationship("User", back_populates="device_profiles")


# ═════════════════════════════════════════════════════════════════
# 5.  BEHAVIORAL PROFILES  (rolling baseline)
# ═════════════════════════════════════════════════════════════════
class BehavioralProfile(Base):
    __tablename__ = "behavioral_profiles"

    id      = Column(String, primary_key=True, default=_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False, unique=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Aggregated statistics (updated with exponential moving average)
    avg_login_duration_ms   = Column(Float, default=5000.0)
    avg_typing_speed_wpm    = Column(Float, default=40.0)
    avg_keystroke_interval_ms = Column(Float, default=120.0)
    avg_mouse_events        = Column(Float, default=15.0)
    typical_login_hours     = Column(JSON, default=list)   # list[int] 0-23
    typical_countries       = Column(JSON, default=list)
    typical_ips             = Column(JSON, default=list)   # last 10 IPs
    login_count             = Column(Integer, default=0)

    user = relationship("User", back_populates="behavioral_profile")


# ═════════════════════════════════════════════════════════════════
# 6.  FRAUD ALERTS
# ═════════════════════════════════════════════════════════════════
class FraudAlert(Base):
    __tablename__ = "fraud_alerts"

    id          = Column(String, primary_key=True, default=_uuid)
    user_id     = Column(String, ForeignKey("users.id"), nullable=True)
    event_type  = Column(String(20))              # LOGIN | TRANSACTION
    event_id    = Column(String)                  # FK to the triggering event
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    risk_score  = Column(Float)
    risk_factors = Column(JSON)
    status      = Column(String(20), default="OPEN")  # OPEN | REVIEWED | DISMISSED
    reviewed_by = Column(String(64))
    notes       = Column(Text)

    user = relationship("User", back_populates="fraud_alerts")
