-- FraudShield AI - PostgreSQL Schema Reference
-- Tables auto-created by SQLAlchemy on startup. Use Alembic for production.

CREATE TABLE IF NOT EXISTS users (
    id VARCHAR PRIMARY KEY, username VARCHAR(64) UNIQUE NOT NULL,
    email VARCHAR(256) UNIQUE NOT NULL, hashed_password VARCHAR NOT NULL,
    is_active BOOLEAN DEFAULT TRUE, is_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS login_events (
    id VARCHAR PRIMARY KEY, user_id VARCHAR REFERENCES users(id),
    username_attempted VARCHAR(64) NOT NULL, timestamp TIMESTAMP DEFAULT NOW(),
    ip_address VARCHAR(45), user_agent TEXT, device_id VARCHAR(128),
    screen_res VARCHAR(20), os_info VARCHAR(128), browser_info VARCHAR(128),
    country VARCHAR(64), city VARCHAR(128), latitude FLOAT, longitude FLOAT,
    login_duration_ms INTEGER, keystroke_intervals JSONB,
    mouse_event_count INTEGER DEFAULT 0, autofill_detected BOOLEAN DEFAULT FALSE,
    typing_speed_wpm FLOAT, risk_score FLOAT NOT NULL, risk_label VARCHAR(10),
    decision VARCHAR(20), risk_factors JSONB, success BOOLEAN
);

CREATE TABLE IF NOT EXISTS transaction_events (
    id VARCHAR PRIMARY KEY, user_id VARCHAR NOT NULL REFERENCES users(id),
    timestamp TIMESTAMP DEFAULT NOW(), amount FLOAT NOT NULL,
    currency VARCHAR(3) DEFAULT 'USD', recipient_id VARCHAR(128),
    transaction_type VARCHAR(32), ip_address VARCHAR(45),
    device_id VARCHAR(128), session_id VARCHAR(128),
    risk_score FLOAT NOT NULL, risk_label VARCHAR(10), decision VARCHAR(20),
    risk_factors JSONB, blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS device_profiles (
    id VARCHAR PRIMARY KEY, user_id VARCHAR NOT NULL REFERENCES users(id),
    device_id VARCHAR(128) NOT NULL, first_seen TIMESTAMP DEFAULT NOW(),
    last_seen TIMESTAMP DEFAULT NOW(), trust_score FLOAT DEFAULT 100.0,
    is_trusted BOOLEAN DEFAULT TRUE, user_agent TEXT, os_info VARCHAR(128),
    browser_info VARCHAR(128), screen_res VARCHAR(20)
);

CREATE TABLE IF NOT EXISTS behavioral_profiles (
    id VARCHAR PRIMARY KEY, user_id VARCHAR UNIQUE NOT NULL REFERENCES users(id),
    updated_at TIMESTAMP DEFAULT NOW(), avg_login_duration_ms FLOAT DEFAULT 5000.0,
    avg_typing_speed_wpm FLOAT DEFAULT 40.0, avg_keystroke_interval_ms FLOAT DEFAULT 120.0,
    avg_mouse_events FLOAT DEFAULT 15.0, typical_login_hours JSONB DEFAULT '[]',
    typical_countries JSONB DEFAULT '[]', typical_ips JSONB DEFAULT '[]',
    login_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fraud_alerts (
    id VARCHAR PRIMARY KEY, user_id VARCHAR REFERENCES users(id),
    event_type VARCHAR(20), event_id VARCHAR, timestamp TIMESTAMP DEFAULT NOW(),
    risk_score FLOAT, risk_factors JSONB, status VARCHAR(20) DEFAULT 'OPEN',
    reviewed_by VARCHAR(64), notes TEXT
);
