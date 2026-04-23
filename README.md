# FraudShield AI — Real-Time Fraud Detection Agent

> **Cognizant Technoverse 2026** — AI-Powered Multi-Agent Fraud Detection System

## Architecture Overview

```
┌─────────────┐     ┌──────────────────────────────────────────────┐
│   Browser    │────▶│  FastAPI Backend (< 1 sec response)         │
│  (signals)   │     │                                              │
│  - keystrokes│     │  ┌────────────┐ ┌──────────────┐            │
│  - mouse     │     │  │ Behavioral │ │   Device     │            │
│  - device fp │     │  │   Agent    │ │   Agent      │            │
│  - timing    │     │  └─────┬──────┘ └──────┬───────┘            │
└─────────────┘     │        │               │                     │
                    │  ┌─────▼───────────────▼──────┐              │
                    │  │   Session & Context Agent   │              │
                    │  │  (Geo-IP / Impossible Travel)│             │
                    │  └─────────────┬───────────────┘              │
                    │                │                               │
                    │  ┌─────────────▼───────────────┐              │
                    │  │     ML Scoring Engine        │              │
                    │  │  IsolationForest (35%)       │              │
                    │  │  LogisticRegression (65%)    │              │
                    │  └─────────────┬───────────────┘              │
                    │                │                               │
                    │  ┌─────────────▼───────────────┐              │
                    │  │     Decision Engine          │              │
                    │  │  LOW→ALLOW  MED→OTP  HI→BLOCK│             │
                    │  └─────────────────────────────┘              │
                    └──────────────────────────────────────────────┘
                              │                    │
                    ┌─────────▼──────┐   ┌────────▼────────┐
                    │  PostgreSQL    │   │     Redis        │
                    │  (persistent)  │   │  (cache + SSE)   │
                    └────────────────┘   └─────────────────┘
```

## Fraud Detection Capabilities

| Scenario | How Detected |
|---|---|
| **Stolen Credentials** | New device + new IP + unusual hour → HIGH risk |
| **Autofill Attack** | Login < 300ms, zero keystrokes, no mouse → flagged |
| **Same-Device Attack** | Known device BUT behaviour deviation (speed, patterns) |
| **Impossible Travel** | Login from 5000km away 10 min after last login |
| **Large Transaction** | Amount 8×+ user average → elevated risk |
| **Bot / Script** | Keystroke interval < 30ms (inhuman speed) |

## Quick Start

### Prerequisites
- Python 3.11+
- PostgreSQL 14+
- Redis 7+

### 1. Clone & Install

```bash
cd fraud-detection-agent
cp .env.example .env          # edit database URL, secrets
pip install -r requirements.txt
```

### 2. Start Services

```bash
# Start PostgreSQL & Redis (or use Docker)
docker run -d --name fraud-pg -e POSTGRES_USER=fraud_user \
  -e POSTGRES_PASSWORD=fraud_pass -e POSTGRES_DB=fraud_db \
  -p 5432:5432 postgres:16

docker run -d --name fraud-redis -p 6379:6379 redis:7-alpine

# Start the API server
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3. Open Dashboard

Open `frontend/index.html` in your browser, or serve it:
```bash
cd frontend && python -m http.server 3000
```

### 4. API Docs

Visit `http://localhost:8000/api/docs` for interactive Swagger UI.

## API Endpoints

### Auth
```
POST /api/auth/register   — Create a test user
POST /api/auth/login      — Login with fraud detection
```

### Transactions
```
POST /api/tx/check        — Fraud-check a transaction
```

### Risk (Direct ML)
```
POST /api/risk/score      — Score raw features directly
```

### Admin Dashboard
```
GET  /api/admin/stats          — Aggregated dashboard stats
GET  /api/admin/alerts         — List fraud alerts
PATCH /api/admin/alerts/{id}   — Review/dismiss an alert
GET  /api/admin/users          — User risk summaries
GET  /api/admin/events/login   — Recent login events
GET  /api/admin/events/tx      — Recent transactions
GET  /api/admin/alerts/stream  — SSE real-time alert feed
```

## Example cURL Requests

### Register a User
```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"john_doe","email":"john@bank.com","password":"SecurePass123"}'
```

### Normal Login (LOW risk — should ALLOW)
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePass123",
    "behavioral": {
      "login_duration_ms": 5200,
      "keystroke_intervals": [110, 95, 130, 105, 120, 88, 115, 102],
      "mouse_event_count": 12,
      "typing_speed_wpm": 42
    },
    "device": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/125.0",
      "screen_res": "1920x1080",
      "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    },
    "ip_address": "192.168.1.100"
  }'
```

### Autofill Attack (HIGH risk — should BLOCK)
```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "SecurePass123",
    "behavioral": {
      "login_duration_ms": 120,
      "keystroke_intervals": [],
      "mouse_event_count": 0,
      "autofill_suspected": true
    },
    "device": {
      "user_agent": "Mozilla/5.0 (Linux; Android 13) Chrome/125.0",
      "screen_res": "1080x2400",
      "device_id": "aaaa1111bbbb2222cccc3333dddd4444"
    },
    "ip_address": "45.33.99.101"
  }'
```

### Direct Risk Scoring
```bash
curl -X POST http://localhost:8000/api/risk/score \
  -H "Content-Type: application/json" \
  -d '{
    "login_duration_ms": 150,
    "keystroke_avg_interval": 0,
    "mouse_event_count": 0,
    "typing_speed_wpm": 0,
    "is_new_device": true,
    "is_new_ip": true,
    "is_unusual_hour": true,
    "geo_distance_km": 5000,
    "autofill_detected": true
  }'
```

### Check a Transaction
```bash
curl -X POST http://localhost:8000/api/tx/check \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "<USER_ID_FROM_REGISTER>",
    "session_id": "sess_abc123",
    "amount": 15000,
    "currency": "USD",
    "recipient_id": "recipient_xyz",
    "transaction_type": "TRANSFER",
    "device": {
      "user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/125.0",
      "screen_res": "1920x1080",
      "device_id": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
    }
  }'
```

## Project Structure

```
fraud-detection-agent/
├── backend/
│   ├── main.py                     # FastAPI app entry point
│   ├── core/
│   │   ├── config.py               # Pydantic settings
│   │   ├── database.py             # Async SQLAlchemy engine
│   │   └── redis_client.py         # Redis singleton
│   ├── models/
│   │   ├── orm_models.py           # 6 database tables
│   │   └── schemas.py              # Pydantic request/response
│   ├── ml/
│   │   ├── model_manager.py        # IsolationForest + LogReg ensemble
│   │   ├── synthetic_data.py       # Training data generator
│   │   └── saved_models/           # Persisted .pkl files
│   ├── services/
│   │   ├── behavioral_agent.py     # Typing/mouse/timing analysis
│   │   ├── device_agent.py         # Fingerprinting + same-device detect
│   │   ├── session_agent.py        # Geo-IP + impossible travel
│   │   ├── decision_engine.py      # Score → action mapping + alerts
│   │   └── fraud_orchestrator.py   # Coordinates all agents
│   ├── routes/
│   │   ├── auth.py                 # Login + register
│   │   ├── transactions.py         # Transaction monitoring
│   │   ├── risk.py                 # Direct ML scoring
│   │   ├── admin.py                # Dashboard APIs + SSE
│   │   └── health.py
│   └── utils/
│       └── auth_utils.py           # JWT + bcrypt
├── frontend/
│   └── index.html                  # Admin dashboard (single-file)
├── database/
│   ├── schema.sql                  # PostgreSQL DDL reference
│   └── sample_dataset.csv          # 2000-row synthetic dataset
├── requirements.txt
├── .env.example
└── README.md
```

## ML Model Details

**Ensemble Architecture**: 35% IsolationForest + 65% Logistic Regression

| Model | Role | Training |
|---|---|---|
| IsolationForest | Unsupervised anomaly detection | All data (no labels needed) |
| LogisticRegression | Supervised fraud probability | Labelled synthetic data |

**10 Features Used**:
login_duration_ms, keystroke_avg_interval, mouse_event_count, typing_speed_wpm,
is_new_device, is_new_ip, is_unusual_hour, geo_distance_km, autofill_detected,
amount_normalised

**Continuous Learning**: Profiles update via exponential moving average (α=0.15)
after each legitimate login, so the baseline adapts to natural behaviour changes.

## Tech Stack

| Component | Technology |
|---|---|
| API Framework | Python + FastAPI |
| ML | scikit-learn (IsolationForest, LogisticRegression) |
| Database | PostgreSQL (async via SQLAlchemy 2.0) |
| Cache / PubSub | Redis |
| Frontend | Single-page HTML + Recharts-style dashboard |
| Auth | JWT (python-jose) + bcrypt |

## License

Built for Cognizant Technoverse 2026 hackathon. 
