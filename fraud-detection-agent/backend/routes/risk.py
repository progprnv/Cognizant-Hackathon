"""
backend/routes/risk.py
POST /api/risk/score   - Direct ML scoring (for testing)
GET  /api/risk/explain - Human-readable risk breakdown
"""
from fastapi import APIRouter
from backend.models.schemas import RiskScoreRequest, RiskResult
from backend.ml.model_manager import ModelManager
from backend.services.decision_engine import DecisionEngine

router = APIRouter()


@router.post("/score", response_model=RiskResult)
async def score_risk(body: RiskScoreRequest):
    """Direct access to the ML models for testing and debugging."""
    features = {
        "login_duration_ms":      body.login_duration_ms,
        "keystroke_avg_interval": body.keystroke_avg_interval,
        "mouse_event_count":      body.mouse_event_count,
        "typing_speed_wpm":       body.typing_speed_wpm,
        "is_new_device":          1.0 if body.is_new_device else 0.0,
        "is_new_ip":              1.0 if body.is_new_ip else 0.0,
        "is_unusual_hour":        1.0 if body.is_unusual_hour else 0.0,
        "geo_distance_km":        body.geo_distance_km,
        "autofill_detected":      1.0 if body.autofill_detected else 0.0,
        "amount_normalised":      body.amount or 1.0,
    }
    risk_score, explanation = await ModelManager.score(features)
    risk_label, decision = DecisionEngine.decide(risk_score)
    return RiskResult(
        risk_score=risk_score,
        risk_label=risk_label,
        decision=decision,
        risk_factors=explanation,
    )
