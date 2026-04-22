"""backend/routes/health.py"""
from fastapi import APIRouter
router = APIRouter()

@router.get("/health")
async def healthcheck():
    return {"status": "healthy", "service": "FraudShield AI", "version": "1.0.0"}
