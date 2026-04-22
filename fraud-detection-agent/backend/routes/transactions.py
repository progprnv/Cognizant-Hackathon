"""
backend/routes/transactions.py
POST /api/tx/check - Fraud-check a financial transaction
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.database import get_db
from backend.models.schemas import TransactionRequest, TransactionResponse
from backend.services.fraud_orchestrator import FraudOrchestrator

router = APIRouter()


@router.post("/check", response_model=TransactionResponse)
async def check_transaction(
    body: TransactionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    ip = body.ip_address or request.client.host
    result = await FraudOrchestrator.assess_transaction(body, ip, db)

    risk = result["risk_result"]
    decision = risk.decision

    if decision == "BLOCK":
        msg = "Transaction blocked - fraud suspected."
    elif decision == "OTP_REQUIRED":
        msg = "Step-up verification required before processing."
    else:
        msg = "Transaction approved."

    return TransactionResponse(
        transaction_id=result["transaction_id"],
        risk=risk,
        message=msg,
    )
