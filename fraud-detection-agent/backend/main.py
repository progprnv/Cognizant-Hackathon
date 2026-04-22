"""
fraud-detection-agent/backend/main.py
────────────────────────────────────────────────────────────────
FastAPI application entry point.
Mounts all route modules and initialises shared services on
startup (DB pool, Redis client, ML models).
"""

from contextlib import asynccontextmanager
import structlog

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse

from backend.core.config import settings
from backend.core.database import engine, Base
from backend.core.redis_client import redis_client
from backend.ml.model_manager import ModelManager
from backend.routes import auth, transactions, risk, admin, health

logger = structlog.get_logger()


# ── Lifespan (startup / shutdown) ───────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs once at startup and once at shutdown."""
    logger.info("🚀 FraudShield AI starting up…")

    # 1. Create DB tables (use Alembic in production)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables initialised")

    # 2. Connect Redis
    await redis_client.ping()
    logger.info("✅ Redis connected")

    # 3. Load / train ML models
    await ModelManager.initialise()
    logger.info("✅ ML models ready")

    yield  # ← application runs here

    # Shutdown
    await redis_client.aclose()
    await engine.dispose()
    logger.info("👋 FraudShield AI shut down cleanly")


# ── App factory ─────────────────────────────────────────────────
def create_app() -> FastAPI:
    app = FastAPI(
        title="FraudShield AI — Real-Time Fraud Detection",
        version="1.0.0",
        description=(
            "Multi-agent AI system for detecting fraud during login "
            "and financial transactions in real time."
        ),
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # ── Middleware ───────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

    # ── Routers ──────────────────────────────────────────────────
    app.include_router(health.router,        prefix="/api",          tags=["Health"])
    app.include_router(auth.router,          prefix="/api/auth",     tags=["Auth"])
    app.include_router(transactions.router,  prefix="/api/tx",       tags=["Transactions"])
    app.include_router(risk.router,          prefix="/api/risk",     tags=["Risk"])
    app.include_router(admin.router,         prefix="/api/admin",    tags=["Admin"])

    # ── Global exception handler ─────────────────────────────────
    @app.exception_handler(Exception)
    async def global_exception_handler(request, exc):
        logger.error("unhandled_exception", error=str(exc))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error. Fraud shield is active."},
        )

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info",
    )
