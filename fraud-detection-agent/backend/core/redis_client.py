"""
backend/core/redis_client.py
────────────────────────────
Async Redis client used by:
  - Session caching (device / geo context)
  - Rate limiting
  - Real-time alert pub/sub
"""

import redis.asyncio as aioredis
from backend.core.config import settings


redis_client: aioredis.Redis = aioredis.from_url(
    settings.REDIS_URL,
    encoding="utf-8",
    decode_responses=True,
)
