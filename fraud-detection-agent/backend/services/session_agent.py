"""
backend/services/session_agent.py
───────────────────────────────────
Session & Context Agent

Analyses:
  • Geo-location change / impossible travel
  • New vs known IP
  • Time-of-day patterns (delegated to BehavioralAgent)
  • Session freshness (token replay detection)
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx
import structlog

from backend.core.config import settings
from backend.core.redis_client import redis_client

logger = structlog.get_logger()

# Cache TTL for geo lookups (24 h)
GEO_CACHE_TTL = 86_400


class SessionAgent:

    @staticmethod
    async def analyse(
        ip_address: str,
        user_profile: Optional[Any],   # ORM BehavioralProfile
        last_login_event: Optional[Any],  # ORM LoginEvent
    ) -> Dict[str, Any]:
        """
        Returns
        ───────
        {
          "is_new_ip": bool,
          "geo_distance_km": float,
          "country": str,
          "city": str,
          "latitude": float,
          "longitude": float,
          "impossible_travel": bool,
        }
        """
        geo = await SessionAgent._geolocate(ip_address)

        # ── New IP? ───────────────────────────────────────────────
        is_new_ip = True
        if user_profile and user_profile.typical_ips:
            is_new_ip = ip_address not in (user_profile.typical_ips or [])

        # ── Geo distance from last login ──────────────────────────
        geo_distance_km = 0.0
        impossible_travel = False

        if last_login_event and last_login_event.latitude and last_login_event.longitude:
            geo_distance_km = _haversine(
                last_login_event.latitude, last_login_event.longitude,
                geo["lat"], geo["lon"],
            )

            # Impossible travel: speed check
            time_delta_h = max(
                0.01,
                (datetime.utcnow() - last_login_event.timestamp).total_seconds() / 3600,
            )
            speed_kmh = geo_distance_km / time_delta_h
            if speed_kmh > settings.IMPOSSIBLE_TRAVEL_SPEED_KMH and geo_distance_km > 100:
                impossible_travel = True
                logger.warning(
                    "impossible_travel_detected",
                    distance_km=geo_distance_km,
                    speed_kmh=speed_kmh,
                    ip=ip_address,
                )

        return {
            "is_new_ip":         is_new_ip,
            "geo_distance_km":   geo_distance_km,
            "country":           geo.get("country", ""),
            "city":              geo.get("city", ""),
            "latitude":          geo.get("lat", 0.0),
            "longitude":         geo.get("lon", 0.0),
            "impossible_travel": impossible_travel,
        }

    @staticmethod
    def compute_ip_update(
        ip_address: str,
        profile: Optional[Any],
    ) -> List[str]:
        """Return updated typical_ips list (rolling window of 10)."""
        ips = list(profile.typical_ips) if profile and profile.typical_ips else []
        if ip_address not in ips:
            ips.append(ip_address)
        return ips[-10:]

    @staticmethod
    async def _geolocate(ip: str) -> Dict[str, Any]:
        """
        Lookup geo for an IP.  Results are cached in Redis for 24 h.
        Falls back to zeros on error.
        """
        # Skip private / loopback IPs
        if ip in ("127.0.0.1", "::1", "localhost") or ip.startswith("192.168.") or ip.startswith("10."):
            return {"country": "LOCAL", "city": "LOCAL", "lat": 0.0, "lon": 0.0}

        cache_key = f"geo:{ip}"
        cached = await redis_client.get(cache_key)
        if cached:
            import json
            return json.loads(cached)

        try:
            async with httpx.AsyncClient(timeout=0.8) as client:
                resp = await client.get(f"{settings.GEOIP_API_URL}/{ip}")
                data = resp.json()
                result = {
                    "country": data.get("country", ""),
                    "city":    data.get("city", ""),
                    "lat":     float(data.get("lat", 0)),
                    "lon":     float(data.get("lon", 0)),
                }
                import json
                await redis_client.setex(cache_key, GEO_CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.warning("geo_lookup_failed", ip=ip, error=str(e))
            return {"country": "", "city": "", "lat": 0.0, "lon": 0.0}


# ── Haversine formula ─────────────────────────────────────────────
def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in kilometres."""
    R = 6371.0
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    Δφ = math.radians(lat2 - lat1)
    Δλ = math.radians(lon2 - lon1)
    a = math.sin(Δφ / 2) ** 2 + math.cos(φ1) * math.cos(φ2) * math.sin(Δλ / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
