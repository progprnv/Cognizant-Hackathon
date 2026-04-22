"""
backend/services/device_agent.py
──────────────────────────────────
Device Fingerprinting Agent

Responsibilities:
  • Determine if device is known (seen before for this user)
  • Detect SAME-DEVICE attacks (device matches but behaviour deviates)
  • Track trust score degradation on suspicious events
  • Parse OS / browser from user-agent
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog

from backend.models.schemas import DeviceFingerprint

logger = structlog.get_logger()


class DeviceAgent:

    @staticmethod
    def build_device_id(fp: DeviceFingerprint, ip_address: str) -> str:
        """
        Create a stable device hash.
        We intentionally EXCLUDE IP so the same device on a different
        network still gets the same ID — IP changes are tracked separately.
        """
        raw = "|".join([
            fp.user_agent,
            fp.screen_res,
            fp.timezone or "",
            fp.language or "",
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    @staticmethod
    def analyse(
        fp: DeviceFingerprint,
        ip_address: str,
        user_devices: List[Any],   # list of ORM DeviceProfile rows
    ) -> Dict[str, Any]:
        """
        Returns
        ───────
        {
          "is_new_device": bool,
          "device_id": str,
          "os_info": str,
          "browser_info": str,
          "matched_profile": DeviceProfile | None,
          "same_device_anomaly": bool,  # device known but characteristics mutated
        }
        """
        device_id = DeviceAgent.build_device_id(fp, ip_address)
        os_info, browser_info = DeviceAgent.parse_user_agent(fp.user_agent)

        # Look for a matching known device
        matched = next(
            (d for d in user_devices if d.device_id == device_id), None
        )

        is_new_device = matched is None

        # ── Same-device anomaly check ─────────────────────────────
        # Even if device_id matches, check whether the UA fingerprint
        # has mutated significantly (browser version jump, OS change, etc.)
        same_device_anomaly = False
        if matched:
            known_os      = matched.os_info or ""
            known_browser = matched.browser_info or ""
            # OS change = strong anomaly
            if known_os and os_info and known_os.split()[0] != os_info.split()[0]:
                same_device_anomaly = True
                logger.warning("same_device_os_change",
                               device_id=device_id,
                               known_os=known_os, new_os=os_info)
            # Screen resolution changed on "same" device
            if matched.screen_res and fp.screen_res != matched.screen_res:
                same_device_anomaly = True
                logger.warning("same_device_screen_change",
                               device_id=device_id,
                               known_res=matched.screen_res, new_res=fp.screen_res)

        return {
            "device_id":          device_id,
            "is_new_device":      is_new_device,
            "os_info":            os_info,
            "browser_info":       browser_info,
            "matched_profile":    matched,
            "same_device_anomaly": same_device_anomaly,
        }

    @staticmethod
    def parse_user_agent(ua: str) -> tuple[str, str]:
        """
        Extract OS and browser name from User-Agent string.
        Returns ("OS string", "Browser string").
        """
        # OS detection
        os_info = "Unknown OS"
        if "Windows NT 10" in ua:
            os_info = "Windows 10/11"
        elif "Windows NT 6.1" in ua:
            os_info = "Windows 7"
        elif "Windows" in ua:
            os_info = "Windows"
        elif "Mac OS X" in ua:
            ver = re.search(r"Mac OS X ([\d_]+)", ua)
            os_info = f"macOS {ver.group(1).replace('_', '.')}" if ver else "macOS"
        elif "Android" in ua:
            ver = re.search(r"Android ([\d.]+)", ua)
            os_info = f"Android {ver.group(1)}" if ver else "Android"
        elif "iPhone" in ua or "iPad" in ua:
            os_info = "iOS"
        elif "Linux" in ua:
            os_info = "Linux"

        # Browser detection (order matters — Chrome must come before Safari)
        browser_info = "Unknown Browser"
        if "Edg/" in ua:
            ver = re.search(r"Edg/([\d.]+)", ua)
            browser_info = f"Edge {ver.group(1)}" if ver else "Edge"
        elif "OPR/" in ua or "Opera" in ua:
            browser_info = "Opera"
        elif "Chrome/" in ua and "Chromium" not in ua:
            ver = re.search(r"Chrome/([\d.]+)", ua)
            browser_info = f"Chrome {ver.group(1).split('.')[0]}" if ver else "Chrome"
        elif "Firefox/" in ua:
            ver = re.search(r"Firefox/([\d.]+)", ua)
            browser_info = f"Firefox {ver.group(1).split('.')[0]}" if ver else "Firefox"
        elif "Safari/" in ua:
            browser_info = "Safari"

        return os_info, browser_info

    @staticmethod
    def trust_score_update(current_score: float, anomaly: bool) -> float:
        """Decay trust score on anomaly; recover slowly on clean sessions."""
        if anomaly:
            return max(0.0, current_score - 25.0)
        return min(100.0, current_score + 2.0)
