"""
backend/services/behavioral_agent.py
──────────────────────────────────────
Behavioural Analysis Agent

Tracks and compares:
  • Typing speed / keystroke timing
  • Mouse movement volume
  • Session duration
  • Login time-of-day patterns

Returns a dict of normalised features + an anomaly score contribution.
"""

from __future__ import annotations

import statistics
from datetime import datetime
from typing import Any, Dict, List, Optional

import structlog

from backend.core.config import settings
from backend.models.schemas import BehavioralSignals

logger = structlog.get_logger()


class BehavioralAgent:
    """
    Stateless analyser — receives signals from the request and the
    user's stored BehavioralProfile, returns feature values for the ML model.
    """

    @staticmethod
    def analyse(
        signals: BehavioralSignals,
        profile: Optional[Any],   # ORM BehavioralProfile | None
    ) -> Dict[str, float]:
        """
        Compare incoming signals against user's historical baseline.

        Returns
        ───────
        dict with keys matching FEATURE_NAMES in model_manager.py
        """
        result: Dict[str, float] = {}

        # ── 1. Login duration ──────────────────────────────────────
        dur_ms = signals.login_duration_ms
        result["login_duration_ms"] = dur_ms

        # ── 2. Keystroke timing ───────────────────────────────────
        intervals = signals.keystroke_intervals
        if intervals:
            avg_ki = statistics.mean(intervals)
            result["keystroke_avg_interval"] = avg_ki
        else:
            # No keystrokes at all → strongest autofill signal
            result["keystroke_avg_interval"] = 0.0

        # ── 3. Mouse activity ─────────────────────────────────────
        result["mouse_event_count"] = float(signals.mouse_event_count)

        # ── 4. Typing speed ───────────────────────────────────────
        if signals.typing_speed_wpm is not None:
            result["typing_speed_wpm"] = signals.typing_speed_wpm
        elif intervals:
            # Estimate: chars / min  assuming avg 5 chars per word
            chars_typed = len(intervals) + 1
            time_min = (dur_ms / 1000) / 60
            result["typing_speed_wpm"] = (chars_typed / 5) / max(time_min, 0.001)
        else:
            result["typing_speed_wpm"] = 0.0

        # ── 5. Unusual login hour ─────────────────────────────────
        current_hour = datetime.utcnow().hour
        if profile and profile.typical_login_hours:
            typical = set(profile.typical_login_hours)
            # Allow ±2-hour window around any typical hour
            expected = set()
            for h in typical:
                expected.update({(h - 2) % 24, (h - 1) % 24, h, (h + 1) % 24, (h + 2) % 24})
            result["is_unusual_hour"] = 0.0 if current_hour in expected else 1.0
        else:
            # No profile yet: business hours (7-23) are "normal"
            result["is_unusual_hour"] = 0.0 if 7 <= current_hour <= 23 else 1.0

        # ── 6. Autofill detection ─────────────────────────────────
        autofill = _detect_autofill(signals)
        result["autofill_detected"] = 1.0 if autofill else 0.0

        logger.debug("behavioral_analysis_complete",
                     dur_ms=dur_ms,
                     keystroke_avg=result["keystroke_avg_interval"],
                     autofill=autofill)
        return result

    @staticmethod
    def compute_profile_update(
        signals: BehavioralSignals,
        profile: Optional[Any],
        current_hour: int,
    ) -> Dict[str, Any]:
        """
        Return updated fields for BehavioralProfile using exponential
        moving average (EMA) with α = 0.15 (slow adaptation).
        """
        α = 0.15   # learning rate

        intervals = signals.keystroke_intervals
        avg_ki = statistics.mean(intervals) if intervals else 0.0
        wpm    = signals.typing_speed_wpm or 0.0

        if profile is None:
            return {
                "avg_login_duration_ms":    signals.login_duration_ms,
                "avg_keystroke_interval_ms": avg_ki,
                "avg_mouse_events":         signals.mouse_event_count,
                "avg_typing_speed_wpm":     wpm,
                "typical_login_hours":      [current_hour],
                "login_count":              1,
            }

        # EMA update
        new_dur  = α * signals.login_duration_ms + (1 - α) * profile.avg_login_duration_ms
        new_ki   = α * avg_ki  + (1 - α) * profile.avg_keystroke_interval_ms
        new_mouse= α * signals.mouse_event_count + (1 - α) * profile.avg_mouse_events
        new_wpm  = α * wpm     + (1 - α) * profile.avg_typing_speed_wpm

        # Update typical hours (rolling window of last 20 unique hours)
        hours = list(set(profile.typical_login_hours or []))
        if current_hour not in hours:
            hours.append(current_hour)
        typical_hours = hours[-20:]

        return {
            "avg_login_duration_ms":     round(new_dur, 1),
            "avg_keystroke_interval_ms": round(new_ki, 2),
            "avg_mouse_events":          round(new_mouse, 1),
            "avg_typing_speed_wpm":      round(new_wpm, 2),
            "typical_login_hours":       typical_hours,
            "login_count":               (profile.login_count or 0) + 1,
        }


# ── Module-level helper ───────────────────────────────────────────
def _detect_autofill(signals: BehavioralSignals) -> bool:
    """
    Return True if the behavioural signals suggest credential autofill or bot.

    Rule 1: Duration below human threshold AND no keystrokes
    Rule 2: Duration < 300 ms (human cannot read and type that fast)
    Rule 3: Browser JS explicitly flagged autofill
    """
    threshold_ms = settings.AUTOFILL_TIME_THRESHOLD_MS

    no_typing = len(signals.keystroke_intervals) == 0
    too_fast  = signals.login_duration_ms < threshold_ms

    return (too_fast and no_typing) or too_fast or signals.autofill_suspected
