"""
sky-shield/core/bot_detector.py

Bot / Malicious Host Detector
================================

Key Innovation: SkyShield avoids expensive "reverse calculation"
of malicious hosts from sketch buckets. Instead, it uses the
*abnormal sketch* — the difference between baseline and current
sketch — to directly rank IPs by their contribution to the anomaly.

Algorithm:
  1. Compute the per-bucket delta: abnormal_sketch = current - baseline
  2. For each candidate IP, estimate its "abnormality score" using
     Count-Min sketch minimum across rows on the delta sketch
  3. IPs with the highest abnormality scores are likely bots
  4. Cross-reference with trust scores from TrustManager

"""

import numpy as np
import mmh3
import time
from collections import defaultdict
from core.sketch import Sketch
from core.bloom_filter import TrustManager
from config import SKETCH_ROWS, SKETCH_COLS, REQUEST_RATE_LIMIT, SKETCH_WINDOW


class BotDetector:
    """
    Identifies malicious hosts contributing to an ongoing DDoS attack
    using the abnormal sketch technique from SkyShield.
    """

    def __init__(self, trust_manager: TrustManager):
        self.trust_manager = trust_manager
        self._ip_window: dict[str, list] = defaultdict(list)  # IP → [timestamps]
        self._ip_request_count: dict[str, int] = defaultdict(int)
        self._detected_bots: dict[str, dict] = {}  # IP → detection info

    def record_request(self, ip: str, timestamp: float | None = None):
        """
        Track an IP's request rate within the current sliding window.
        Returns True if the IP exceeds the request rate limit.
        """
        if timestamp is None:
            timestamp = time.time()

        window_start = timestamp - SKETCH_WINDOW
        # Purge old timestamps
        self._ip_window[ip] = [
            t for t in self._ip_window[ip] if t > window_start
        ]
        self._ip_window[ip].append(timestamp)
        self._ip_request_count[ip] += 1

        count_in_window = len(self._ip_window[ip])
        return count_in_window > REQUEST_RATE_LIMIT

    def compute_abnormal_sketch(
        self, baseline: Sketch, current: Sketch
    ) -> np.ndarray:
        """
        Compute the abnormal sketch = max(current - baseline, 0).
        Buckets that grew sharply indicate where attack traffic landed.
        """
        delta = current.table - baseline.table
        return np.clip(delta, 0, None)

    def identify_malicious_hosts(
        self,
        baseline: Sketch,
        current: Sketch,
        candidate_ips: list,
        top_n: int = 20,
    ) -> list:
        """
        Identify the top malicious IPs from a candidate pool.

        Args:
            baseline:      Reference sketch (before attack)
            current:       Live sketch (during suspected attack)
            candidate_ips: List of IPs seen in the current window
            top_n:         How many top bots to return

        Returns:
            List of dicts: {ip, abnormality_score, request_count, trust, action}
        """
        abnormal = self.compute_abnormal_sketch(baseline, current)
        scored = []

        for ip in candidate_ips:
            # Count-Min estimate on the abnormal sketch
            min_bucket = float("inf")
            for row in range(baseline.rows):
                col = mmh3.hash(ip, seed=row, signed=False) % baseline.cols
                min_bucket = min(min_bucket, abnormal[row][col])

            if min_bucket == float("inf"):
                min_bucket = 0.0

            trust = self.trust_manager.get_trust(ip)
            req_count = len(self._ip_window.get(ip, []))

            scored.append({
                "ip": ip,
                "abnormality_score": float(min_bucket),
                "request_count": req_count,
                "trust": trust,
                "status": self.trust_manager.get_status(ip),
            })

        # Sort by abnormality score descending
        scored.sort(key=lambda x: x["abnormality_score"], reverse=True)
        top = scored[:top_n]

        # Tag actions
        for entry in top:
            if entry["abnormality_score"] > 0:
                if self.trust_manager.is_blacklisted(entry["ip"]):
                    entry["action"] = "BLOCK"
                elif entry["trust"] <= 50:
                    entry["action"] = "CAPTCHA"
                    self.trust_manager.record_suspicious(entry["ip"])
                else:
                    entry["action"] = "MONITOR"
                    self.trust_manager.record_suspicious(entry["ip"])

                # Save to detected bots
                self._detected_bots[entry["ip"]] = {
                    **entry,
                    "detected_at": time.strftime("%H:%M:%S"),
                }

        return top

    def get_rate_abusers(self) -> list:
        """
        Return IPs that are exceeding the request rate limit,
        regardless of sketch analysis.
        """
        now = time.time()
        window_start = now - SKETCH_WINDOW
        abusers = []

        for ip, timestamps in self._ip_window.items():
            recent = [t for t in timestamps if t > window_start]
            if len(recent) > REQUEST_RATE_LIMIT:
                abusers.append({
                    "ip": ip,
                    "requests_in_window": len(recent),
                    "limit": REQUEST_RATE_LIMIT,
                    "trust": self.trust_manager.get_trust(ip),
                })

        return sorted(abusers, key=lambda x: x["requests_in_window"], reverse=True)

    def get_detected_bots(self) -> list:
        """Return all IPs identified as bots during this session."""
        return list(self._detected_bots.values())

    def get_ip_stats(self, ip: str) -> dict:
        """Return per-IP statistics."""
        recent = [
            t for t in self._ip_window.get(ip, [])
            if t > time.time() - SKETCH_WINDOW
        ]
        return {
            "ip": ip,
            "requests_this_window": len(recent),
            "total_requests": self._ip_request_count[ip],
            "trust": self.trust_manager.get_trust(ip),
            "status": self.trust_manager.get_status(ip),
            "is_bot": ip in self._detected_bots,
        }

    def purge_stale_entries(self):
        """Remove IPs with no recent activity to save memory."""
        cutoff = time.time() - (SKETCH_WINDOW * 10)
        stale = [
            ip for ip, ts in self._ip_window.items()
            if not ts or max(ts) < cutoff
        ]
        for ip in stale:
            del self._ip_window[ip]
