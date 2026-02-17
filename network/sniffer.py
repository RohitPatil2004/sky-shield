"""
sky-shield/network/sniffer.py

HTTP Traffic Sniffer
====================
Captures live HTTP packets on the monitored interface using Scapy.
Extracts source IPs and feeds them into the Sketch + BotDetector.

In a real deployment this runs as root (needed for raw socket capture).
For testing/demo, a simulation mode is available.
"""

from __future__ import annotations
import typing
import typing as t
if typing.TYPE_CHECKING:
    from simulator.attack_sim import TrafficSimulator

import threading
import time
import logging
from collections import defaultdict
from typing import Callable, Optional

try:
    from scapy.layers.inet import IP, TCP
    from scapy.all import sniff, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    # Fallback for static analysis (these won't be used if import fails)
    IP = None  # type: ignore
    TCP = None  # type: ignore
    sniff = None  # type: ignore
    Raw = None  # type: ignore
    SCAPY_AVAILABLE = False

# Type alias for sniff function
SniffFunc = t.Optional[t.Callable[..., t.Any]]

from core.sketch import Sketch
from core.hellinger import sketch_divergence
from core.bloom_filter import TrustManager
from core.bot_detector import BotDetector
from config import (
    MONITOR_INTERFACE,
    MONITOR_PORT,
    HTTPS_PORT,
    SKETCH_WINDOW,
    AUTO_BLOCK,
)

logger = logging.getLogger("skyshield.sniffer")


class TrafficSniffer:
    """
    Captures HTTP packets, updates sketches, and triggers detection pipeline.

    Flow:
      1. Packet arrives → extract source IP
      2. Update current_sketch with IP
      3. Every SKETCH_WINDOW seconds → compare with baseline_sketch
      4. If Hellinger distance > threshold → alert + identify bots
      5. Rotate sketches (current becomes new baseline)
    """

    def __init__(self, trust_manager: TrustManager, bot_detector: BotDetector, event_bus=None):
        self.trust_manager = trust_manager
        self.bot_detector = bot_detector
        self.event_bus = event_bus  # Optional callback for dashboard updates

        self.baseline_sketch = Sketch()
        self.current_sketch = Sketch()

        self._running = False
        self._sniff_thread = None
        self._rotate_thread = None

        self._seen_ips: set = set()  # IPs in current window
        self._packet_count = 0
        self._attack_count = 0
        self._blocked_count = 0
        self._lock = threading.Lock()

        # Rate tracking
        self._packets_per_second = 0
        self._last_rate_calc = time.time()
        self._packets_since_last_calc = 0

    def _process_packet(self, pkt):
        """Callback for each captured packet."""
        try:
            if not pkt.haslayer(IP):
                return

            src_ip = pkt[IP].src

            # Filter: only process HTTP/HTTPS packets
            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                if dport not in (MONITOR_PORT, HTTPS_PORT) and sport not in (MONITOR_PORT, HTTPS_PORT):
                    return

            with self._lock:
                # Update sketch
                self.current_sketch.update(src_ip)
                self._seen_ips.add(src_ip)
                self._packet_count += 1
                self._packets_since_last_calc += 1

            # Quick per-packet checks
            is_rate_abuser = self.bot_detector.record_request(src_ip)
            if is_rate_abuser:
                self.trust_manager.record_suspicious(src_ip)
                logger.warning(f"Rate abuse detected: {src_ip}")

            # Bloom filter fast-path
            if self.trust_manager.is_blacklisted(src_ip):
                self._emit_event("blocked", {"ip": src_ip, "reason": "blacklist"})

        except Exception as e:
            logger.error(f"Packet processing error: {e}")

    def _rotate_and_analyze(self):
        """
        Periodically rotate sketches and run Hellinger analysis.
        Runs every SKETCH_WINDOW seconds in a background thread.
        """
        while self._running:
            time.sleep(SKETCH_WINDOW)
            if not self._running:
                break

            with self._lock:
                # Calculate divergence between baseline and current
                result = sketch_divergence(self.baseline_sketch, self.current_sketch)
                candidate_ips = list(self._seen_ips)

                # Update packets/sec
                elapsed = time.time() - self._last_rate_calc
                if elapsed > 0:
                    self._packets_per_second = int(
                        self._packets_since_last_calc / elapsed
                    )
                self._packets_since_last_calc = 0
                self._last_rate_calc = time.time()

            logger.info(
                f"[SKETCH ROTATE] Distance={result['distance']:.4f} "
                f"Severity={result['severity']} "
                f"Packets/s={self._packets_per_second}"
            )

            if result["is_attack"]:
                self._attack_count += 1
                logger.warning(
                    f"[ATTACK DETECTED] Hellinger={result['distance']:.4f} "
                    f"| Threshold={result['threshold']}"
                )

                # Identify malicious hosts using abnormal sketch
                with self._lock:
                    bots = self.bot_detector.identify_malicious_hosts(
                        self.baseline_sketch,
                        self.current_sketch,
                        candidate_ips,
                    )

                for bot in bots:
                    if bot["action"] == "BLOCK":
                        self._blocked_count += 1
                        self._emit_event("attack", {
                            "ip": bot["ip"],
                            "score": bot["abnormality_score"],
                            "action": "BLOCK",
                            "distance": result["distance"],
                        })
                    else:
                        self._emit_event("suspicious", {
                            "ip": bot["ip"],
                            "score": bot["abnormality_score"],
                            "action": bot["action"],
                            "distance": result["distance"],
                        })

                self._emit_event("alert", {
                    "severity": result["severity"],
                    "distance": result["distance"],
                    "bots_found": len(bots),
                    "timestamp": time.strftime("%H:%M:%S"),
                })
            else:
                # Traffic is clean → reward visible IPs
                for ip in list(self._seen_ips)[:50]:
                    self.trust_manager.record_clean(ip)

            # Rotate: current becomes the new baseline
            with self._lock:
                self.baseline_sketch = self.current_sketch.clone()
                self.current_sketch.reset()
                self._seen_ips.clear()

            # Emit stats update
            self._emit_event("stats", self.get_stats())

            # Cleanup
            self.bot_detector.purge_stale_entries()

    def _emit_event(self, event_type: str, data: dict):
        """Push an event to the dashboard event bus (if connected)."""
        if self.event_bus:
            try:
                self.event_bus(event_type, data)
            except Exception as e:
                logger.error(f"Event emit error: {e}")

    def start(self, interface: str = MONITOR_INTERFACE):
        """Start packet capture and analysis threads."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available — using simulation mode.")
            self._start_simulation()
            return

        self._running = True

        # Start sketch rotation thread
        self._rotate_thread = threading.Thread(
            target=self._rotate_and_analyze, daemon=True
        )
        self._rotate_thread.start()

        # Start Scapy sniffer in background thread
        filter_str = f"tcp and (port {MONITOR_PORT} or port {HTTPS_PORT})"
        self._sniff_thread = threading.Thread(
            target=lambda: sniff(  # type: ignore[operator]
                iface=interface,
                filter=filter_str,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running,
            ),
            daemon=True,
        )
        self._sniff_thread.start()
        logger.info(f"Sky-Shield sniffer started on {interface}:{MONITOR_PORT}")

    def _start_simulation(self):
        """
        Simulation mode — generates synthetic traffic for testing
        when no real network traffic is available or no root privileges.
        """
        from simulator.attack_sim import TrafficSimulator
        self._running = True

        self._rotate_thread = threading.Thread(
            target=self._rotate_and_analyze, daemon=True
        )
        self._rotate_thread.start()

        sim = TrafficSimulator(self)
        self._sim_thread = threading.Thread(
            target=sim.run, daemon=True
        )
        self._sim_thread.start()
        logger.info("Sky-Shield started in SIMULATION mode")

    def stop(self):
        """Stop all background threads."""
        self._running = False
        logger.info("Sky-Shield sniffer stopped.")

    def inject_packet(self, src_ip: str, count: int = 1):
        """
        Manually inject a simulated packet — used by simulator and unit tests.
        """
        with self._lock:
            self.current_sketch.update(src_ip, count)
            self._seen_ips.add(src_ip)
            self._packet_count += count
            self._packets_since_last_calc += count

        self.bot_detector.record_request(src_ip)

        if self.trust_manager.is_blacklisted(src_ip):
            self._blocked_count += 1

    def get_stats(self) -> dict:
        """Return current runtime statistics."""
        return {
            "total_packets": self._packet_count,
            "packets_per_second": self._packets_per_second,
            "attack_events": self._attack_count,
            "blocked_ips": self._blocked_count,
            "tracked_ips": len(self.trust_manager._trust),
            "flagged_ips": len(self.trust_manager._flagged_ips),
            "running": self._running,
            "timestamp": time.strftime("%H:%M:%S"),
        }
