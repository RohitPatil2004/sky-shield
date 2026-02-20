"""
sky-shield/simulator/attack_sim.py

DDoS Attack Simulator
======================
Generates synthetic HTTP traffic for testing Sky-Shield without
needing real network traffic or root privileges.

Simulates:
  - Normal traffic: many IPs, low-medium request rates
  - DDoS attack:    a small botnet (10-50 IPs) flooding at high rates
  - Flash crowd:    many legitimate IPs spiking at once (false positive test)
  - Slow loris:     few IPs but incomplete connections (low-rate attack)
"""

from typing import Optional
import time
import random
import threading
import logging
from ipaddress import IPv4Address

logger = logging.getLogger("skyshield.simulator")


def random_ip(prefix: Optional[str] = None) -> str:
    """Generate a random IPv4 address, optionally from a given prefix.

    FIX: Strip trailing dot before splitting so "192.168." doesn't produce
    an empty string part, which caused malformed IPs like "192.168..200".
    """
    if prefix:
        parts = prefix.rstrip(".").split(".")
        while len(parts) < 4:
            parts.append(str(random.randint(1, 254)))
        return ".".join(parts[:4])
    return str(IPv4Address(random.randint(0x01000001, 0xFEFFFFFE)))


class TrafficSimulator:
    """
    Drives synthetic traffic into the sniffer's inject_packet() method.
    Cycles through phases: NORMAL → ATTACK → NORMAL → FLASH_CROWD → ...
    """

    PHASES = [
        {"name": "NORMAL",      "duration": 15, "normal_ips": 50,  "normal_rps": 20,  "attack": False},
        {"name": "DDOS_ATTACK", "duration": 20, "normal_ips": 50,  "normal_rps": 10,  "attack": True,  "bot_count": 20, "bot_rps": 200},
        {"name": "NORMAL",      "duration": 15, "normal_ips": 50,  "normal_rps": 20,  "attack": False},
        {"name": "FLASH_CROWD", "duration": 15, "normal_ips": 300, "normal_rps": 80,  "attack": False},
        {"name": "SLOW_LORIS",  "duration": 15, "normal_ips": 40,  "normal_rps": 15,  "attack": True,  "bot_count": 5,  "bot_rps": 30},
        {"name": "NORMAL",      "duration": 20, "normal_ips": 50,  "normal_rps": 20,  "attack": False},
    ]

    def __init__(self, sniffer):
        self.sniffer = sniffer
        self._running = False

        # Generate stable pools of IPs
        self.normal_ip_pool = [random_ip() for _ in range(500)]
        # FIX: rstrip ensures "192.168." → parts ["192","168"] → valid "192.168.x.y"
        self.bot_ip_pool = [random_ip("192.168.") for _ in range(50)]

    def run(self):
        """Main simulation loop — cycles through phases indefinitely."""
        self._running = True
        phase_idx = 0
        logger.info("[SIM] Traffic simulator started")

        while self._running:
            phase = self.PHASES[phase_idx % len(self.PHASES)]
            logger.info(
                f"[SIM] Phase: {phase['name']} | Duration: {phase['duration']}s"
            )

            # Emit phase change event to dashboard
            if self.sniffer.event_bus:
                self.sniffer.event_bus("sim_phase", {
                    "phase": phase["name"],
                    "duration": phase["duration"],
                    "is_attack": phase.get("attack", False),
                })

            phase_start = time.time()
            phase_duration = phase["duration"]

            # Select IPs for this phase
            normal_count = min(phase["normal_ips"], len(self.normal_ip_pool))
            active_normal_ips = random.sample(self.normal_ip_pool, normal_count)

            bot_ips = []
            if phase.get("attack"):
                bot_count = phase.get("bot_count", 10)
                bot_ips = random.sample(self.bot_ip_pool, min(bot_count, len(self.bot_ip_pool)))

            # Send traffic for this phase
            tick = 0.1  # 100ms ticks
            while self._running and (time.time() - phase_start) < phase_duration:
                # Normal traffic
                normal_rps = phase["normal_rps"]
                normal_per_tick = max(1, int(normal_rps * tick))
                for _ in range(normal_per_tick):
                    ip = random.choice(active_normal_ips)
                    self.sniffer.inject_packet(ip)

                # Attack traffic (bots)
                if phase.get("attack") and bot_ips:
                    bot_rps = phase.get("bot_rps", 100)
                    bot_per_tick = max(1, int(bot_rps * tick))
                    for _ in range(bot_per_tick):
                        ip = random.choice(bot_ips)
                        self.sniffer.inject_packet(ip)

                time.sleep(tick)

            phase_idx += 1

        logger.info("[SIM] Traffic simulator stopped")

    def stop(self):
        self._running = False

    def inject_burst(self, ip: str, count: int = 500):
        """Manually inject a burst of packets from a specific IP."""
        for _ in range(count):
            self.sniffer.inject_packet(ip)
        logger.info(f"[SIM] Injected {count} packets from {ip}")
