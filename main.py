"""
sky-shield/main.py

Sky-Shield — Entry Point
==========================
Wires together all components and starts the system.

Usage:
    # Full simulation mode (no root needed):
    python main.py

    # Live capture mode (requires root + network interface):
    sudo python main.py --live --interface eth0

    # Custom port for dashboard:
    python main.py --port 8080

    # Silent mode (no dashboard):
    python main.py --no-dashboard
"""

import argparse
import logging
import threading
import sys
import os
import signal
import time

# ── Logging Setup ──
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/skyshield.log"),
    ],
)
logger = logging.getLogger("skyshield")

# ── Import Core Modules ──
from core.sketch import Sketch
from core.bloom_filter import TrustManager
from core.bot_detector import BotDetector
from network.sniffer import TrafficSniffer
from network.blocker import IPBlocker
from dashboard.app import init_dashboard, run_dashboard
from config import (
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    MONITOR_INTERFACE,
)

# ── Banner ──
BANNER = r"""
  ____  _          ____  _     _      _     _ 
 / ___|| | ___   _/ ___|| |__ (_) ___| | __| |
 \___ \| |/ / | | \___ \| '_ \| |/ _ \ |/ _` |
  ___) |   <| |_| |___) | | | | |  __/ | (_| |
 |____/|_|\_\\__, |____/|_| |_|_|\___|_|\__,_|
             |___/                             
  Sketch-Based DDoS Defense System
  ─────────────────────────────────────────────
"""


def parse_args():
    parser = argparse.ArgumentParser(description="Sky-Shield DDoS Defense System")
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use live packet capture (requires root + Scapy)",
    )
    parser.add_argument(
        "--interface",
        default=MONITOR_INTERFACE,
        help=f"Network interface to monitor (default: {MONITOR_INTERFACE})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DASHBOARD_PORT,
        help=f"Dashboard port (default: {DASHBOARD_PORT})",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Run without the web dashboard",
    )
    parser.add_argument(
        "--no-block",
        action="store_true",
        help="Disable iptables blocking (detection only)",
    )
    return parser.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    logger.info("Initializing Sky-Shield components...")

    # ── Core Components ──
    trust_manager = TrustManager()
    bot_detector  = BotDetector(trust_manager)
    sniffer       = TrafficSniffer(trust_manager, bot_detector)
    blocker       = IPBlocker(use_iptables=(not args.no_block))

    # ── Wire Blocker into Sniffer ──
    # Auto-block IPs when they're detected as malicious
    original_event_bus = None
    def blocking_event_bus(event_type, data):
        if event_type == "attack" and data.get("ip"):
            blocker.block(data["ip"], reason="SkyShield Auto-Block")
        if original_event_bus:
            original_event_bus(event_type, data)

    sniffer.event_bus = blocking_event_bus

    # ── Dashboard ──
    if not args.no_dashboard:
        init_dashboard(sniffer, blocker, trust_manager, bot_detector)
        # event_bus is now set by init_dashboard; update blocking wrapper
        from dashboard.app import push_event as dash_push
        def combined_bus(event_type, data):
            if event_type == "attack" and data.get("ip"):
                blocker.block(data["ip"], reason="SkyShield Auto-Block")
            dash_push(event_type, data)
        sniffer.event_bus = combined_bus

        logger.info(
            f"Dashboard: http://{DASHBOARD_HOST}:{args.port}"
        )

    # ── Start Sniffer ──
    if args.live:
        logger.info(f"Starting LIVE capture on {args.interface}...")
        sniffer.start(interface=args.interface)
    else:
        logger.info("Starting in SIMULATION mode...")
        sniffer._start_simulation()

    # ── Graceful Shutdown ──
    def shutdown(sig=None, frame=None):
        logger.info("\nShutting down Sky-Shield...")
        sniffer.stop()
        blocker.flush_all()
        logger.info("All iptables rules cleared. Goodbye.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Start Dashboard (blocking) ──
    if not args.no_dashboard:
        logger.info(f"Opening dashboard on http://localhost:{args.port}")
        run_dashboard(host=DASHBOARD_HOST, port=args.port, debug=False)
    else:
        logger.info("Running headless. Press Ctrl+C to stop.")
        while True:
            time.sleep(5)
            stats = sniffer.get_stats()
            logger.info(
                f"[STATUS] Packets={stats['total_packets']} | "
                f"PPS={stats['packets_per_second']} | "
                f"Attacks={stats['attack_events']} | "
                f"Blocked={stats['blocked_ips']}"
            )


if __name__ == "__main__":
    main()
