"""
sky-shield/network/blocker.py

IP Blocker — iptables Integration
====================================
Applies iptables rules on Kali Linux to DROP packets from malicious IPs.
Requires root privileges (run sky-shield as sudo or with CAP_NET_ADMIN).

Falls back to a soft-block log if iptables is unavailable (non-root mode).
"""

import subprocess
import logging
import time
import threading
from config import BLOCK_DURATION, USE_IPTABLES

logger = logging.getLogger("skyshield.blocker")


class IPBlocker:
    """
    Manages iptables rules for blocking/unblocking IPs.

    Uses the INPUT chain by default.
    Each rule is temporary — auto-unblocked after BLOCK_DURATION seconds.
    """

    CHAIN = "INPUT"
    IPTABLES = "/sbin/iptables"

    def __init__(self, use_iptables: bool = USE_IPTABLES):
        self.use_iptables = use_iptables
        self._blocked: dict[str, float] = {}  # IP → unblock timestamp
        self._block_log: list = []             # Audit log
        self._lock = threading.Lock()

        # Start auto-unblock thread
        self._unblock_thread = threading.Thread(
            target=self._auto_unblock_loop, daemon=True
        )
        self._unblock_thread.start()

        logger.info(
            f"IPBlocker initialized (iptables={'enabled' if use_iptables else 'disabled/simulation'})"
        )

    def block(self, ip: str, duration: int = BLOCK_DURATION, reason: str = "DDoS"):
        """
        Block an IP address for a given duration.
        Applies an iptables DROP rule (if enabled) and records the block.

        If the IP is already blocked, extends the expiry time.
        If the IP was previously unblocked (deleted from _blocked), it is
        re-added as a fresh entry so the dashboard shows it again.
        """
        with self._lock:
            if ip in self._blocked:
                # Extend the block — IP already visible in dashboard
                self._blocked[ip] = max(
                    self._blocked[ip], time.time() + duration
                )
                return

            # Fresh block or re-block after manual unblock cleared _blocked
            self._blocked[ip] = time.time() + duration
            self._block_log.append({
                "ip": ip,
                "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": duration,
                "reason": reason,
                "unblocked": False,
            })

        if self.use_iptables:
            success = self._run_iptables("-I", ip)
            if success:
                logger.warning(f"[BLOCKED] {ip} for {duration}s — {reason}")
            else:
                logger.error(f"[BLOCK FAILED] Could not block {ip} via iptables")
        else:
            logger.warning(f"[SOFT BLOCK] {ip} for {duration}s — {reason} (simulation)")

    def unblock(self, ip: str):
        """
        Unblock an IP address (remove iptables rule).
        Deletes from _blocked so that a subsequent block() call creates
        a fresh entry and the dashboard shows the re-block.
        """
        with self._lock:
            if ip not in self._blocked:
                return
            del self._blocked[ip]

            # Update audit log
            for entry in reversed(self._block_log):
                if entry["ip"] == ip and not entry["unblocked"]:
                    entry["unblocked"] = True
                    entry["unblocked_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    break

        if self.use_iptables:
            self._run_iptables("-D", ip)
            logger.info(f"[UNBLOCKED] {ip}")
        else:
            logger.info(f"[SOFT UNBLOCK] {ip}")

    def _run_iptables(self, action: str, ip: str) -> bool:
        """
        Run an iptables command.
        action: '-I' to insert (block), '-D' to delete (unblock)
        """
        cmd = [
            self.IPTABLES,
            action, self.CHAIN,
            "-s", ip,
            "-j", "DROP",
            "-m", "comment",
            "--comment", "sky-shield"
        ]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                logger.error(f"iptables error: {result.stderr.strip()}")
                return False
            return True
        except FileNotFoundError:
            logger.error("iptables not found. Install with: sudo apt install iptables")
            return False
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out")
            return False
        except PermissionError:
            logger.error("Permission denied. Run sky-shield as root (sudo).")
            return False

    def _auto_unblock_loop(self):
        """Background thread that unblocks IPs after their duration expires."""
        while True:
            time.sleep(10)  # Check every 10 seconds
            now = time.time()
            with self._lock:
                expired = [ip for ip, exp in self._blocked.items() if now >= exp]

            for ip in expired:
                self.unblock(ip)

    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked."""
        with self._lock:
            if ip not in self._blocked:
                return False
            return time.time() < self._blocked[ip]

    def get_blocked_list(self) -> list:
        """Return all currently blocked IPs with their expiry times."""
        now = time.time()
        with self._lock:
            return [
                {
                    "ip": ip,
                    "expires_in": max(0, int(exp - now)),
                    "expires_at": time.strftime(
                        "%H:%M:%S", time.localtime(exp)
                    ),
                }
                for ip, exp in self._blocked.items()
                if now < exp
            ]

    def get_block_log(self, limit: int = 50) -> list:
        """Return the most recent block/unblock events."""
        return self._block_log[-limit:][::-1]

    def flush_all(self):
        """Remove all sky-shield iptables rules (cleanup on exit)."""
        if not self.use_iptables:
            return
        try:
            for ip in list(self._blocked.keys()):
                self.unblock(ip)
            logger.info("All sky-shield iptables rules flushed.")
        except Exception as e:
            logger.error(f"Flush error: {e}")

    def get_stats(self) -> dict:
        return {
            "currently_blocked": len(self.get_blocked_list()),
            "total_blocks": len(self._block_log),
            "iptables_enabled": self.use_iptables,
            "blocked_ips": len(self.get_blocked_list()),
        }
