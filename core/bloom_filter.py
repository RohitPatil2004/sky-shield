"""
sky-shield/core/bloom_filter.py

Dual Bloom Filter — Whitelist & Blacklist
==========================================

SkyShield uses two Bloom filters:
  1. Whitelist: trusted IPs that pass freely
  2. Blacklist: confirmed malicious IPs to block

Each IP has a trust value [0, 100]:
  - Starts at INITIAL_TRUST
  - Decrements on suspicious behaviour
  - Increments on clean requests
  - Falls to BLACKLIST_THRESHOLD → added to blacklist
  - Rises to WHITELIST_THRESHOLD → added to whitelist

The Bloom filter is a space-efficient probabilistic structure.
It may have false positives (legitimate IP flagged) but never
false negatives (malicious IP passes through).
"""

import mmh3
from bitarray import bitarray
import math
import time
import threading
from config import (
    BLOOM_CAPACITY,
    BLOOM_ERROR_RATE,
    INITIAL_TRUST,
    TRUST_DECREMENT,
    TRUST_INCREMENT,
    BLACKLIST_THRESHOLD,
    WHITELIST_THRESHOLD,
    BLOCK_DURATION,
)


class BloomFilter:
    """
    A standard Bloom filter with configurable capacity and error rate.
    Uses multiple hash functions via MurmurHash3 with different seeds.
    """

    def __init__(self, capacity: int = BLOOM_CAPACITY, error_rate: float = BLOOM_ERROR_RATE):
        self.capacity = capacity
        self.error_rate = error_rate

        # Calculate optimal bit array size and number of hash functions
        # m = -(n * ln(p)) / (ln(2))^2
        # k = (m/n) * ln(2)
        self.size = self._optimal_size(capacity, error_rate)
        self.hash_count = self._optimal_hash_count(self.size, capacity)
        self.bit_array = bitarray(self.size)
        self.bit_array.setall(0)
        self._count = 0

    @staticmethod
    def _optimal_size(n: int, p: float) -> int:
        m = -(n * math.log(p)) / (math.log(2) ** 2)
        return int(m)

    @staticmethod
    def _optimal_hash_count(m: int, n: int) -> int:
        k = (m / n) * math.log(2)
        return max(1, int(k))

    def add(self, item: str):
        """Add an item to the Bloom filter."""
        for seed in range(self.hash_count):
            index = mmh3.hash(item, seed=seed, signed=False) % self.size
            self.bit_array[index] = 1
        self._count += 1

    def __contains__(self, item: str) -> bool:
        """Check if an item is possibly in the filter (may have false positives)."""
        for seed in range(self.hash_count):
            index = mmh3.hash(item, seed=seed, signed=False) % self.size
            if not self.bit_array[index]:
                return False
        return True

    def clear(self):
        """Reset the filter."""
        self.bit_array.setall(0)
        self._count = 0

    def __len__(self):
        return self._count

    def __repr__(self):
        return (
            f"BloomFilter(capacity={self.capacity}, "
            f"size={self.size} bits, "
            f"hash_count={self.hash_count}, "
            f"items≈{self._count})"
        )


class TrustManager:
    """
    Manages per-IP trust scores and dual Bloom filters (whitelist + blacklist).

    Trust Score Logic:
      - New IP starts at INITIAL_TRUST
      - Clean request  → += TRUST_INCREMENT
      - Suspicious     → -= TRUST_DECREMENT
      - Score ≤ BLACKLIST_THRESHOLD → blacklisted (blocked)
      - Score ≥ WHITELIST_THRESHOLD → whitelisted (fast-pass)
    """

    def __init__(self):
        self.whitelist = BloomFilter()
        self.blacklist = BloomFilter()

        # Exact trust scores per IP (dict for precise tracking)
        self._trust: dict[str, int] = {}
        self._block_expiry: dict[str, float] = {}  # IP → unblock timestamp
        self._request_counts: dict[str, int] = {}  # IP → total requests
        self._flagged_ips: set = set()              # IPs currently flagged

        self._lock = threading.Lock()

    def get_trust(self, ip: str) -> int:
        """Return the current trust value for an IP (default: INITIAL_TRUST)."""
        return self._trust.get(ip, INITIAL_TRUST)

    def record_clean(self, ip: str):
        """Increment trust after a clean/legitimate request."""
        with self._lock:
            current = self._trust.get(ip, INITIAL_TRUST)
            new_trust = min(100, current + TRUST_INCREMENT)
            self._trust[ip] = new_trust
            self._request_counts[ip] = self._request_counts.get(ip, 0) + 1

            if new_trust >= WHITELIST_THRESHOLD:
                self.whitelist.add(ip)

    def record_suspicious(self, ip: str):
        """Decrement trust after a suspicious request."""
        with self._lock:
            current = self._trust.get(ip, INITIAL_TRUST)
            new_trust = max(0, current - TRUST_DECREMENT)
            self._trust[ip] = new_trust
            self._flagged_ips.add(ip)

            if new_trust <= BLACKLIST_THRESHOLD:
                self._blacklist_ip(ip)

    def _blacklist_ip(self, ip: str):
        """Add IP to blacklist with a block expiry."""
        self.blacklist.add(ip)
        self._block_expiry[ip] = time.time() + BLOCK_DURATION

    def is_blacklisted(self, ip: str) -> bool:
        """Check if an IP is currently blacklisted (and block hasn't expired).

        IMPORTANT: Bloom filters are append-only — once an IP is added, it stays
        in the filter forever. We therefore check expiry BEFORE consulting the
        Bloom filter. expiry == 0 means manual_unblock was called; treat as clear.
        """
        expiry = self._block_expiry.get(ip, 0)
        if expiry == 0:
            # Manually unblocked — override the Bloom filter
            return False
        if time.time() > expiry:
            # Natural expiry — partial trust recovery
            self._trust[ip] = INITIAL_TRUST // 2
            return False
        # Expiry is valid and in the future — confirm with Bloom filter
        return ip in self.blacklist

    def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted (trusted)."""
        return ip in self.whitelist

    def get_status(self, ip: str) -> str:
        """Return the status of an IP: 'WHITELISTED', 'BLACKLISTED', or 'UNKNOWN'."""
        if self.is_blacklisted(ip):
            return "BLACKLISTED"
        if self.is_whitelisted(ip):
            return "WHITELISTED"
        return "UNKNOWN"

    def get_all_flagged(self) -> list:
        """Return list of all flagged/suspicious IPs with their trust values."""
        return [
            {
                "ip": ip,
                "trust": self._trust.get(ip, INITIAL_TRUST),
                "status": self.get_status(ip),
                "requests": self._request_counts.get(ip, 0),
            }
            for ip in self._flagged_ips
        ]

    def get_stats(self) -> dict:
        """Return summary statistics."""
        blacklisted = [
            ip for ip in self._flagged_ips if self.is_blacklisted(ip)
        ]
        return {
            "total_tracked": len(self._trust),
            "flagged": len(self._flagged_ips),
            "blacklisted": len(blacklisted),
            "whitelisted_approx": len(self.whitelist),
            "blacklist_filter": repr(self.blacklist),
            "whitelist_filter": repr(self.whitelist),
        }

    def manual_block(self, ip: str, duration: int = BLOCK_DURATION):
        """Manually block an IP for a given duration."""
        with self._lock:
            self._trust[ip] = 0
            self._blacklist_ip(ip)
            self._block_expiry[ip] = time.time() + duration
            self._flagged_ips.add(ip)

    def manual_unblock(self, ip: str):
        """Manually remove a block — fully restore trust so the system doesn't
        immediately re-blacklist the IP on the next sketch window.

        Why full reset (not half)?
        - BLACKLIST_THRESHOLD = 50, INITIAL_TRUST = 100
        - Half reset → trust = 50, exactly at threshold — one hit re-blacklists
        - Full reset → trust = 100, gives the IP a genuine second chance

        Why expiry = 0?
        - Bloom filters are append-only; we can't remove the IP from the filter
        - is_blacklisted() checks expiry FIRST and returns False when expiry == 0
        """
        with self._lock:
            self._trust[ip] = INITIAL_TRUST    # full reset
            self._block_expiry[ip] = 0          # sentinel: manually unblocked
            self._flagged_ips.discard(ip)
