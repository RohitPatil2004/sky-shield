"""
sky-sheild/core/sketch.py

Sketch Data Struture
====================
core component of SkyShield

A Sketch is a 2D array of counters: ROWS x COLS.
Each incoming IP is hashed into ROWS different buckets, 
one per row, using distinct hash seeds. This Compresses 
high-volume traffic into a compact probability distribution
that can be compared over time using Hellinger Distance.
"""

import mmh3
import numpy as np
import time
from config import SKETCH_ROWS, SKETCH_COLS, SKETCH_WINDOW

class Sketch:
    def __init__(self, rows=SKETCH_ROWS, cols=SKETCH_COLS):
        self.rows = rows
        self.cols = cols
        self.table = np.zeros((rows, cols), dtype=np.float64)
        self.total_packets = 0
        self.created_at = time.time()
    
    def update(self, ip: str, count: int = 1):
        # Hash an IP address into each row and increment its bucket.
        for row in range(self.rows):
            col = mmh3.hash(ip, seed=row, signed=False) % self.cols
            self.table[row][col] += count
        self.total_packets += count
    
    def get_distribution(self) -> np.ndarray:
        """
        Normalize each row into a probability distribution.
        Returns shape [ROWS x COLS] where each row sums to 1.
        """
        dist = np.zeros_like(self.table)
        for row in range(self.rows):
            row_sum = self.table[row].sum()
            if row_sum > 0:
                dist[row] = self.table[row] / row_sum
            else:
                dist[row] = np.ones(self.cols) / self.cols  # uniform if empty
        return dist

    def clone(self) -> "Sketch":
        """Return a deep copy of this sketch (used for snapshot comparison)."""
        s = Sketch(self.rows, self.cols)
        s.table = self.table.copy()
        s.total_packets = self.total_packets
        s.created_at = self.created_at
        return s

    def reset(self):
        """Clear the sketch for the next time window."""
        self.table = np.zeros((self.rows, self.cols), dtype=np.float64)
        self.total_packets = 0
        self.created_at = time.time()

    def is_expired(self) -> bool:
        """Check if this sketch's time window has elapsed."""
        return (time.time() - self.created_at) >= SKETCH_WINDOW

    def get_bucket(self, ip: str, row: int) -> float:
        """Return the raw bucket value for an IP in a given row."""
        col = mmh3.hash(ip, seed=row, signed=False) % self.cols
        return self.table[row][col]

    def top_ips_estimate(self, candidate_ips: list) -> list:
        """
        Given a list of candidate IPs, estimate each one's contribution
        using minimum bucket across all rows (Count-Min Sketch estimate).
        Returns sorted list of (ip, estimated_count).
        """
        estimates = []
        for ip in candidate_ips:
            min_count = min(
                self.table[row][mmh3.hash(ip, seed=row, signed=False) % self.cols]
                for row in range(self.rows)
            )
            estimates.append((ip, min_count))
        return sorted(estimates, key=lambda x: x[1], reverse=True)

    def __repr__(self):
        return (
            f"Sketch(rows={self.rows}, cols={self.cols}, "
            f"total_packets={self.total_packets}, "
            f"age={time.time() - self.created_at:.1f}s)"
        )
