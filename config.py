"""
sky-shield/config.py

Central Configuration
=====================
All tunable parameters for Sky-Shield in one place.
"""

# ─────────────────────────────────────────────
#  Network Interface
# ─────────────────────────────────────────────
MONITOR_INTERFACE = "eth0"      # Interface to sniff on
MONITOR_PORT     = 80           # HTTP port
HTTPS_PORT       = 443          # HTTPS port

# ─────────────────────────────────────────────
#  Sketch Parameters
# ─────────────────────────────────────────────
SKETCH_ROWS   = 4               # Number of hash functions (rows in sketch table)
SKETCH_COLS   = 1024            # Number of columns (buckets per row)
SKETCH_WINDOW = 5               # Time window in seconds for each sketch snapshot

# ─────────────────────────────────────────────
#  Hellinger Distance Threshold
# ─────────────────────────────────────────────
HELLINGER_THRESHOLD = 0.3       # Distance above this → attack declared

# ─────────────────────────────────────────────
#  Trust / Bloom Filter Parameters
# ─────────────────────────────────────────────
BLOOM_CAPACITY    = 10000       # Expected number of unique IPs
BLOOM_ERROR_RATE  = 0.01        # Acceptable false positive rate

INITIAL_TRUST       = 100       # Starting trust value for each IP
TRUST_DECREMENT     = 10        # Deducted per suspicious hit
TRUST_INCREMENT     = 5         # Added per clean request

# Raised 30 → 50: bots with score=60 drop to trust=40, which is now ≤ threshold → BLOCK
BLACKLIST_THRESHOLD = 50        # Trust at or below this → blacklisted
WHITELIST_THRESHOLD = 90        # Trust at or above this → whitelisted

# ─────────────────────────────────────────────
#  Blocking
# ─────────────────────────────────────────────
BLOCK_DURATION = 300            # Seconds to block an IP (5 minutes)

# Set False: iptables requires root; soft-block dict is sufficient for simulation
USE_IPTABLES   = False          # Use iptables for real blocking (requires root)

# ─────────────────────────────────────────────
#  Bot Detection
# ─────────────────────────────────────────────
REQUEST_RATE_LIMIT = 100        # Max requests per SKETCH_WINDOW before flagged
AUTO_BLOCK         = True       # Automatically block detected bots

# ─────────────────────────────────────────────
#  Dashboard Server
# ─────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"     # Host to bind the Flask dashboard
DASHBOARD_PORT = 5000           # Port for the web dashboard
