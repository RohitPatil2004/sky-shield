# ─────────────────────────────────────────────
#  SKETCH CONFIGURATION
# ─────────────────────────────────────────────
SKETCH_ROWS = 4          # Number of hash functions (rows in sketch table)
SKETCH_COLS = 1024       # Number of columns (buckets per row)
SKETCH_WINDOW = 5        # Time window in seconds for each sketch snapshot

# ─────────────────────────────────────────────
#  HELLINGER DISTANCE THRESHOLD
# ─────────────────────────────────────────────
# Divergence threshold - if Hellinger distance exceeds this, attack is detected
# Range: [0.0, 1.0]
HELLINGER_THRESHOLD = 0.3

# ─────────────────────────────────────────────
#  BLOOM FILTER CONFIGURATION
# ─────────────────────────────────────────────
BLOOM_CAPACITY = 100000   # Expected number of IPs to store
BLOOM_ERROR_RATE = 0.001  # False positive rate (0.1%)

# ─────────────────────────────────────────────
#  TRUST VALUE SYSTEM
# ─────────────────────────────────────────────
INITIAL_TRUST = 100        # Starting trust value for each IP
TRUST_DECREMENT = 10       # Deducted per suspicious request
TRUST_INCREMENT = 2        # Added per legitimate request
BLACKLIST_THRESHOLD = 30   # Trust below this → blacklisted
WHITELIST_THRESHOLD = 80   # Trust above this → whitelisted

# ─────────────────────────────────────────────
#  NETWORK SETTINGS
# ─────────────────────────────────────────────
MONITOR_INTERFACE = "eth0"        # Network interface to monitor (change to your NIC)
MONITOR_PORT = 80                  # HTTP port to monitor
HTTPS_PORT = 443
REQUEST_RATE_LIMIT = 100           # Max requests per IP per window before flagging

# ─────────────────────────────────────────────
#  BLOCKING
# ─────────────────────────────────────────────
AUTO_BLOCK = True                  # Automatically apply iptables rules
BLOCK_DURATION = 300               # Seconds to block an IP (5 minutes)
USE_IPTABLES = True                # Use iptables for real blocking (requires root)

# ─────────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────────
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
DASHBOARD_DEBUG = False
LOG_FILE = "logs/skyshield.log"
MAX_LOG_ENTRIES = 1000             # Max events to keep in memory for dashboard

# ─────────────────────────────────────────────
#  CAPTCHA (Soft mitigation)
# ─────────────────────────────────────────────
ENABLE_CAPTCHA = True              # Issue CAPTCHA challenge before hard block
CAPTCHA_ATTEMPTS = 3               # Failed attempts before hard block
