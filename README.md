# 🛡️ Sky-Shield

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Flask](https://img.shields.io/badge/Flask-SocketIO-black?logo=flask)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)

**A real-time DDoS detection and mitigation system** built on Count-Min Sketches and Hellinger Distance — with a live web dashboard, trust-based IP scoring, and optional iptables blocking.

> Detects volumetric floods, slow-loris attacks, and flash crowds within seconds using probabilistic data structures. No deep packet inspection required.

---

## 📸 Dashboard Preview

```
⚠ ATTACK DETECTED — HELLINGER DISTANCE THRESHOLD EXCEEDED — MITIGATION ACTIVE

Packets/sec: 209     Attack Events: 3     Blocked IPs: 12     Tracked IPs: 435
Hellinger Distance: 0.961   [████████████████░░░░]   Threshold: 0.30

IP Address        Abnormality   Requests   Trust   Action
192.168.35.146       2400.0        148       0      BLOCK  🔴
192.168.127.88       2200.0        141       0      BLOCK  🔴
192.168.61.203       1980.0        139       0      BLOCK  🔴
```

---

## 📖 What Is This?

Sky-Shield monitors network traffic by compressing it into compact **sketch matrices** and using **Hellinger distance** to detect when the traffic distribution has shifted abnormally compared to a recent baseline.

When an attack is detected, the system identifies the contributing IPs using an **abnormal sketch** — subtracting the baseline sketch from the live sketch to find which buckets (IP hash slots) grew the most. Each IP has a **trust score** that decays under suspicious traffic. When trust drops below the blacklist threshold, the IP is blocked.

Everything runs in a 5-second sliding window, making detection fast and memory usage constant regardless of traffic volume.

---

## 🔬 Research Background

Sky-Shield is based on sketch-based DDoS detection techniques from network security research. The core idea: instead of maintaining per-IP state (which collapses under flood conditions), summarize all traffic into a fixed-size probabilistic structure and compare distributions over time.

| Concept | Role in Sky-Shield |
|---|---|
| **Count-Min Sketch** | Compresses traffic into a fixed `ROWS × COLS` matrix using multiple hash functions. Each IP hashes into one bucket per row. |
| **Hellinger Distance** | Measures divergence between two probability distributions `[0–1]`. Applied per-row and averaged for robustness. |
| **Abnormal Sketch** | `delta = max(current − baseline, 0)` — buckets that grew sharply during the window identify attack traffic. |
| **Count-Min Estimation** | For each candidate IP, take the minimum across all rows of the delta sketch — this is the Count-Min estimate of that IP's contribution to the anomaly. |
| **Bloom Filter** | Space-efficient probabilistic set used for the IP whitelist and blacklist. No deletions needed — expiry is tracked separately. |
| **Trust Scoring** | Per-IP reputation `[0–100]`. Decays proportional to abnormality score. Recovers on clean traffic. Falls below threshold → blacklisted. |

**Key formula:**

```
H(P, Q) = (1/√2) × √( Σ (√pᵢ − √qᵢ)² )

Where:
  P = baseline sketch row (normalized to probability distribution)
  Q = current sketch row (normalized)
  H ∈ [0, 1] — 0 means identical, 1 means completely different
```

---

## 🏗️ Architecture

```
sky-shield/
│
├── main.py                      ← Entry point, wires all components
├── config.py                    ← All tunable parameters
├── requirements.txt
│
├── core/
│   ├── sketch.py                ← Count-Min Sketch (2D numpy array, mmh3 hashing)
│   ├── hellinger.py             ← Hellinger distance + sketch_divergence()
│   ├── bloom_filter.py          ← BloomFilter + TrustManager
│   └── bot_detector.py          ← Abnormal sketch ranking + trust decrement
│
├── network/
│   ├── sniffer.py               ← Packet capture, sketch rotation loop, analysis
│   └── blocker.py               ← iptables / soft-block manager
│
├── dashboard/
│   ├── app.py                   ← Flask + Socket.IO server, REST API
│   ├── templates/
│   │   └── index.html           ← Real-time dashboard UI (WebSocket)
│   └── static/                  ← CSS / JS assets
│
├── simulator/
│   └── attack_sim.py            ← Synthetic traffic generator for testing
│
└── logs/
    └── skyshield.log            ← Runtime log
```

### Detection Loop (runs every `SKETCH_WINDOW` seconds)

```
┌─────────────────────────────────────────────────────────┐
│  Every 5 seconds:                                       │
│                                                         │
│  1. ROTATE                                              │
│     baseline ← clone(current)                           │
│     current  ← reset()                                  │
│                                                         │
│  2. COMPARE                                             │
│     For each row r in [0, SKETCH_ROWS):                 │
│       normalize baseline[r] → P                         │
│       normalize current[r]  → Q                         │
│       distance[r] = Hellinger(P, Q)                     │
│     avg_distance = mean(distance)                       │
│                                                         │
│  3. DECIDE                                              │
│     if avg_distance >= 0.3 → ATTACK                     │
│       abnormal = max(current - baseline, 0)             │
│       for each candidate IP:                            │
│         score = min over rows of abnormal[r][hash(ip,r)]│
│       sort IPs by score descending                      │
│       trust[ip] -= hits × TRUST_DECREMENT               │
│       if trust[ip] <= 50 → BLOCK                        │
│                                                         │
│  4. EMIT to dashboard via WebSocket                     │
└─────────────────────────────────────────────────────────┘
```

---

## ⚙️ Configuration (`config.py`)

| Parameter | Default | Description |
|---|---|---|
| `SKETCH_ROWS` | `4` | Number of hash functions / sketch rows |
| `SKETCH_COLS` | `1024` | Buckets per row |
| `SKETCH_WINDOW` | `5` | Seconds per detection window |
| `HELLINGER_THRESHOLD` | `0.3` | Attack detection threshold `[0–1]` |
| `INITIAL_TRUST` | `100` | Starting trust score per IP |
| `TRUST_DECREMENT` | `10` | Trust lost per suspicious hit |
| `TRUST_INCREMENT` | `5` | Trust gained per clean request |
| `BLACKLIST_THRESHOLD` | `50` | Trust ≤ this → IP blocked |
| `WHITELIST_THRESHOLD` | `90` | Trust ≥ this → IP fast-passed |
| `BLOCK_DURATION` | `300` | Seconds an IP stays blocked (5 min) |
| `USE_IPTABLES` | `False` | Enable real iptables rules (requires root) |
| `REQUEST_RATE_LIMIT` | `100` | Max requests per window before flagging |
| `DASHBOARD_HOST` | `0.0.0.0` | Dashboard bind address |
| `DASHBOARD_PORT` | `5000` | Dashboard port |

---

## 🚀 Installation

### Prerequisites

- Python 3.10+
- Linux (Kali or Ubuntu recommended)
- Root/sudo only needed for live iptables blocking

### Clone & Install

```bash
git clone https://github.com/RohitPatil2004/sky-shield.git
cd sky-shield
pip install -r requirements.txt
```

**`requirements.txt`:**
```
flask
flask-socketio
scapy
mmh3
bitarray
numpy
```

---

## ▶️ Running

### Simulation Mode — No Root Required ✅

Automatically generates synthetic traffic cycling through Normal → DDoS → Flash Crowd → Slow Loris phases. Best for testing and demo.

```bash
python3 main.py
```

Open the dashboard at **http://localhost:5000**

---

### Live Capture Mode — Requires Root

Captures real HTTP/HTTPS traffic from your network interface.

```bash
sudo python3 main.py --live --interface eth0
```

Find your interface name with `ip a` or `ifconfig`.

---

### All CLI Options

```bash
python3 main.py                          # Simulation mode (default)
python3 main.py --port 8080              # Custom dashboard port
python3 main.py --no-dashboard           # Headless / CLI only
sudo python3 main.py --live              # Live capture on default interface
sudo python3 main.py --live --interface wlan0   # Custom interface
sudo python3 main.py --live --no-block   # Detect only, no iptables blocking
python3 main.py --help                   # Show all options
```

---

## 📊 Dashboard

| Panel | Description |
|---|---|
| **Packets/sec** | Live ingress rate |
| **Attack Events** | Hellinger threshold breach count |
| **Blocked IPs** | Currently active blocks |
| **Tracked IPs** | Unique IPs seen this session |
| **Live Traffic Chart** | Packets/sec over time, attack overlay |
| **Hellinger Distance** | Live divergence score vs threshold |
| **Detected Bots Table** | IPs ranked by abnormality score, trust, action |
| **Currently Blocked IPs** | Active blocks with expiry countdown |
| **Event Log** | Real-time stream of all system events |

### Manual Controls

- **BLOCK** — immediately block any IP for 5 minutes
- **UNBLOCK** — remove a block and fully reset the IP's trust score to 100

---

## 🧪 Simulation Phases

| Phase | Duration | IPs | Rate | Type |
|---|---|---|---|---|
| `NORMAL` | 15s | 50 | 20 req/s | Baseline |
| `DDOS_ATTACK` | 20s | 20 bots | 200 req/s | Volumetric flood |
| `NORMAL` | 15s | 50 | 20 req/s | Recovery |
| `FLASH_CROWD` | 15s | 300 | 80 req/s | Legitimate spike |
| `SLOW_LORIS` | 15s | 5 bots | 30 req/s | Low-rate attack |
| `NORMAL` | 20s | 50 | 20 req/s | Final recovery |

**Expected behavior:**
- `DDOS_ATTACK` → Hellinger spikes ~0.96, bot IPs blocked within one window
- `FLASH_CROWD` → Distance rises but IPs spread across many buckets, few/no blocks
- `SLOW_LORIS` → Caught by rate-limit check in `inject_packet`, not sketch analysis

---

## 🔧 Enabling Real iptables Blocking

By default `USE_IPTABLES = False`. For real kernel-level blocking:

1. Set `USE_IPTABLES = True` in `config.py`
2. Run as root: `sudo python3 main.py --live`

Sky-Shield automatically flushes all its iptables rules on shutdown (`CTRL+C`). To manually clear them:

```bash
# List sky-shield rules
sudo iptables -L INPUT -n --line-numbers | grep sky-shield

# Delete by line number
sudo iptables -D INPUT <line-number>
```

---

## 📁 File Map

| File | Project Location |
|---|---|
| `config.py` | `sky-shield/config.py` |
| `bloom_filter.py` | `sky-shield/core/bloom_filter.py` |
| `bot_detector.py` | `sky-shield/core/bot_detector.py` |
| `blocker.py` | `sky-shield/network/blocker.py` |
| `sniffer.py` | `sky-shield/network/sniffer.py` |
| `app.py` | `sky-shield/dashboard/app.py` |
| `attack_sim.py` | `sky-shield/simulator/attack_sim.py` |

---

## 🐛 Troubleshooting

**`ImportError: cannot import name 'DASHBOARD_HOST'`**
Add to the bottom of `config.py`:
```python
DASHBOARD_HOST = "0.0.0.0"
DASHBOARD_PORT = 5000
```

**`iptables=enabled` but not running as root**
Set `USE_IPTABLES = False` in `config.py`. Soft-blocking still works and the dashboard blocked list will populate correctly.

**Dashboard shows "0 blocked" during attacks**
Make sure you're using the patched `app.py` — the fix calls `blocker.block()` before emitting the WebSocket event so the frontend fetch doesn't race ahead of the block being registered.

**`[SKETCH ROTATE]` logs stop after first attack**
Use the patched `sniffer.py` — the rotation loop is wrapped in `try/except` so exceptions don't silently kill the detection thread.

**All bots show `action=MONITOR` despite high Hellinger distance**
Check two things: `bot_detector.py` must have divisor `5` (not `50`), and `config.py` must have `BLACKLIST_THRESHOLD = 50`.

**Bot IPs appear as `192.168..200` (double dot) in logs**
Use the patched `attack_sim.py` — `random_ip()` now strips the trailing dot from prefixes correctly.

---

## 🤝 Contributing

Pull requests welcome. Key areas for improvement:

- **False positive reduction** — the current Hellinger threshold is global; per-time-of-day adaptive thresholds would reduce false alarms during flash crowds
- **IPv6 support** — sketch hashing works with any string, but the simulator and sniffer only generate/capture IPv4
- **Persistence** — trust scores and block history reset on restart; adding Redis or SQLite backing would allow cross-session memory
- **Rate-limit detection** — slow-loris is currently caught only by `REQUEST_RATE_LIMIT`; a more sophisticated connection-state tracker would improve accuracy

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 👤 Author

**Rohit Patil**  
GitHub: [@RohitPatil2004](https://github.com/RohitPatil2004)  
Repo: [github.com/RohitPatil2004/sky-shield](https://github.com/RohitPatil2004/sky-shield)
