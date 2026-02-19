#!/bin/bash
# ─────────────────────────────────────────────────────────────
#  Sky-Shield Setup Script for Kali Linux
#  Installs all dependencies and configures the environment
# ─────────────────────────────────────────────────────────────

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ____  _          ____  _     _      _     _ "
echo " / ___|| | ___   _/ ___|| |__ (_) ___| | __| |"
echo " \___ \| |/ / | | \___ \| '_ \| |/ _ \ |/ _\` |"
echo "  ___) |   <| |_| |___) | | | | |  __/ | (_| |"
echo " |____/|_|\_\\\__,_|____/|_| |_|_|\___|_|\__,_|"
echo -e "${NC}"
echo -e "${YELLOW}  Sky-Shield Setup — Kali Linux${NC}"
echo "  ─────────────────────────────────────"

# ── Check Python ──
echo -e "\n${CYAN}[1/5] Checking Python version...${NC}"
python3 --version
if ! python3 -c "import sys; assert sys.version_info >= (3,9)" 2>/dev/null; then
    echo -e "${RED}Error: Python 3.9+ required${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python OK${NC}"

# ── System Dependencies ──
echo -e "\n${CYAN}[2/5] Installing system dependencies...${NC}"
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3-pip \
    python3-dev \
    libpcap-dev \
    iptables \
    net-tools \
    libffi-dev \
    build-essential
echo -e "${GREEN}✓ System dependencies installed${NC}"

# ── Python Dependencies ──
echo -e "\n${CYAN}[3/5] Installing Python packages...${NC}"
pip3 install --break-system-packages -r requirements.txt
echo -e "${GREEN}✓ Python packages installed${NC}"

# ── Permissions ──
echo -e "\n${CYAN}[4/5] Setting up permissions...${NC}"
mkdir -p logs
chmod +x main.py

# Allow Python to capture packets without full root (optional)
if command -v setcap &>/dev/null; then
    PYTHON_BIN=$(which python3)
    sudo setcap cap_net_raw,cap_net_admin=eip "$PYTHON_BIN" 2>/dev/null && \
        echo -e "${GREEN}✓ Packet capture capability set (cap_net_raw)${NC}" || \
        echo -e "${YELLOW}⚠ Could not set capabilities — use 'sudo python3 main.py --live' for live capture${NC}"
fi

# ── Network Interface Detection ──
echo -e "\n${CYAN}[5/5] Detecting network interface...${NC}"
IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
if [ -n "$IFACE" ]; then
    echo -e "${GREEN}✓ Default interface: ${IFACE}${NC}"
    # Update config.py with detected interface
    sed -i "s/MONITOR_INTERFACE = \"eth0\"/MONITOR_INTERFACE = \"${IFACE}\"/" config.py
    echo "  Updated config.py: MONITOR_INTERFACE = \"${IFACE}\""
else
    echo -e "${YELLOW}⚠ Could not detect interface. Edit MONITOR_INTERFACE in config.py manually${NC}"
fi

echo -e "\n${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Sky-Shield setup complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Run (simulation mode):${NC}"
echo "    python3 main.py"
echo ""
echo -e "  ${CYAN}Run (live capture — requires root):${NC}"
echo "    sudo python3 main.py --live --interface ${IFACE:-eth0}"
echo ""
echo -e "  ${CYAN}Dashboard:${NC}"
echo "    http://localhost:5000"
echo ""
