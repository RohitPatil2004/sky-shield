"""
sky-sheild/main.py

Sky-Shield - Entry Point
========================
Wires together all components and starts the system.

Usage:
    # Full Simulation mode ( no root needed ):
    python main.py

    # Live capture mode ( root access required ):
    sudo python main.py --live --interface eth0

    # custom port for dashboard 
    python main.py --port 8080
"""

import argparse
import logging
import sys
import os
import time
import signal

# -- Logging Setup --
os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler('logs/sky-shield.log'),
        logging.StreamHandler(sys.stdout)
    ],
)
logger = logging.getLogger('SkyShield')

# -- Importing Modules --


# -- Banner --
BANNER = r"""
  ____  _          ____  _     _      _     _ 
 / ___|| | ___   _/ ___|| |__ (_) ___| | __| |
 \___ \| |/ / | | \___ \| '_ \| |/ _ \ |/ _` |
  ___) |   <| |_| |___) | | | | |  __/ | (_| |
 |____/|_|\_\\__, |____/|_| |_|_|\___|_|\__,_|

 Sketch - Based DDos Defence System
 """


def main():
    print(BANNER)
    logger.info("Starting Sky-Shield...")

if __name__ == "__main__":
    main()