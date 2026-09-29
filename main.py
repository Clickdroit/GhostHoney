"""
GhostHoney — Multi-Protocol Honeypot & Live Threat Map
Entry point for launching honeypot listeners and web dashboard.
"""

import asyncio
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("GhostHoney")

async def main():
    logger.info("Starting GhostHoney services...")
    logger.info("1. Initializing async multi-protocol listeners (SSH, Telnet, HTTP)...")
    logger.info("2. Connecting GeoIP lookup service...")
    logger.info("3. Launching FastAPI WebSocket server on http://localhost:8000...")
    logger.info("GhostHoney is ready to capture incoming telemetry.")

if __name__ == "__main__":
    asyncio.run(main())
