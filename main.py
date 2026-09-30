"""
GhostHoney ?" Multi-Protocol Honeypot & Live Threat Map
Launches honeypot decoy listeners (SSH, Telnet, HTTP) and web SOC dashboard.
"""

import asyncio
import logging
import argparse
import uvicorn

from ghosthoney.storage import HoneypotStorage
from ghosthoney.services import SSHHoneypot, TelnetHoneypot
from ghosthoney.web import create_app

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("GhostHoney")

async def run_server(args):
    storage = HoneypotStorage(db_path=args.db)
    app = create_app(storage)

    async def on_attack_captured(event: dict):
        attack_id = storage.record_attack(event)
        logger.warning(
            f"[ALERT] Trapped {event.get('protocol')} from {event.get('source_ip')}:{event.get('source_port')} "
            f"({event.get('country')}) - User: {event.get('username')}"
        )
        if hasattr(app.state, "broadcast_attack"):
            await app.state.broadcast_attack(event)

    ssh_honeypot = SSHHoneypot(host=args.host, port=args.ssh_port, on_attack=on_attack_captured)
    telnet_honeypot = TelnetHoneypot(host=args.host, port=args.telnet_port, on_attack=on_attack_captured)

    await ssh_honeypot.start()
    await telnet_honeypot.start()

    logger.info(f"GhostHoney Web Dashboard running on http://{args.host}:{args.port}")
    config = uvicorn.Config(app=app, host=args.host, port=args.port, log_level="info")
    server = uvicorn.Server(config)

    try:
        await server.serve()
    finally:
        logger.info("Shutting down GhostHoney honeypots...")
        await ssh_honeypot.stop()
        await telnet_honeypot.stop()

def main():
    parser = argparse.ArgumentParser(description="GhostHoney Multi-Protocol Honeypot & SOC Dashboard")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="Web dashboard & HTTP trap port (default: 8000)")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Fake SSH listener port (default: 2222)")
    parser.add_argument("--telnet-port", type=int, default=2323, help="Fake Telnet listener port (default: 2323)")
    parser.add_argument("--db", default="attacks.db", help="SQLite database path (default: attacks.db)")
    args = parser.parse_args()

    asyncio.run(run_server(args))

if __name__ == "__main__":
    main()
