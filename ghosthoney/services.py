import asyncio
import logging
from typing import Callable, Optional
from .geoip import enrich_ip

logger = logging.getLogger("GhostHoney.Services")

class ProtocolListener:
    def __init__(self, host: str, port: int, protocol_name: str, on_attack: Callable):
        self.host = host
        self.port = port
        self.protocol_name = protocol_name
        self.on_attack = on_attack
        self.server: Optional[asyncio.Server] = None

    async def start(self):
        try:
            self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
            logger.info(f"[*] {self.protocol_name} Honeypot listening on {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"[!] Failed to bind {self.protocol_name} on {self.host}:{self.port}: {e}")

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info(f"[-] {self.protocol_name} listener stopped.")

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        raise NotImplementedError


class SSHHoneypot(ProtocolListener):
    def __init__(self, host: str = "0.0.0.0", port: int = 2222, on_attack: Callable = None):
        super().__init__(host, port, "SSH", on_attack)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "0.0.0.0"
        src_port = peer[1] if peer else 0
        geo = enrich_ip(ip)

        try:
            # Send OpenSSH banner
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            await writer.drain()

            # Read client banner or payload (up to 512 bytes)
            raw_data = await asyncio.wait_for(reader.read(512), timeout=5.0)
            payload_str = raw_data.decode("utf-8", errors="replace").strip()

            attack_event = {
                "protocol": "SSH",
                "source_ip": ip,
                "source_port": src_port,
                "payload": payload_str[:255],
                "username": "root" if "root" in payload_str else "admin",
                "password": "[SSH-Handshake]",
                **geo
            }

            if self.on_attack:
                await self.on_attack(attack_event)

        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        except Exception as e:
            logger.debug(f"SSH handler error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class TelnetHoneypot(ProtocolListener):
    def __init__(self, host: str = "0.0.0.0", port: int = 2323, on_attack: Callable = None):
        super().__init__(host, port, "Telnet", on_attack)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "0.0.0.0"
        src_port = peer[1] if peer else 0
        geo = enrich_ip(ip)

        try:
            writer.write(b"\r\nDebian GNU/Linux 11 (bullseye)\r\nlogin: ")
            await writer.drain()

            raw_login = await asyncio.wait_for(reader.readline(), timeout=8.0)
            username = raw_login.decode("utf-8", errors="replace").strip()

            writer.write(b"Password: ")
            await writer.drain()

            raw_pass = await asyncio.wait_for(reader.readline(), timeout=8.0)
            password = raw_pass.decode("utf-8", errors="replace").strip()

            writer.write(b"\r\nLogin incorrect\r\n\r\nlogin: ")
            await writer.drain()

            attack_event = {
                "protocol": "TELNET",
                "source_ip": ip,
                "source_port": src_port,
                "username": username,
                "password": password,
                "payload": f"LOGIN:{username}:{password}",
                **geo
            }

            if self.on_attack:
                await self.on_attack(attack_event)

        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        except Exception as e:
            logger.debug(f"Telnet handler error: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
