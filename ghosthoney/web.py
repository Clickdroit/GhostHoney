import asyncio
import json
from typing import Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse
from .storage import HoneypotStorage
from .geoip import enrich_ip

def create_app(storage: HoneypotStorage) -> FastAPI:
    app = FastAPI(title="GhostHoney Threat Intel", version="1.0.0")
    active_websockets: Set[WebSocket] = set()

    async def broadcast_attack(event: dict):
        dead_sockets = set()
        msg = json.dumps(event)
        for ws in active_websockets:
            try:
                await ws.send_text(msg)
            except Exception:
                dead_sockets.add(ws)
        active_websockets.difference_update(dead_sockets)

    app.state.broadcast_attack = broadcast_attack

    # Trap routes for HTTP reconnaissance
    TRAP_PATHS = ["/.env", "/admin", "/wp-login.php", "/setup.cgi", "/shell", "/actuator/env", "/api/v1/debug"]

    @app.middleware("http")
    async def trap_middleware(request: Request, call_next):
        path = request.url.path
        if any(path.startswith(trap) for trap in TRAP_PATHS):
            client_ip = request.client.host if request.client else "127.0.0.1"
            client_port = request.client.port if request.client else 0
            geo = enrich_ip(client_ip)
            event = {
                "protocol": "HTTP-TRAP",
                "source_ip": client_ip,
                "source_port": client_port,
                "username": None,
                "password": None,
                "payload": f"{request.method} {path}",
                "headers": dict(request.headers).get("user-agent", "Unknown"),
                **geo
            }
            storage.record_attack(event)
            await broadcast_attack(event)
            return JSONResponse({"status": "403 Forbidden", "message": "Access Denied"}, status_code=403)
        return await call_next(request)

    @app.get("/api/stats/overview")
    async def get_overview():
        return storage.get_overview_stats()

    @app.get("/api/attacks")
    async def get_attacks(limit: int = 50):
        return storage.get_recent_attacks(limit)

    @app.post("/api/simulate")
    async def simulate_attack(protocol: str = "SSH", source_ip: str = "185.220.101.5", username: str = "root", password: str = "admin123"):
        """Endpoint to simulate incoming attack for testing and live dashboard demo."""
        geo = enrich_ip(source_ip)
        event = {
            "protocol": protocol,
            "source_ip": source_ip,
            "source_port": 54321,
            "username": username,
            "password": password,
            "payload": f"Simulated {protocol} brute-force attempt",
            **geo
        }
        storage.record_attack(event)
        await broadcast_attack(event)
        return {"status": "success", "event": event}

    @app.websocket("/ws/live")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        active_websockets.add(websocket)
        try:
            while True:
                # Keep alive
                await websocket.receive_text()
        except WebSocketDisconnect:
            active_websockets.discard(websocket)

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    async def get_dashboard():
        return HTMLResponse(content=DASHBOARD_HTML)

    return app

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GhostHoney ?" Live Cyber Threat Map & SOC</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        :root {
            --bg-dark: #0a0e17;
            --card-bg: #131b2e;
            --border: #1e293b;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
            --accent-cyan: #00f2fe;
            --accent-red: #ff3366;
            --accent-green: #00ff88;
            --accent-amber: #ffaa00;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }
        body { background-color: var(--bg-dark); color: var(--text-main); display: flex; flex-direction: column; height: 100vh; overflow: hidden; }
        header { background: rgba(19, 27, 46, 0.85); backdrop-filter: blur(10px); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.3rem; font-weight: 700; color: var(--accent-cyan); display: flex; align-items: center; gap: 8px; letter-spacing: 1px; }
        .status-badge { display: flex; align-items: center; gap: 6px; font-size: 0.85rem; color: var(--accent-green); background: rgba(0, 255, 136, 0.1); border: 1px solid rgba(0, 255, 136, 0.3); padding: 4px 12px; border-radius: 999px; }
        .pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--accent-green); box-shadow: 0 0 8px var(--accent-green); animation: pulse 1.5s infinite; }
        @keyframes pulse { 0% { opacity: 0.4; } 50% { opacity: 1; } 100% { opacity: 0.4; } }
        
        .main-layout { display: grid; grid-template-columns: 1fr 380px; flex: 1; height: calc(100vh - 65px); }
        .map-section { position: relative; height: 100%; display: flex; flex-direction: column; }
        #map { flex: 1; width: 100%; background: #050811; }
        
        .stats-bar { position: absolute; top: 16px; left: 16px; right: 16px; z-index: 1000; display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; pointer-events: none; }
        .stat-card { background: rgba(19, 27, 46, 0.88); backdrop-filter: blur(8px); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; pointer-events: auto; }
        .stat-val { font-size: 1.4rem; font-weight: 700; color: #fff; margin-top: 4px; }
        .stat-label { font-size: 0.75rem; text-transform: uppercase; color: var(--text-dim); letter-spacing: 0.5px; }

        .feed-section { background: var(--card-bg); border-left: 1px solid var(--border); display: flex; flex-direction: column; }
        .feed-header { padding: 14px 16px; border-bottom: 1px solid var(--border); font-size: 0.95rem; font-weight: 600; display: flex; justify-content: space-between; align-items: center; }
        .feed-list { flex: 1; overflow-y: auto; padding: 8px 12px; display: flex; flex-direction: column; gap: 8px; }
        .feed-item { background: rgba(10, 14, 23, 0.6); border: 1px solid rgba(255, 255, 255, 0.05); border-left: 4px solid var(--accent-red); border-radius: 6px; padding: 10px; font-size: 0.82rem; transition: transform 0.2s; }
        .feed-item:hover { transform: translateX(-2px); border-color: rgba(255, 255, 255, 0.15); }
        .feed-meta { display: flex; justify-content: space-between; margin-bottom: 4px; color: var(--text-dim); font-size: 0.75rem; }
        .feed-proto { font-weight: 700; color: var(--accent-cyan); }
        .feed-ip { font-family: monospace; font-weight: 600; color: #fff; }
        .feed-payload { color: #cbd5e1; word-break: break-all; margin-top: 4px; font-family: monospace; font-size: 0.75rem; background: #0004; padding: 4px; border-radius: 4px; }
        
        .sim-btn { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; }
        .sim-btn:hover { background: #334155; color: #fff; }
    </style>
</head>
<body>
    <header>
        <div class="logo">
            <span>dY'</span> GhostHoney SOC
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
            <button class="sim-btn" onclick="triggerSimulation()">Simulate Attack</button>
            <div class="status-badge">
                <div class="pulse"></div>
                <span>LISTENERS ACTIVE</span>
            </div>
        </div>
    </header>

    <div class="main-layout">
        <div class="map-section">
            <div class="stats-bar">
                <div class="stat-card">
                    <div class="stat-label">Total Trapped Attacks</div>
                    <div class="stat-val" id="stat-total" style="color: var(--accent-red)">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Unique Attacker IPs</div>
                    <div class="stat-val" id="stat-ips" style="color: var(--accent-cyan)">0</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Active Honey-Ports</div>
                    <div class="stat-val" style="color: var(--accent-green)">2222, 2323, 8080</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Active Sensors</div>
                    <div class="stat-val" style="color: var(--accent-amber)">SSH, Telnet, HTTP</div>
                </div>
            </div>
            <div id="map"></div>
        </div>

        <div class="feed-section">
            <div class="feed-header">
                <span>Live Intercept Feed</span>
                <span id="feed-count" style="font-size: 0.75rem; color: var(--text-dim)">0 events</span>
            </div>
            <div class="feed-list" id="feed">
                <!-- Dynamically populated -->
            </div>
        </div>
    </div>

    <script>
        const map = L.map('map', { zoomControl: false }).setView([25, 10], 2);
        L.control.zoom({ position: 'bottomright' }).addTo(map);

        L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
            attribution: '&copy; CartoDB',
            maxZoom: 19
        }).addTo(map);

        const markers = [];

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats/overview');
                const data = await res.json();
                document.getElementById('stat-total').innerText = data.total_attacks;
                document.getElementById('stat-ips').innerText = data.unique_ips;
            } catch(e) {}
        }

        async function fetchRecent() {
            try {
                const res = await fetch('/api/attacks?limit=25');
                const data = await res.json();
                data.reverse().forEach(addAttackToUI);
            } catch(e) {}
        }

        function addAttackToUI(attack) {
            const feed = document.getElementById('feed');
            const item = document.createElement('div');
            item.className = 'feed-item';
            
            const time = attack.timestamp ? new Date(attack.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString();
            item.innerHTML = `
                <div class="feed-meta">
                    <span class="feed-proto">${attack.protocol}</span>
                    <span>${time}</span>
                </div>
                <div class="feed-ip">${attack.source_ip} [${attack.city || 'Unknown'}, ${attack.country_code || 'XX'}]</div>
                ${attack.username ? `<div style="font-size: 0.75rem; color: #ffaa00;">User: <b>${attack.username}</b> / Pass: <b>${attack.password || 'none'}</b></div>` : ''}
                ${attack.payload ? `<div class="feed-payload">${attack.payload}</div>` : ''}
            `;
            feed.insertBefore(item, feed.firstChild);
            document.getElementById('feed-count').innerText = `${feed.children.length} events`;

            if (attack.latitude && attack.longitude) {
                const marker = L.circleMarker([attack.latitude, attack.longitude], {
                    radius: 7,
                    fillColor: '#ff3366',
                    color: '#ff99aa',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 0.8
                }).addTo(map);

                marker.bindPopup(`<b>${attack.protocol}</b> from ${attack.source_ip} (${attack.country})`);
                markers.push(marker);
            }
        }

        function connectWS() {
            const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            const ws = new WebSocket(`${proto}//${window.location.host}/ws/live`);
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                addAttackToUI(data);
                fetchStats();
            };
            ws.onclose = () => {
                setTimeout(connectWS, 3000);
            };
        }

        async function triggerSimulation() {
            const ips = ["194.26.29.112", "45.154.255.88", "185.196.11.23", "91.240.118.244"];
            const protos = ["SSH", "TELNET", "HTTP-TRAP"];
            const users = ["root", "admin", "support", "ubuntu"];
            const passes = ["123456", "admin", "toor", "password"];
            
            const ip = ips[Math.floor(Math.random() * ips.length)];
            const proto = protos[Math.floor(Math.random() * protos.length)];
            const u = users[Math.floor(Math.random() * users.length)];
            const p = passes[Math.floor(Math.random() * passes.length)];

            await fetch(`/api/simulate?protocol=${proto}&source_ip=${ip}&username=${u}&password=${p}`, { method: 'POST' });
        }

        fetchStats();
        fetchRecent();
        connectWS();
    </script>
</body>
</html>
"""
