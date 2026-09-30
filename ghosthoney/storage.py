import sqlite3
import datetime
from typing import List, Dict, Any, Optional

class HoneypotStorage:
    def __init__(self, db_path: str = "attacks.db"):
        self.db_path = db_path
        self._shared_conn = None
        if db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:")
            self._shared_conn.row_factory = sqlite3.Row
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def close(self):
        if self._shared_conn:
            self._shared_conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER NOT NULL,
                    country TEXT DEFAULT 'Unknown',
                    country_code TEXT DEFAULT 'XX',
                    city TEXT DEFAULT 'Unknown',
                    latitude REAL DEFAULT 0.0,
                    longitude REAL DEFAULT 0.0,
                    username TEXT,
                    password TEXT,
                    payload TEXT,
                    headers TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_protocol ON attacks(protocol)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(source_ip)")
            conn.commit()

    def record_attack(self, data: Dict[str, Any]) -> int:
        now = datetime.datetime.utcnow().isoformat() + "Z"
        with self._get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO attacks (
                    timestamp, protocol, source_ip, source_port,
                    country, country_code, city, latitude, longitude,
                    username, password, payload, headers
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.get("timestamp", now),
                data.get("protocol", "UNKNOWN"),
                data.get("source_ip", "127.0.0.1"),
                data.get("source_port", 0),
                data.get("country", "Unknown"),
                data.get("country_code", "XX"),
                data.get("city", "Unknown"),
                data.get("latitude", 0.0),
                data.get("longitude", 0.0),
                data.get("username"),
                data.get("password"),
                data.get("payload", ""),
                data.get("headers", "")
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_attacks(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM attacks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    def get_overview_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
            unique_ips = conn.execute("SELECT COUNT(DISTINCT source_ip) FROM attacks").fetchone()[0]
            protocols = conn.execute(
                "SELECT protocol, COUNT(*) as count FROM attacks GROUP BY protocol ORDER BY count DESC"
            ).fetchall()
            top_countries = conn.execute(
                "SELECT country, country_code, COUNT(*) as count FROM attacks GROUP BY country ORDER BY count DESC LIMIT 5"
            ).fetchall()
            top_credentials = conn.execute(
                "SELECT username, password, COUNT(*) as count FROM attacks WHERE username IS NOT NULL GROUP BY username, password ORDER BY count DESC LIMIT 5"
            ).fetchall()

            return {
                "total_attacks": total,
                "unique_ips": unique_ips,
                "protocols": [dict(p) for p in protocols],
                "top_countries": [dict(c) for c in top_countries],
                "top_credentials": [dict(c) for c in top_credentials]
            }
