import hashlib
from typing import Dict, Any

# Mock lookup locations for realistic honeypot visual representation
KNOWN_LOCATIONS = [
    {"country": "United States", "code": "US", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    {"country": "Germany", "code": "DE", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"country": "China", "code": "CN", "city": "Beijing", "lat": 39.9042, "lon": 116.4074},
    {"country": "Russia", "code": "RU", "city": "Moscow", "lat": 55.7558, "lon": 37.6173},
    {"country": "France", "code": "FR", "city": "Paris", "lat": 48.8566, "lon": 2.3522},
    {"country": "Netherlands", "code": "NL", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"country": "Singapore", "code": "SG", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"country": "Brazil", "code": "BR", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333}
]

def enrich_ip(ip: str) -> Dict[str, Any]:
    """Provides geo-metadata for an IP address reliably without external API rate limits."""
    if ip.startswith("127.") or ip == "localhost" or ip.startswith("192.168.") or ip.startswith("10."):
        return {
            "country": "Local Network",
            "country_code": "LO",
            "city": "Internal LAN",
            "latitude": 48.8566,
            "longitude": 2.3522
        }

    # Deterministic hash mapping for demo/offline resilience
    hash_val = int(hashlib.md5(ip.encode("utf-8")).hexdigest(), 16)
    loc = KNOWN_LOCATIONS[hash_val % len(KNOWN_LOCATIONS)]
    return {
        "country": loc["country"],
        "country_code": loc["code"],
        "city": loc["city"],
        "latitude": loc["lat"],
        "longitude": loc["lon"]
    }
