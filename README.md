# 🍯 GhostHoney — Multi-Protocol Honeypot & Live Threat Map

**GhostHoney** est un honeypot réseau léger, asynchrone et modulaire développé en **Python** couplé à un tableau de bord cartographique en temps réel (**Live Threat Map**).

Il permet de simuler des services vulnérables exposés sur Internet (SSH, Telnet, HTTP Admin), de capturer les scans et tentatives d'intrusion des attaquants, et de projeter ces attaques en direct sur une carte du monde.

---

## 🗺️ Architecture Globale

```
+-------------------------------------------------------------------------+
|                              INTERNET                                   |
|             (Scanners automatisés, Bots, Attaquants)                    |
+------------------------------------+------------------------------------+
                                     | Tentatives de connexion
                                     v
+-------------------------------------------------------------------------+
|                            GHOSTHONEY CORE                              |
|                                                                         |
|  +------------------+  +-------------------+  +----------------------+  |
|  | Fake SSH (2222)  |  | Fake Telnet (2323)|  | Fake HTTP Admin(8080)|  |
|  +--------+---------+  +---------+---------+  +-----------+----------+  |
|           |                      |                        |             |
|           +----------------------+------------------------+             |
|                                  |                                      |
|                                  v                                      |
|                    +---------------------------+                        |
|                    |     Event Aggregator      |                        |
|                    | - Extraction IP / Payload |                        |
|                    | - Résolution GeoIP / ASN  |                        |
|                    +-------------+-------------+                        |
+----------------------------------|--------------------------------------+
                                   | Événements enrichis
                    +--------------+--------------+
                    |                             |
                    v                             v
       +-----------------------+     +--------------------------+
       | Base SQLite / JSON    |     | WebSocket Server         |
       | (Historique & Logs)   |     | (Diffusion en temps réel)|
       +-----------------------+     +-------------+------------+
                                                   |
                                                   v
                                     +--------------------------+
                                     | Web Threat Map           |
                                     | (Leaflet.js / Dark UI)   |
                                     +--------------------------+
```

---

## ✨ Fonctionnalités clés

- **⚡ Écouteurs Multi-Protocoles Asynchrones (`asyncio`) :**
  - **Fake SSH (Port 2222) :** Négociation de bannière SSH, capture des combinaisons identifiants / mots de passe testés (bruteforce).
  - **Fake Telnet (Port 2323) :** Capture des commandes injectées par les botnets type Mirai.
  - **Fake HTTP Admin (Port 8080) :** Fausse page d'authentification (`/admin`, `/login`, `/wp-login.php`) enregistrant les formulaires soumis et headers.

- **🌍 Géolocalisation & Enrichissement GeoIP :**
  - Résolution instantanée de l'adresse IP de l'attaquant : Pays, Ville, Coordonnées GPS (Latitude / Longitude), Fournisseur d'accès (FAI / ASN).

- **🌐 Live Threat Map (Carte interactive temps réel) :**
  - Interface web responsive et sombre.
  - Diffusion des attaques par flux **WebSockets**.
  - Marqueurs animés et arcs de trajectoire sur la carte mondiale (**Leaflet.js**).

- **📊 Statistiques & Export :**
  - Top des pays attaquants, top des mots de passe les plus ciblés, top des ports scannés.
  - Stockage structuré dans SQLite et export des journaux au format JSON.

---

## 🛠️ Stack Technique

- **Langage :** Python 3.11+ (`asyncio`)
- **Backend Web & Sockets :** FastAPI / WebSockets / Uvicorn
- **Frontend :** HTML5, CSS3 (thème Cyberpunk/Dark), JavaScript Vanilla, Leaflet.js
- **Géolocalisation :** Base GeoLite2 (MaxMind) ou API GeoIP
- **Déploiement :** Docker & Docker Compose

---

## 🚀 Démarrage Rapide

### 1. Installation
```bash
git clone https://github.com/Clickdroit/GhostHoney.git
cd GhostHoney
python -m venv venv
# Activer le venv (Windows: .\venv\Scripts\activate | Linux: source venv/bin/activate)
pip install -r requirements.txt
```

### 2. Lancement en local
```bash
python main.py
```
Ouvrez ensuite votre navigateur sur `http://localhost:8000` pour observer la carte des menaces en direct.

---

## 📄 Licence
Ce projet est sous licence MIT - voir le fichier [LICENSE](LICENSE) pour plus d'informations.
