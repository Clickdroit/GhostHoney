# 🗺️ Feuille de Route (Roadmap) — GhostHoney

Ce document décrit les étapes de développement pour construire **GhostHoney**, du prototype local jusqu'au déploiement en production sur un serveur VPS exposé.

---

## 📌 Phase 1 : Cœur du Honeypot & Écouteurs Réseau
- [ ] Mettre en place la structure du projet (`core/`, `api/`, `web/`, `data/`).
- [ ] Créer l'écouteur TCP asynchrone générique avec `asyncio.start_server`.
- [ ] Implémenter le faux serveur **SSH** (envoi de la bannière SSH-2.0-OpenSSH_8.9p1, capture login/mdp).
- [ ] Implémenter le faux serveur **Telnet** (envoi du prompt `login: `, capture des commandes brutes).
- [ ] Implémenter le faux serveur **HTTP** (endpoints pièges `/admin`, `/.env`, `/wp-login.php`).
- [ ] Écrire un système de journalisation unifié (`logger.py`) pour formater les événements en JSON.

---

## 📌 Phase 2 : Enrichissement GeoIP & Stockage
- [ ] Intégrer la bibliothèque `geoip2` avec la base locale MaxMind GeoLite2-City (ou fallback sur API `ip-api.com`).
- [ ] Extraire pour chaque IP : Pays, Code Pays, Ville, Latitude, Longitude, ASN.
- [ ] Créer le schéma de base de données SQLite :
  - Table `attacks` (`id`, `timestamp`, `ip`, `port`, `service`, `country`, `city`, `lat`, `lon`, `payload`, `username`, `password`).
- [ ] Mettre en place un repository SQLite pour insérer chaque attaque de manière asynchrone sans bloquer les sockets.

---

## 📌 Phase 3 : Serveur FastAPI & Diffusion WebSockets
- [ ] Créer l'application FastAPI pour servir le dashboard statique et les API REST.
- [ ] Créer l'endpoint WebSocket `/ws/attacks` pour broadcaster en direct chaque nouvelle attaque détectée aux clients connectés.
- [ ] Ajouter des endpoints REST analytiques :
  - `GET /api/stats/overview` (total attaques, attaques/heure).
  - `GET /api/stats/top-countries` (top 10 pays).
  - `GET /api/stats/top-credentials` (top mots de passe et usernames tentés).

---

## 📌 Phase 4 : Interface Web & Carte Interactive (Threat Map)
- [ ] Intégrer la carte **Leaflet.js** avec un fond de carte sombre (CartoDB DarkMatter).
- [ ] Développer la connexion WebSocket côté client JS avec reconnexion automatique.
- [ ] À chaque message reçu :
  - Ajouter un point clignotant sur les coordonnées de l'attaquant.
  - Tracer un arc lumineux entre l'attaquant et l'emplacement de votre serveur.
  - Ajouter l'événement dans le flux de log déroulant (Live Feed).
- [ ] Créer des compteurs dynamiques en haut de page (Total Attaques, Pays uniques, Attaques/min).

---

## 📌 Phase 5 : Sécurisation & Déploiement Docker
- [ ] Créer un `Dockerfile` optimisé (multi-stage Python slim) et un `docker-compose.yml`.
- [ ] Isoler le conteneur dans un réseau restreint (sécurité : le honeypot ne doit jamais pouvoir être pivoté pour attaquer l'extérieur).
- [ ] Rédiger le guide de déploiement sur VPS Linux (redirection de ports avec `iptables` du port 22 standard vers le port 2222 du honeypot).
