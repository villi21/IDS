#!/usr/bin/env python3
"""
main_final_integrat.py - Sistema complet de detecció d’intents SSH + gestió avançada d’alertes
Inclou:
- HU1–HU5: Lectura, detecció, informes i validació
- Gestió d’alertes avançada amb log + BD (AlertManager)
"""

import re
from pathlib import Path
from datetime import datetime
import uuid
import sqlite3
import json
import logging

# ======== CONFIGURACIÓ GENERAL ========
LOG_PATH = "sample.log"
THRESHOLD = 5
WINDOW_SECONDS = 60

# ======== CONFIGURACIÓ DEL LOGGER ========
logging.basicConfig(
    filename='backend.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)
logger = logging.getLogger(__name__)

# ======== EXPRESSIONS REGULARS ========
RELEVANT_RE = re.compile(r"(Failed|Accepted|Invalid|authentication failure|session opened|session closed)", re.IGNORECASE)
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")
DATE_RE = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
USER_RE = re.compile(r"for\s+(\w+)")

# =========================================================
# CLASSE DE GESTIÓ D'ALERTES AVANÇADA
# =========================================================

class AlertManager:
    """Gestor d'alertes amb emmagatzematge dual (fitxer + BD)."""
    
    def __init__(self, db_name="alerts.db"):
        self.db_name = db_name
        self.crear_taula()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_name)
        conn.row_factory = sqlite3.Row 
        return conn, conn.cursor()
    
    def crear_taula(self):
        conn, cursor = self._get_connection()
        try:
            with conn: 
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        created_at TEXT NOT NULL,
                        level TEXT NOT NULL,
                        message TEXT NOT NULL,
                        source TEXT,
                        metadata TEXT,
                        processed INTEGER NOT NULL DEFAULT 0,
                        acknowledged INTEGER NOT NULL DEFAULT 0,
                        acknowledged_by TEXT,
                        acknowledged_at TEXT,
                        last_updated TEXT NOT NULL
                    );
                """)
            print(f"Base de dades '{self.db_name}' preparada correctament.")
        except Exception as e:
            print(f"❌ Error en crear la taula: {e}")

    def save_alert(self, alert: dict):
        if "level" not in alert or "message" not in alert:
            return "Error: Falten camps obligatoris (level o message)."
        
        level = alert["level"]
        message = alert["message"]
        source = alert.get("source")
        metadata = alert.get("metadata")
        metadata_json = json.dumps(metadata) if metadata else None
        now = datetime.utcnow().isoformat()
        
        log_message = f"IDS Alert - Level: {level}, Message: '{message}', Source: {source or 'N/A'}, Metadata: {metadata_json or 'N/A'}"
        if level in ["ERROR", "CRITICAL"]:
            logger.error(log_message)
        elif level == "WARNING":
            logger.warning(log_message)
        else:
            logger.info(log_message)
        
        conn, cursor = self._get_connection()
        try:
            with conn:
                cursor.execute("""
                    INSERT INTO alerts (
                        created_at, level, message, source, metadata,
                        processed, acknowledged, last_updated
                    ) VALUES (?, ?, ?, ?, ?, 0, 0, ?)
                """, (now, level, message, source, metadata_json, now))
                alert_id = cursor.lastrowid
                return f"Alerta desada correctament amb ID {alert_id} (BD i Log)."
        except Exception as e:
            logger.critical(f"FATAL ERROR: No es pot desar l'alerta a la BD. Error: {str(e)}")
            return f"Error en desar alerta a la BD: {str(e)}"

# =========================================================
# FUNCIONS DE DETECCIÓ
# =========================================================

def read_log(path: str):
    p = Path(path)
    if not p.exists():
        print(f"Fitxer no trobat: {path}")
        return []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def filter_lines(lines):
    return [l for l in lines if RELEVANT_RE.search(l)]

def detect_failed_attempts(lines):
    failed_attempts = []
    for line in lines:
        if "Failed password" in line or "Invalid user" in line:
            ip_match = IP_RE.search(line)
            date_match = DATE_RE.search(line)
            user_match = USER_RE.search(line)
            ip = ip_match.group(1) if ip_match else "Desconeguda"
            date = date_match.group(0) if date_match else "Sense data"
            user = user_match.group(1) if user_match else "Desconegut"
            failed_attempts.append({
                "data": date,
                "usuari": user,
                "ip": ip,
                "missatge": line
            })
    return failed_attempts

def parse_log_timestamp(date_str: str):
    if not date_str or date_str in ("N/A", "Sense data"):
        return None
    try:
        year = datetime.now().year
        full = f"{date_str} {year}"
        return datetime.strptime(full, "%b %d %H:%M:%S %Y")
    except Exception:
        return None

def detect_brute_force(failed_attempts, threshold=THRESHOLD, window_seconds=WINDOW_SECONDS):
    ip_times = {}
    for att in failed_attempts:
        ip = att.get("ip", "Desconeguda")
        ts = parse_log_timestamp(att.get("data", ""))
        if ts is None:
            continue
        ip_times.setdefault(ip, []).append((ts, att))

    alerts = []
    for ip, entries in ip_times.items():
        entries.sort(key=lambda x: x[0])
        times = [t for t, _ in entries]
        left = 0
        for right in range(len(times)):
            while left <= right and (times[right] - times[left]).total_seconds() > window_seconds:
                left += 1
            count = right - left + 1
            if count >= threshold:
                last_ts, last_att = entries[right]
                alerts.append({
                    "level": "CRITICAL",
                    "message": f"{count} intents fallits des de {ip} en {window_seconds}s.",
                    "source": "SSH IDS",
                    "metadata": {
                        "ip": ip,
                        "timestamp": last_ts.isoformat(sep=' '),
                        "usuari": last_att.get('usuari')
                    }
                })
                left = right + 1
    return alerts

# =========================================================
# MAIN
# =========================================================

def main():
    print("Iniciant detecció d'intents SSH sospitosos...\n")
    manager = AlertManager()

    lines = read_log(LOG_PATH)
    relevant = filter_lines(lines)
    failed = detect_failed_attempts(relevant)
    alerts = detect_brute_force(failed)

    print(f"Total intents fallits: {len(failed)}")
    print(f"Total alertes generades: {len(alerts)}")

    for alert in alerts:
        resultat = manager.save_alert(alert)
        print(resultat)

    print("\nProcés completat. Consulta 'backend.log' i 'alerts.db' per a més detalls.")

if __name__ == "__main__":
    main()
