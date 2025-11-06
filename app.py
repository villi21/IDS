#!/usr/bin/env python3
"""
app.py - Interfaz web para el Sistema de Detecció d’intents SSH.
Basat en 'main_final_integrat.py' i potenciat per Streamlit.
"""

import re
from pathlib import Path
from datetime import datetime
import uuid
import sqlite3
import json
import logging
import streamlit as st
import pandas as pd

# ======== CONFIGURACIÓ GENERAL ========
LOG_PATH = "sample.log"
THRESHOLD = 5
WINDOW_SECONDS = 60

# ======== CONFIGURACIÓ DEL LOGGER ========
# (El logger de Streamlit es gestiona de manera diferent, 
# però mantenim el logger de backend per a 'backend.log')
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
# (El teu codi original)
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
        except Exception as e:
            logger.error(f"❌ Error en crear la taula: {e}")
            try:
                st.error(f"Error en crear la taula de la BD: {e}")
            except:
                pass 

    def save_alert(self, alert: dict):
        if "level" not in alert or "message" not in alert:
            logger.warning("Intent de desar alerta amb camps 'level' o 'message' buits.")
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
# (El teu codi original)
# =========================================================

def read_log(path: str):
    p = Path(path)
    if not p.exists():
        logger.error(f"Fitxer no trobat: {path}")
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
# LÒGICA D'ANÀLISI (abans era 'main()')
# =========================================================

def run_analysis(manager):
    """
    Executa el procés d'anàlisi complet i desa les alertes.
    Retorna el recompte d'intents fallits i alertes generades.
    """
    logger.info("Iniciant anàlisi de log...")
    lines = read_log(LOG_PATH)
    if not lines:
        st.warning(f"El fitxer de log '{LOG_PATH}' està buit o no s'ha trobat.")
        return 0, 0
        
    relevant = filter_lines(lines)
    failed = detect_failed_attempts(relevant)
    alerts = detect_brute_force(failed)

    alerts_saved_count = 0
    if alerts:
        for alert in alerts:
            manager.save_alert(alert)
            alerts_saved_count += 1
    
    logger.info(f"Anàlisi completada. Intents fallits: {len(failed)}. Noves alertes: {alerts_saved_count}.")
    return len(failed), alerts_saved_count

# =========================================================
# FUNCIONS PER A LA INTERFÍCIE WEB (Streamlit)
# =========================================================

@st.cache_resource
def get_alert_manager():
    """Crea una única instància del gestor d'alertes."""
    return AlertManager()

@st.cache_data(ttl=60) # Actualitza les dades de la BD cada 60 segons
def load_all_alerts(_manager):
    """
    Carrega totes les alertes des de la BD usant Pandas per a més eficiència.
    El paràmetre '_manager' només hi és per invalidar la cache quan canvia.
    """
    try:
        conn = _manager._get_connection()[0] 
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY created_at DESC", conn)
        conn.close()
        
        if 'metadata' in df.columns:
            # Funció helper per extreure la IP
            def get_ip_from_metadata(metadata):
                if metadata:
                    try:
                        data = json.loads(metadata)
                        if isinstance(data, dict) and 'ip' in data:
                            return data.get('ip')
                    except json.JSONDecodeError:
                        return 'N/A'
                return 'N/A'
            
            df['ip_source'] = df['metadata'].apply(get_ip_from_metadata)
        else:
            df['ip_source'] = 'N/A'
            
        return df
    except Exception as e:
        st.error(f"Error en llegir la base de dades 'alerts.db': {e}")
        return pd.DataFrame(columns=['id', 'created_at', 'level', 'message', 'source', 'metadata', 'ip_source'])


# =========================================================
# INTERFÍCIE WEB (Streamlit)
# (Això reemplaça el teu 'if __name__ == "__main__":')
# =========================================================

# --- Configuració de la Pàgina ---
st.set_page_config(page_title="Dashboard IDS SSH", layout="wide", page_icon="🛡️")

# --- Títol ---
st.title("🛡️ Dashboard de Detección de Intrusos (IDS SSH)")

# Obtenim el gestor d'alertes (cachejat)
manager = get_alert_manager()

# --- Secció 1: Executar Anàlisi ---
with st.expander("Executar Anàlisi Manual", expanded=False):
    if st.button("Analitzar 'sample.log' ara"):
        with st.spinner("Processant el fitxer de log..."):
            failed_count, alerts_count = run_analysis(manager)
        
        st.success(f"Anàlisi completada! Intents fallits detectats: **{failed_count}**. Noves alertes generades: **{alerts_count}**.")
        # Forcem la recàrrega de les dades (invalidant la cache)
        st.cache_data.clear()

st.markdown("---")

# --- Secció 2: Dashboard d'Alertes ---
st.header("Alertes de Seguretat Registrades")

# Carregar dades
alerts_df = load_all_alerts(manager)

# --- ★ NOU: Barra lateral de Filtres (Sprint 3) ★ ---
st.sidebar.header("Filtres i Cerca")

# Filtre de Cerca per IP
ip_search = st.sidebar.text_input("Cercar per IP")

# Filtre de Severitat (Nivell)
all_levels = alerts_df['level'].unique()
level_filter = st.sidebar.multiselect("Filtrar per Nivell", options=all_levels, default=all_levels)

# Aplicar filtres
if not alerts_df.empty:
    if ip_search:
        alerts_df = alerts_df[alerts_df['ip_source'].str.contains(ip_search, case=False, na=False)]
    
    if level_filter:
        alerts_df = alerts_df[alerts_df['level'].isin(level_filter)]
else:
    st.info("No s'ha trobat cap alerta a la base de dades. Executa una anàlisi.")

# --- Mostrar Dashboard ---
if alerts_df.empty and (ip_search or len(level_filter) < len(all_levels)):
    st.warning("Cap alerta coincideix amb els filtres seleccionats.")
elif not alerts_df.empty:
    # --- Estadístiques Clau (ara basades en les dades filtrades) ---
    st.subheader("Estadístiques (Segons Filtres)")
    total_alerts = len(alerts_df)
    critical_alerts = alerts_df[alerts_df['level'] == 'CRITICAL'].shape[0]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total d'Alertes", total_alerts)
    col2.metric("Alertes Crítiques", critical_alerts)
    col3.metric("Alertes No Reconegudes", alerts_df[alerts_df['acknowledged'] == 0].shape[0])

    # --- Gràfic d'Alertes per IP (ara basat en les dades filtrades) ---
    st.subheader("Top IPs amb Alertes (Segons Filtres)")
    
    ip_counts = alerts_df[alerts_df['ip_source'] != 'N/A']['ip_source'].value_counts().head(10)
    
    if not ip_counts.empty:
        st.bar_chart(ip_counts)
    else:
        st.caption("No s'han trobat dades d'IP per mostrar al gràfic.")

    # --- Taula d'Alertes (ara filtrada) ---
    st.subheader("Taula Completa d'Alertes (Filtrada)")
    st.dataframe(alerts_df)
