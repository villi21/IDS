#!/usr/bin/env python3
"""
app.py - Interfaz web per a l'Analista de Seguretat (IDS SSH).
Inclou visualització de dades, gràfics temporals i filtres interactius.
(Versió amb lògica de severitat qualitativa i gràfic corregit)
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
WINDOW_SECONDS = 60

# Llindars per a la lògica qualitativa
BRUTE_FORCE_CRITICAL_THRESHOLD = 5
BRUTE_FORCE_HIGH_THRESHOLD = 3
SCANNING_MEDIUM_THRESHOLD = 5
SCANNING_LOW_THRESHOLD = 3

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
        conn = sqlite3.connect(self.db_name, check_same_thread=False)
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
        if level in ["ERROR", "CRITICAL", "HIGH"]:
            logger.error(log_message)
        elif level == "MEDIUM":
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
        logger.error(f"Fitxer no trobat: {path}")
        st.error(f"Error: El fitxer '{path}' no s'ha trobat. Assegura't que existeix al repositori.")
        return []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]

def filter_lines(lines):
    return [l for l in lines if RELEVANT_RE.search(l)]

def detect_failed_attempts(lines):
    """
    Analitza les línies de log i les classifica per tipus de fallada.
    """
    failed_attempts = []
    for line in lines:
        failure_type = None
        if "Failed password" in line:
            failure_type = "password"
        elif "authentication failure" in line:
            failure_type = "auth_failure"
        elif "Invalid user" in line:
            failure_type = "invalid_user"
        
        if failure_type:
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
                "missatge": line,
                "failure_type": failure_type
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

def run_detection_logic(failed_attempts, failure_types, thresholds, levels, message_template, window_seconds=WINDOW_SECONDS):
    """
    Funció genèrica per a la detecció basada en finestra de temps.
    """
    ip_times = {}
    for att in failed_attempts:
        if att.get("failure_type") in failure_types:
            ip = att.get("ip", "Desconeguda")
            ts = parse_log_timestamp(att.get("data", ""))
            if ts is None:
                continue
            ip_times.setdefault(ip, []).append((ts, att))

    alerts = []
    for ip, entries in ip_times.items():
        entries.sort(key=lambda x: x[0]) 
        
        alerted_at_index = {level: -1 for level in levels}
        
        left = 0
        for right in range(len(entries)):
            while left <= right and (entries[right][0] - entries[left][0]).total_seconds() > window_seconds:
                left += 1
                alerted_at_index = {level: -1 for level in levels}

            count = right - left + 1
            
            # Comprova del llindar més alt al més baix
            for level in reversed(levels): # Ex: ["HIGH", "CRITICAL"] -> comprova CRITICAL primer
                threshold = thresholds[level]
                if count >= threshold and alerted_at_index[level] < left:
                    last_ts, last_att = entries[right]
                    alerts.append({
                        "level": level,
                        "message": message_template.format(level=level, count=count, ip=ip, seconds=window_seconds),
                        "source": "SSH IDS",
                        "metadata": {
                            "ip": ip,
                            "timestamp": last_ts.isoformat(sep=' '), # Timestamp de l'event
                            "usuari": last_att.get('usuari'),
                            "primer_intent_finestra": entries[left][0].isoformat(sep=' '),
                            "total_intents_finestra": count,
                            "attack_type": failure_types[0] # Simplificació
                        }
                    })
                    alerted_at_index[level] = left
                    break # Genera només 1 alerta per intent
                
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
        return 0, 0
        
    relevant = filter_lines(lines)
    failed = detect_failed_attempts(relevant)

    # ★ LÒGICA DE DETECCIÓ QUALITATIVA ★
    
    # 1. Detecció de Força Bruta (Password/Auth)
    bf_thresholds = {"HIGH": BRUTE_FORCE_HIGH_THRESHOLD, "CRITICAL": BRUTE_FORCE_CRITICAL_THRESHOLD}
    bf_levels = ["HIGH", "CRITICAL"]
    bf_message = "Atac Força Bruta ({level}): {count} intents de contrasenya des de {ip} en {seconds}s."
    brute_force_alerts = run_detection_logic(failed, ["password", "auth_failure"], bf_thresholds, bf_levels, bf_message)

    # 2. Detecció d'Escaneig d'Usuaris
    scan_thresholds = {"LOW": SCANNING_LOW_THRESHOLD, "MEDIUM": SCANNING_MEDIUM_THRESHOLD}
    scan_levels = ["LOW", "MEDIUM"]
    scan_message = "Escaneig d'Usuaris ({level}): {count} intents d'usuari invàlid des de {ip} en {seconds}s."
    scanning_alerts = run_detection_logic(failed, ["invalid_user"], scan_thresholds, scan_levels, scan_message)

    alerts = brute_force_alerts + scanning_alerts
    
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

def get_timestamp_from_metadata(metadata_str):
    """Intenta extreure el timestamp de l'event des del JSON de metadata."""
    if not metadata_str:
        return None
    try:
        data = json.loads(metadata_str)
        if isinstance(data, dict) and 'timestamp' in data:
            return datetime.fromisoformat(data['timestamp'])
    except:
        return None
    return None

@st.cache_data(ttl=60) # Actualitza les dades de la BD cada 60 segons
def load_all_alerts(_manager):
    """
    Carrega totes les alertes des de la BD usant Pandas per a més eficiència.
    """
    try:
        conn = _manager._get_connection()[0] 
        df = pd.read_sql_query("SELECT * FROM alerts ORDER BY created_at DESC", conn)
        conn.close()
        
        if df.empty:
            return pd.DataFrame(columns=['id', 'created_at', 'level', 'message', 'source', 'metadata', 'ip_source', 'event_timestamp_dt'])

        df['created_at_dt'] = pd.to_datetime(df['created_at'])

        def get_ip_from_metadata(metadata):
            if metadata:
                try:
                    data = json.loads(metadata)
                    if isinstance(data, dict) and 'ip' in data:
                        return data.get('ip')
                except json.JSONDecodeError:
                    return 'N/A'
            return 'N/A'
        
        if 'metadata' in df.columns:
            df['ip_source'] = df['metadata'].apply(get_ip_from_metadata)
            df['event_timestamp_dt'] = df['metadata'].apply(get_timestamp_from_metadata)
        else:
            df['ip_source'] = 'N/A'
            df['event_timestamp_dt'] = None
        
        df['event_timestamp_dt'] = df['event_timestamp_dt'].fillna(df['created_at_dt'])

        return df
    except Exception as e:
        st.error(f"Error en llegir la base de dades 'alerts.db': {e}")
        return pd.DataFrame(columns=['id', 'created_at', 'level', 'message', 'source', 'metadata', 'ip_source', 'event_timestamp_dt'])

# =========================================================
# INTERFÍCIE WEB (Streamlit)
# =========================================================

st.set_page_config(page_title="Dashboard IDS SSH", layout="wide", page_icon="🛡️")

st.title("🛡️ Dashboard d'Analista de Seguretat (IDS SSH)")
st.caption("Un monitor visual per a la detecció d'intrusions i anàlisi de logs SSH.")

manager = get_alert_manager()

with st.expander("Panel d'Anàlisi (Execució Manual)"):
    st.info("""
    Prement aquest botó, el sistema llegirà 'sample.log', processarà les línies, 
    detectarà atacs (Força Bruta vs Escaneig d'Usuaris) i desarà les noves alertes.
    """)
    if st.button("Analitzar 'sample.log' ara"):
        with st.spinner("Processant el fitxer de log..."):
            failed_count, alerts_count = run_analysis(manager)
        
        if failed_count == 0 and alerts_count == 0:
             st.warning("El fitxer de log s'ha llegit, però estava buit o no s'han trobat línies rellevants.")
        else:
            st.success(f"Anàlisi completada! Intents fallits detectats: **{failed_count}**. Noves alertes generades: **{alerts_count}**.")
        
        st.cache_data.clear()

st.markdown("---")
st.header("📊 Visualització de Dades")

alerts_df = load_all_alerts(manager)

st.sidebar.header("🔍 Controls i Filtres")
ip_search = st.sidebar.text_input("Cercar per IP", help="Filtra per una IP específica. Ex: 192.168.1.100")

if not alerts_df.empty:
    all_levels = sorted(alerts_df['level'].unique(), key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x) if x in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] else 99)
    level_filter = st.sidebar.multoselect("Filtrar per Nivell", 
                                        options=all_levels, 
                                        help="Selecciona els nivells d'alerta a mostrar.")
else:
    all_levels = []
    level_filter = []

if not alerts_df.empty:
    filtered_df = alerts_df.copy()
    if ip_search:
        filtered_df = filtered_df[filtered_df['ip_source'].str.contains(ip_search, case=False, na=False)]
    if level_filter:
        filtered_df = filtered_df[filtered_df['level'].isin(level_filter)]
else:
    filtered_df = alerts_df.copy()

if alerts_df.empty:
    st.info("No s'ha trobat cap alerta a la base de dades. Executa una anàlisi per començar.")
elif filtered_df.empty:
    st.warning("S'han trobat alertes a la BD, però cap coincideix amb els filtres seleccionats.")
else:
    st.subheader("Estadístiques Clau (Segons Filtres)")
    total_alerts = len(filtered_df)
    critical_alerts = filtered_df[filtered_df['level'] == 'CRITICAL'].shape[0]
    unacknowledged = filtered_df[filtered_df['acknowledged'] == 0].shape[0]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total d'Alertes", total_alerts, help="Nombre total d'alertes que coincideixen amb els filtres.")
    col2.metric("Alertes Crítiques", critical_alerts, help="Nombre d'alertes de nivell 'CRITICAL'.")
    col3.metric("Alertes No Reconegudes", unacknowledged, help="Alertes pendents de revisió.")
    st.markdown("---")

    col_graph1, col_graph2 = st.columns(2)
    with col_graph1:
        st.subheader("📈 Gràfic Temporal d'Alertes")
        st.caption("Nombre d'alertes generades per hora (basat en l'hora del log).")
        
        # ★ CORRECCIÓ GRÀFIC (Part 2): Convertir a DF simple abans de 'barchart' ★
        if 'event_timestamp_dt' in filtered_df.columns:
            alerts_per_hour = filtered_df.set_index('event_timestamp_dt').resample('h').size()
            if alerts_per_hour.empty:
                st.caption("No hi ha dades per mostrar al gràfic temporal.")
            else:
                # Convertim l'índex de temps en una columna per a st.barchart
                alerts_per_hour_df = alerts_per_hour.reset_index()
                alerts_per_hour_df.columns = ['Hora', 'Nombre d\'alertes']
                st.bar_chart(alerts_per_hour_df, x='Hora', y='Nombre d\'alertes', use_container_width=True)
        else:
            st.caption("No s'han pogut extreure les dades temporals.")

    with col_graph2:
        st.subheader("💥 Top IPs Problemàtiques")
        st.caption("Comptador d'alertes generades per cada IP.")
        ip_counts = filtered_df[filtered_df['ip_source'] != 'N/A']['ip_source'].value_counts().head(10)
        if not ip_counts.empty:
            st.bar_chart(ip_counts, use_container_width=True)
        else:
            st.caption("No s'han trobat dades d'IP per mostrar al gràfic.")

    st.markdown("---")

    st.subheader("🔔 Resum d'Alertes")
    st.caption("Visió ràpida de les alertes filtrades.")
    
    summary_df = filtered_df[['event_timestamp_dt', 'ip_source', 'level', 'message']]
    summary_df = summary_df.rename(columns={
        'event_timestamp_dt': "Data de l'Event",
        'ip_source': "IP d'Origen",
        'level': 'Severitat',
        'message': 'Motiu (Descripció)'
    })
    st.dataframe(summary_df.sort_values(by="Data de l'Event", ascending=False), use_container_width=True)

    with st.expander("Veure Registre Detallat Complet (Totes les Columnes)"):
        st.dataframe(filtered_df, use_container_width=True)
