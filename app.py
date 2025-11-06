#!/usr/bin/env python3
"""
app.py - Interfaz web per a l'Analista de Seguretat (IDS SSH).
Inclou visualització de dades, gràfics temporals i filtres interactius.
(Versió amb lògica d'escalada d'alertes i gràfic temporal corregit)
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

# Llindars per a l'escalada d'alertes
THRESHOLDS = {
    "LOW": 3,
    "MEDIUM": 5,
    "HIGH": 7,
    "CRITICAL": 10
}
# Ordre per a la lògica de comprovació
LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

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
    failed_attempts = []
    for line in lines:
        if "Failed password" in line or "Invalid user" in line or "authentication failure" in line:
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
        # ★ CORRECCIÓ: Fem que l'any sigui 2024 (o un any fix) per consistència
        # Si no, un log de "Oct 10" s'interpretaria com "Oct 10, 2025" (any actual del servidor)
        # Anem a forçar-lo a un any comú, p.ex. 2024
        # O millor, agafem l'any actual i ja està, assumint que els logs són recents.
        # El problema és si el log és de Desembre i estem a Gener.
        # Solució simple: utilitzar l'any actual.
        full = f"{date_str} {year}"
        return datetime.strptime(full, "%b %d %H:%M:%S %Y")
    except Exception:
        return None

def detect_brute_force(failed_attempts, window_seconds=WINDOW_SECONDS):
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
        
        # ★ NOVA LÒGICA D'ESCALADA D'ALERTES ★
        # Un diccionari per rastrejar quins llindars s'han alertat JA
        # per a la finestra actual (marcat per 'left')
        alerted_at_index = {"LOW": -1, "MEDIUM": -1, "HIGH": -1, "CRITICAL": -1}
        
        left = 0
        for right in range(len(entries)):
            # Expandeix la finestra de temps
            while left <= right and (entries[right][0] - entries[left][0]).total_seconds() > window_seconds:
                left += 1
                # Quan la finestra es mou, reseteja els rastrejadors d'alertes
                alerted_at_index = {"LOW": -1, "MEDIUM": -1, "HIGH": -1, "CRITICAL": -1}

            count = right - left + 1
            
            # Comprova si s'ha superat un nou llindar
            for level in LEVEL_ORDER: # Comprova de CRITICAL cap a LOW
                threshold = THRESHOLDS[level]
                if count >= threshold and alerted_at_index[level] < left:
                    # S'ha superat un nou llindar que no s'havia alertat en aquesta finestra
                    last_ts, last_att = entries[right]
                    alerts.append({
                        "level": level,
                        "message": f"Atac esdevingut {level}: {count} intents des de {ip} en {window_seconds}s.",
                        "source": "SSH IDS",
                        "metadata": {
                            "ip": ip,
                            "timestamp": last_ts.isoformat(sep=' '), # Timestamp de l'event
                            "usuari": last_att.get('usuari'),
                            "primer_intent_finestra": entries[left][0].isoformat(sep=' '),
                            "total_intents_finestra": count
                        }
                    })
                    # Marca aquest nivell com alertat per a aquesta finestra
                    alerted_at_index[level] = left
                    # Important: No reiniciem 'left', permetem que la finestra segueixi creixent
                    # i pugui escalar a un nivell superior.
                    break # Només genera una alerta (la més alta) per a aquest intent
                
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

# ★ NOVA FUNCIÓ HELPER PER CORREGIR GRÀFIC ★
def get_timestamp_from_metadata(metadata_str):
    """Intenta extreure el timestamp de l'event des del JSON de metadata."""
    if not metadata_str:
        return None
    try:
        data = json.loads(metadata_str)
        if isinstance(data, dict) and 'timestamp' in data:
            # Converteix el timestamp ISO a objecte datetime
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

        # --- Processament de Dades ---
        df['created_at_dt'] = pd.to_datetime(df['created_at'])

        # Extreure IP de 'metadata' (JSON)
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
            # ★ CORRECCIÓ GRÀFIC: Extreu el timestamp de l'event (del log)
            df['event_timestamp_dt'] = df['metadata'].apply(get_timestamp_from_metadata)
        else:
            df['ip_source'] = 'N/A'
            df['event_timestamp_dt'] = None
        
        # Si per alguna raó falla l'extracció del metadata, fem fallback al 'created_at'
        df['event_timestamp_dt'] = df['event_timestamp_dt'].fillna(df['created_at_dt'])

        return df
    except Exception as e:
        st.error(f"Error en llegir la base de dades 'alerts.db': {e}")
        return pd.DataFrame(columns=['id', 'created_at', 'level', 'message', 'source', 'metadata', 'ip_source', 'event_timestamp_dt'])

# =========================================================
# INTERFÍCIE WEB (Streamlit)
# =========================================================

# --- Configuració de la Pàgina ---
st.set_page_config(page_title="Dashboard IDS SSH", layout="wide", page_icon="🛡️")

# --- Títol i Descripció ---
st.title("🛡️ Dashboard d'Analista de Seguretat (IDS SSH)")
st.caption("Un monitor visual per a la detecció d'intrusions i anàlisi de logs SSH.")

# Obtenim el gestor d'alertes (cachejat)
manager = get_alert_manager()

# --- Secció 1: Executar Anàlisi ---
with st.expander("Panel d'Anàlisi (Execució Manual)"):
    st.info("""
    Prement aquest botó, el sistema llegirà 'sample.log', processarà les línies, 
    detectarà atacs amb escalada de nivell (LOW, MEDIUM, HIGH, CRITICAL) i desarà les noves alertes.
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

# --- Secció 2: Dashboard d'Alertes ---
st.header("📊 Visualització de Dades")

# Carregar dades
alerts_df = load_all_alerts(manager)

# --- Barra lateral de Filtres ---
st.sidebar.header("🔍 Controls i Filtres")

# Filtre de Cerca per IP
ip_search = st.sidebar.text_input("Cercar per IP", help="Filtra per una IP específica. Ex: 192.168.1.100")

# Filtre de Severitat (Nivell)
if not alerts_df.empty:
    all_levels = sorted(alerts_df['level'].unique(), key=lambda x: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x) if x in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] else 99)
    level_filter = st.sidebar.multiselect("Filtrar per Nivell", 
                                        options=all_levels, 
                                        help="Selecciona els nivells d'alerta a mostrar.")
else:
    all_levels = []
    level_filter = []

# Aplicar filtres
if not alerts_df.empty:
    filtered_df = alerts_df.copy()
    if ip_search:
        filtered_df = filtered_df[filtered_df['ip_source'].str.contains(ip_search, case=False, na=False)]
    
    if level_filter:
        filtered_df = filtered_df[filtered_df['level'].isin(level_filter)]
else:
    filtered_df = alerts_df.copy()


# --- Mostrar Dashboard ---
if alerts_df.empty:
    st.info("No s'ha trobat cap alerta a la base de dades. Executa una anàlisi per començar.")
elif filtered_df.empty:
    st.warning("S'han trobat alertes a la BD, però cap coincideix amb els filtres seleccionats.")
else:
    # --- Estadístiques Clau (basades en les dades filtrades) ---
    st.subheader("Estadístiques Clau (Segons Filtres)")
    
    total_alerts = len(filtered_df)
    critical_alerts = filtered_df[filtered_df['level'] == 'CRITICAL'].shape[0]
    unacknowledged = filtered_df[filtered_df['acknowledged'] == 0].shape[0]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total d'Alertes", total_alerts, help="Nombre total d'alertes que coincideixen amb els filtres.")
    col2.metric("Alertes Crítiques", critical_alerts, help="Nombre d'alertes de nivell 'CRITICAL'.")
    col3.metric("Alertes No Reconegudes", unacknowledged, help="Alertes pendents de revisió.")

    st.markdown("---")

    # --- Gràfics (basats en les dades filtrades) ---
    col_graph1, col_graph2 = st.columns(2)

    with col_graph1:
        # --- Gràfic Temporal d'Alertes (Corregit) ---
        st.subheader("📈 Gràfic Temporal d'Alertes")
        st.caption("Nombre d'alertes generades per hora (basat en l'hora del log).")
        
        # ★ CORRECCIÓ GRÀFIC: Utilitza 'event_timestamp_dt'
        alerts_per_hour = filtered_df.set_index('event_timestamp_dt').resample('h').size()
        alerts_per_hour.name = "Nombre d'alertes"
        
        if alerts_per_hour.empty:
            st.caption("No hi ha dades per mostrar al gràfic temporal.")
        else:
            st.bar_chart(alerts_per_hour, use_container_width=True)

    with col_graph2:
        # --- Gràfic d'Alertes per IP ---
        st.subheader("💥 Top IPs Problemàtiques")
        st.caption("Comptador d'alertes generades per cada IP.")
        
        ip_counts = filtered_df[filtered_df['ip_source'] != 'N/A']['ip_source'].value_counts().head(10)
        
        if not ip_counts.empty:
            st.bar_chart(ip_counts, use_container_width=True)
        else:
            st.caption("No s'han trobat dades d'IP per mostrar al gràfic.")

    st.markdown("---")

    # --- ★ NOU: APARTAT DE RESUM ★ ---
    st.subheader("🔔 Resum d'Alertes")
    st.caption("Visió ràpida de les alertes filtrades.")
    
    # Seleccionem i reanomenem les columnes per al resum
    summary_df = filtered_df[['event_timestamp_dt', 'ip_source', 'level', 'message']]
    summary_df = summary_df.rename(columns={
        'event_timestamp_dt': 'Data de l\'Event',
        'ip_source': 'IP d\'Origen',
        'level': 'Severitat',
        'message': 'Motiu (Descripció)'
    })
    
    # Mostrem el resum, ordenat per data més recent
    st.dataframe(summary_df.sort_values(by="Data de l'Event", ascending=False), use_container_width=True)

    # --- Taula Completa (dins un desplegable) ---
    with st.expander("Veure Registre Detallat Complet (Totes les Columnes)"):
        st.subheader("📄 Registre Detallat d'Alertes (Filtrat)")
        st.dataframe(filtered_df, use_container_width=True)
