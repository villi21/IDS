#!/usr/bin/env python3
"""
app.py - Interfaz web per a l'Analista de Seguretat (IDS SSH).
Versió amb lògica de "Sessió d'Atac" (Una alerta per atac) i gràfic funcional.
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
import altair as alt

# ======== CONFIGURACIÓ GENERAL ========
LOG_PATH = "sample.log"
# Temps màxim entre intents per considerar-los de la mateixa "sessió" d'atac
ATTACK_SESSION_WINDOW_SECONDS = 60

# Llindars per a la lògica qualitativa (de més alt a més baix)
THRESHOLDS_BRUTE_FORCE = {
    "CRITICAL": 5, # 5+ intents de contrasenya
    "HIGH": 3      # 3-4 intents de contrasenya
}
THRESHOLDS_SCANNING = {
    "MEDIUM": 5,   # 5+ intents d'usuari invàlid
    "LOW": 3       # 3-4 intents d'usuari invàlid
}

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

    def clear_alerts(self):
        """Esborra totes les alertes existents de la taula."""
        conn, cursor = self._get_connection()
        try:
            with conn:
                cursor.execute("DELETE FROM alerts")
            logger.info("Base de dades d'alertes esborrada correctament abans de la nova anàlisi.")
        except Exception as e:
            logger.error(f"❌ Error en esborrar la taula d'alertes: {e}")
            st.error(f"Error en esborrar alertes antigues: {e}")

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
        if "Failed password" in line or "authentication failure" in line:
            failure_type = "password_auth" # Agrupem "Failed pass" i "auth failure"
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

def parse_log_timestamp(date_str: str, base_year=None):
    if not date_str or date_str in ("N/A", "Sense data"):
        return None
    try:
        # Extraiem el mes per lògica de l'any
        month = date_str.split()[0]
        day = int(date_str.split()[1])
        
        # Suposem l'any actual. Aquest script no està pensat per a logs de l'any passat.
        # Això és un problema comú. Per a aquest projecte, utilitzarem l'any actual.
        if base_year is None:
            base_year = datetime.now().year
            
        full = f"{date_str} {base_year}"
        return datetime.strptime(full, "%b %d %H:%M:%S %Y")
    except Exception:
        return None

def run_detection_logic(failed_attempts, failure_type, thresholds_dict, message_template):
    """
    ★ NOVA LÒGICA: "SESSIONS D'ATAC" ★
    Genera UNA alerta per cada "sessió" d'atac.
    Una sessió es defineix com un grup d'intents separats per menys de ATTACK_SESSION_WINDOW_SECONDS.
    """
    ip_times = {}
    for att in failed_attempts:
        if att.get("failure_type") == failure_type:
            ip = att.get("ip", "Desconeguda")
            ts = parse_log_timestamp(att.get("data", ""))
            if ts is None:
                continue
            ip_times.setdefault(ip, []).append((ts, att))

    alerts = []
    threshold_levels_sorted = sorted(thresholds_dict.items(), key=lambda item: item[1], reverse=True)

    for ip, entries in ip_times.items():
        entries.sort(key=lambda x: x[0]) 
        
        if not entries:
            continue

        # Inicialitzem la primera sessió
        current_session = [entries[0]]
        
        for i in range(1, len(entries)):
            current_entry_ts, _ = entries[i]
            last_entry_ts, _ = current_session[-1]
            
            # Comprovem si l'intent actual pertany a la sessió
            if (current_entry_ts - last_entry_ts).total_seconds() <= ATTACK_SESSION_WINDOW_SECONDS:
                current_session.append(entries[i])
            else:
                # La sessió s'ha tancat. Processem l'anterior.
                alerts.extend(process_attack_session(current_session, thresholds_dict, threshold_levels_sorted, message_template, ip))
                # Comença una nova sessió
                current_session = [entries[i]]
        
        # Processem l'última sessió
        alerts.extend(process_attack_session(current_session, thresholds_dict, threshold_levels_sorted, message_template, ip))
                
    return alerts

def process_attack_session(session_entries, thresholds_dict, threshold_levels_sorted, message_template, ip):
    """Funció helper per generar l'alerta d'UNA sessió d'atac."""
    count = len(session_entries)
    
    # Comprovem si el recompte supera el llindar mínim
    min_threshold = min(thresholds_dict.values())
    if count < min_threshold:
        return [] # No és un atac, ignorem

    # Determinem el nivell MÉS ALT assolit
    triggered_level = None
    for level, threshold in threshold_levels_sorted:
        if count >= threshold:
            triggered_level = level
            break
            
    if triggered_level:
        first_ts, _ = session_entries[0]
        last_ts, last_att = session_entries[-1]
        
        # ★ CORRECCIÓ DEL GRÀFIC: Canviem 'sep=" "' per 'T' ★
        last_ts_iso = last_ts.isoformat() 
        first_ts_iso = first_ts.isoformat()
        
        alert = {
            "level": triggered_level,
            "message": message_template.format(level=triggered_level, count=count, ip=ip),
            "source": "SSH IDS",
            "metadata": {
                "ip": ip,
                "timestamp": last_ts_iso, # Timestamp de l'event (format ISO 8601)
                "usuari": last_att.get('usuari'),
                "primer_intent_finestra": first_ts_iso,
                "total_intents_finestra": count,
                "attack_type": last_att.get('failure_type')
            }
        }
        return [alert]
    return []


# =========================================================
# LÒGICA D'ANÀLISI (abans era 'main()')
# =========================================================

def run_analysis(manager):
    """
    Executa el procés d'anàlisi complet i desa les alertes.
    Retorna el recompte d'intents fallits i alertes generades.
    """
    logger.info("Netejant alertes antigues de la BD...")
    manager.clear_alerts()
    
    logger.info("Iniciant anàlisi de log...")
    lines = read_log(LOG_PATH)
    if not lines:
        return 0, 0
        
    relevant = filter_lines(lines)
    failed = detect_failed_attempts(relevant)
    
    # 1. Detecció de Força Bruta (Password/Auth)
    bf_message = "Atac Força Bruta ({level}): {count} intents de contrasenya des de {ip}."
    brute_force_alerts = run_detection_logic(failed, "password_auth", THRESHOLDS_BRUTE_FORCE, bf_message)

    # 2. Detecció d'Escaneig d'Usuaris
    scan_message = "Escaneig d'Usuaris ({level}): {count} intents d'usuari invàlid des de {ip}."
    scanning_alerts = run_detection_logic(failed, "invalid_user", THRESHOLDS_SCANNING, scan_message)

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
            # ★ CORRECCIÓ DEL GRÀFIC: Ara pot llegir el format ISO 8601 amb 'T' ★
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
        
        # Converteix a datetime de pandas (pd.to_datetime) per assegurar compatibilitat amb Altair
        df['event_timestamp_dt'] = pd.to_datetime(df['event_timestamp_dt'], utc=True)
        df['event_timestamp_dt'] = df['event_timestamp_dt'].fillna(pd.to_datetime(df['created_at_dt'], utc=True))

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

with st.expander("Panel de Control d'Anàlisi"):
    st.info("""
    En prémer el botó, el sistema **esborrarà les dades existents** i tornarà a analitzar el fitxer `sample.log` des de zero.
    Es detectaran atacs (Força Bruta vs. Escaneig d'Usuaris) i es desaran les noves alertes a la base de dades.
    """)
    if st.button("Executar Anàlisi"):
        with st.spinner("Processant el fitxer de log..."):
            failed_count, alerts_count = run_analysis(manager)
        
        if failed_count == 0 and alerts_count == 0:
             st.warning("El fitxer de log s'ha llegit, però estava buit o no s'han trobat línies rellevants.")
        else:
            st.success(f"Anàlisi completada! Intents fallits detectats: **{failed_count}**. Noves alertes generades: **{alerts_count}**.")
        
        st.cache_data.clear()

st.markdown("---")
st.header("📊 Tauler de Visualització")

alerts_df = load_all_alerts(manager)

st.sidebar.header("🔍 Controls de Visualització")
ip_search = st.sidebar.text_input("Cerca per IP d'Origen", help="Filtra la vista per una IP específica. Ex: 192.168.1.100")

if not alerts_df.empty:
    valid_levels = [lvl for lvl in alerts_df['level'].unique() if lvl is not None and pd.notna(lvl)]
    level_order = [lvl for lvl in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] if lvl in valid_levels]
    all_levels = level_order + [lvl for lvl in valid_levels if lvl not in level_order]

    level_filter = st.sidebar.multiselect("Filtra per Severitat", 
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
    st.info("La base de dades està buida. Executeu una anàlisi per carregar dades.")
elif filtered_df.empty:
    st.warning("Cap alerta coincideix amb els filtres de visualització seleccionats.")
else:
    st.subheader("Mètriques Clau (Segons Filtres)")
    total_alerts = len(filtered_df)
    critical_alerts = filtered_df[filtered_df['level'] == 'CRITICAL'].shape[0]
    unacknowledged = filtered_df[filtered_df['acknowledged'] == 0].shape[0]
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Alertes Visualitzades", total_alerts, help="Nombre total d'alertes que coincideixen amb els filtres.")
    col2.metric("Alertes Crítiques", critical_alerts, help="Nombre d'alertes de nivell CRITICAL en la vista actual.")
    col3.metric("Alertes Pendents", unacknowledged, help="Alertes que encara no han estat marcades com a 'reconegudes'.")
    st.markdown("---")

    col_graph1, col_graph2 = st.columns(2)
    with col_graph1:
        st.subheader("📈 Línia Temporal d'Alertes")
        st.caption("Activitat d'alertes agrupada per hora (basada en la data de l'event del log).")
        
        if 'event_timestamp_dt' in filtered_df.columns:
            time_data = filtered_df.dropna(subset=['event_timestamp_dt'])
            if not time_data.empty:
                # ★ CORRECCIÓ GRÀFIC: Agrupem per hora ('h') ★
                alerts_per_hour = time_data.set_index('event_timestamp_dt').resample('h').size()
                if alerts_per_hour.empty:
                    st.caption("No hi ha dades per mostrar al gràfic temporal.")
                else:
                    alerts_per_hour_df = alerts_per_hour.reset_index()
                    alerts_per_hour_df.columns = ['Hora', "Nombre d'alertes"]
                    
                    chart = alt.Chart(alerts_per_hour_df).mark_bar().encode(
                        x=alt.X('Hora:T', title="Data i Hora de l'Event"), 
                        y=alt.Y("Nombre d'alertes:Q", title="Nombre d'Alertes")
                    ).interactive() 
                    
                    st.altair_chart(chart, use_container_width=True)
            else:
                 st.caption("No hi ha dades temporals vàlides per mostrar.")
        else:
            st.caption("No s'han pogut extreure les dades temporals.")

    with col_graph2:
        st.subheader("💥 Top 10 IPs d'Atacants")
        st.caption("IPs que han generat més alertes en la vista actual.")
        ip_counts = filtered_df[filtered_df['ip_source'] != 'N/A']['ip_source'].value_counts().head(10)
        if not ip_counts.empty:
            st.bar_chart(ip_counts, use_container_width=True)
        else:
            st.caption("No s'han trobat dades d'IP per mostrar al gràfic.")

    st.markdown("---")

    st.subheader("🔔 Taula de Resum d'Alertes")
    st.caption("Vista ràpida de les alertes que coincideixen amb els filtres.")
    
    cols_per_resum = ['event_timestamp_dt', 'ip_source', 'level', 'message']
    if all(col in filtered_df.columns for col in cols_per_resum):
        summary_df = filtered_df[cols_per_resum]
        summary_df = summary_df.rename(columns={
            'event_timestamp_dt': "Data/Hora de l'Event",
            'ip_source': "IP d'Origen",
            'level': 'Severitat',
            'message': 'Descripció de l\'Alerta'
        })
        # Formategem la data per a més llegibilitat
        summary_df["Data/Hora de l'Event"] = summary_df["Data/Hora de l'Event"].dt.strftime('%Y-%m-%d %H:%M:%S')
        st.dataframe(summary_df.sort_values(by="Data/Hora de l'Event", ascending=False), use_container_width=True)
    else:
        st.warning("No s'ha pogut generar el resum d'alertes. Faltes columnes.")

    with st.expander("Veure Registre de Dades Complet (Totes les Columnes)"):
        st.dataframe(filtered_df, use_container_width=True)
