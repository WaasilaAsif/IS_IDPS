import streamlit as st
import pandas as pd
import os
import time
from datetime import datetime

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

st.set_page_config(page_title='AI-Powered IDS Dashboard', layout='wide')
st.title('AI-Powered IDS for Home Networks')

# Live traffic stats
def load_packets():
    if os.path.exists(DATA_PATH):
        return pd.read_csv(DATA_PATH)
    return pd.DataFrame()

def load_alerts():
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            lines = f.readlines()
        return lines[-20:][::-1]  # Show last 20 alerts, newest first
    return []

packets = load_packets()
col1, col2 = st.columns(2)

with col1:
    st.header('Live Traffic')
    st.write(f"Total packets captured: {len(packets)}")
    if not packets.empty:
        st.dataframe(packets.tail(20))
        st.line_chart(packets['packet_length'].tail(100))

with col2:
    st.header('Recent Alerts')
    alerts = load_alerts()
    if alerts:
        for alert in alerts:
            st.error(alert.strip())
    else:
        st.success('No suspicious activity detected.')

# Sidebar: Threat Intelligence (AbuseIPDB)
st.sidebar.header('Threat Intelligence (AbuseIPDB)')
last_abuse = None
for line in alerts:
    if line.startswith('AbuseIPDB:'):
        try:
            import ast
            abuse_data = ast.literal_eval(line[len('AbuseIPDB: '):].strip())
            last_abuse = abuse_data
            break
        except Exception:
            continue
if last_abuse:
    st.sidebar.write(f"**IP:** {last_abuse.get('ip')}")
    st.sidebar.write(f"**Abuse Score:** {last_abuse.get('abuseConfidenceScore')}")
    st.sidebar.write(f"**Country:** {last_abuse.get('countryCode')}")
    st.sidebar.write(f"**Usage:** {last_abuse.get('usageType')}")
    st.sidebar.write(f"**Domain:** {last_abuse.get('domain')}")
    st.sidebar.write(f"**Total Reports:** {last_abuse.get('totalReports')}")
    st.sidebar.write(f"**Last Reported:** {last_abuse.get('lastReportedAt')}")
    if last_abuse.get('abuseConfidenceScore', 0) >= 50:
        st.sidebar.error('This IP was auto-blocked!')
else:
    st.sidebar.info('No recent AbuseIPDB results.')

# Optionally, show GeoIP info for suspicious IPs
try:
    import geoip2.database
    GEOIP_DB = os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City.mmdb')
    if os.path.exists(GEOIP_DB) and not packets.empty:
        st.header('GeoIP Lookup (last suspicious IP)')
        last_alert = alerts[0] if alerts else None
        if last_alert:
            import re
            import ast
            match = re.search(r"src_ip': '([^']+)'", last_alert)
            if match:
                ip = match.group(1)
                reader = geoip2.database.Reader(GEOIP_DB)
                try:
                    response = reader.city(ip)
                    st.write(f"IP: {ip}")
                    st.write(f"Country: {response.country.name}")
                    st.write(f"City: {response.city.name}")
                except Exception as e:
                    st.write(f"GeoIP lookup failed: {e}")
                reader.close()
except ImportError:
    pass

st.caption('AI-Powered IDS | Streamlit Dashboard') 