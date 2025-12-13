import streamlit as st
import pandas as pd
import os
import time
import subprocess
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

def load_blocked_ips():
    """Extract blocked and unblocked IPs from alerts log"""
    blocked = []
    unblocked = set()
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH, 'r') as f:
            for line in f:
                if 'AUTO-BLOCKED' in line:
                    try:
                        # Extract IP from "AUTO-BLOCKED: 185.220.101.1 - Reason: ..."
                        parts = line.split('AUTO-BLOCKED:')[1].split(' - Reason:')
                        ip = parts[0].strip()
                        reason = parts[1].strip() if len(parts) > 1 else 'Unknown'
                        blocked.append({'ip': ip, 'reason': reason})
                    except:
                        pass
                elif 'UNBLOCKED' in line:
                    try:
                        # Extract IP from "UNBLOCKED: 185.220.101.1"
                        ip = line.split('UNBLOCKED:')[1].strip().split()[0]
                        unblocked.add(ip)
                    except:
                        pass
    # Deduplicate by IP (keep last occurrence) and mark unblock status
    seen = {}
    for b in blocked:
        seen[b['ip']] = b['reason']
    
    return [{'ip': ip, 'reason': reason, 'is_blocked': ip not in unblocked} 
            for ip, reason in seen.items()]

def unblock_ip(ip):
    """Unblock an IP by removing firewall rule and logging"""
    try:
        cmd = f'netsh advfirewall firewall delete rule name="IDS_Block_{ip}"'
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        # Check if rule was deleted or already doesn't exist
        if result.returncode == 0 or "No rules match" in result.stdout or "No rules match" in result.stderr:
            # Log as unblocked (even if already unblocked)
            with open(LOG_PATH, 'a') as f:
                f.write(f"UNBLOCKED: {ip} - Manually unblocked from dashboard at {datetime.now().isoformat()}\n")
            return True, "Successfully unblocked (rule removed or already removed)"
        else:
            return False, result.stderr or "Unknown error"
    except Exception as e:
        return False, str(e)


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

# Blocked IPs section
st.header('🚫 IP Block Management')
all_ips = load_blocked_ips()
blocked_ips = [ip for ip in all_ips if ip['is_blocked']]
unblocked_ips = [ip for ip in all_ips if not ip['is_blocked']]

if blocked_ips:
    st.write(f"**Currently blocked: {len(blocked_ips)} IPs | Previously unblocked: {len(unblocked_ips)} IPs**")
    
    for block in blocked_ips:
        with st.expander(f"🔴 {block['ip']} - BLOCKED"):
            st.write(f"**Reason:** {block['reason']}")
            if st.button(f"Unblock {block['ip']}", key=f"unblock_{block['ip']}"):
                success, message = unblock_ip(block['ip'])
                if success:
                    st.success(f"✅ {block['ip']} has been unblocked")
                    st.rerun()
                else:
                    st.error(f"❌ Failed to unblock: {message}")
    
    if unblocked_ips:
        st.write("---")
        st.subheader("📜 Previously Unblocked IPs")
        for block in unblocked_ips:
            with st.expander(f"⚪ {block['ip']} - UNBLOCKED"):
                st.write(f"**Original block reason:** {block['reason']}")
                st.info("This IP was previously blocked but has been manually unblocked")
else:
    if unblocked_ips:
        st.info(f'No IPs currently blocked. {len(unblocked_ips)} previously blocked IPs have been unblocked.')
    else:
        st.success('No IPs have been blocked yet.')


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