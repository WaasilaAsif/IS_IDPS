import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time
import subprocess
from datetime import datetime

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

# Attack label mapping (from NSL-KDD label encoder)
ATTACK_LABELS = {
    0: 'Normal',
    1: 'DoS - Back',
    2: 'DoS - Land',
    3: 'DoS - Neptune',
    4: 'DoS - Pod',
    5: 'DoS - Smurf',
    6: 'DoS - Teardrop',
    7: 'Probe - IPSweep',
    8: 'Probe - NMap',
    9: 'Probe - PortSweep',
    10: 'Probe - Satan',
    11: 'R2L - FTP Write',
    12: 'R2L - Guess Passwd',
    13: 'R2L - IMAP',
    14: 'R2L - Multihop',
    15: 'R2L - PHF',
    16: 'R2L - Spy',
    17: 'R2L - Warezclient',
    18: 'R2L - Warezmaster',
    19: 'U2R - Buffer Overflow',
    20: 'U2R - Loadmodule',
    21: 'U2R - Perl',
    22: 'U2R - Rootkit',
}

# Attack category mapping
ATTACK_CATEGORIES = {
    'Normal': 'Normal',
    'DoS - Back': 'DoS', 'DoS - Land': 'DoS', 'DoS - Neptune': 'DoS',
    'DoS - Pod': 'DoS', 'DoS - Smurf': 'DoS', 'DoS - Teardrop': 'DoS',
    'Probe - IPSweep': 'Probe', 'Probe - NMap': 'Probe',
    'Probe - PortSweep': 'Probe', 'Probe - Satan': 'Probe',
    'R2L - FTP Write': 'R2L', 'R2L - Guess Passwd': 'R2L', 'R2L - IMAP': 'R2L',
    'R2L - Multihop': 'R2L', 'R2L - PHF': 'R2L', 'R2L - Spy': 'R2L',
    'R2L - Warezclient': 'R2L', 'R2L - Warezmaster': 'R2L',
    'U2R - Buffer Overflow': 'U2R', 'U2R - Loadmodule': 'U2R',
    'U2R - Perl': 'U2R', 'U2R - Rootkit': 'U2R',
}

st.set_page_config(page_title='AI-Powered IDS Dashboard', layout='wide')
st.title('AI-Powered IDS for Home Networks')

# Load functions
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
alerts = load_alerts()
alerts_df = load_all_alerts()

# ================== METRICS ROW ==================
st.markdown("---")
col_m1, col_m2, col_m3, col_m4 = st.columns(4)

with col_m1:
    st.metric("Total Packets", f"{len(packets):,}")

with col_m2:
    st.metric("Total Alerts", f"{len(alerts_df):,}")

with col_m3:
    if not alerts_df.empty:
        unique_attackers = alerts_df['src_ip'].nunique()
        st.metric("Unique Source IPs", f"{unique_attackers:,}")
    else:
        st.metric("Unique Source IPs", "0")

with col_m4:
    if not alerts_df.empty:
        attack_types = alerts_df['attack_category'].nunique()
        st.metric("Attack Categories", f"{attack_types}")
    else:
        st.metric("Attack Categories", "0")

st.markdown("---")

# ================== ANALYTICS CHARTS ==================
if not alerts_df.empty:
    st.header('Security Analytics')
    
    chart_col1, chart_col2 = st.columns(2)
    
    # ============ BAR CHART: Attacks Per Minute ============
    with chart_col1:
        st.subheader('Attacks Per Minute')
        
        # Group by minute
        alerts_df['minute'] = alerts_df['timestamp'].dt.floor('min')
        attacks_per_minute = alerts_df.groupby('minute').size().reset_index(name='count')
        attacks_per_minute = attacks_per_minute.tail(30)  # Last 30 minutes
        
        fig_bar = px.bar(
            attacks_per_minute,
            x='minute',
            y='count',
            labels={'minute': 'Time', 'count': 'Number of Attacks'},
            color='count',
            color_continuous_scale='Reds'
        )
        fig_bar.update_layout(
            xaxis_title='Time',
            yaxis_title='Attacks',
            showlegend=False,
            height=350
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # ============ PIE CHART: Attack Categories ============
    with chart_col2:
        st.subheader('Attack Categories Distribution')
        
        category_counts = alerts_df['attack_category'].value_counts().reset_index()
        category_counts.columns = ['category', 'count']
        
        # Color scheme for categories
        colors = {
            'Normal': '#2ecc71',
            'DoS': '#e74c3c',
            'Probe': '#f39c12',
            'R2L': '#9b59b6',
            'U2R': '#3498db',
            'Unknown': '#95a5a6'
        }
        
        fig_pie = px.pie(
            category_counts,
            values='count',
            names='category',
            color='category',
            color_discrete_map=colors,
            hole=0.4  # Donut chart
        )
        fig_pie.update_traces(textposition='inside', textinfo='percent+label')
        fig_pie.update_layout(height=350, showlegend=True)
        st.plotly_chart(fig_pie, use_container_width=True)
    
    # ============ LINE CHART: Alerts Over Time ============
    st.subheader('Alerts Over Time')
    
    # Allow user to select time granularity
    time_options = st.radio(
        "Time Granularity:",
        ['Per Minute', 'Per 5 Minutes', 'Per Hour'],
        horizontal=True
    )
    
    if time_options == 'Per Minute':
        alerts_df['time_bucket'] = alerts_df['timestamp'].dt.floor('min')
    elif time_options == 'Per 5 Minutes':
        alerts_df['time_bucket'] = alerts_df['timestamp'].dt.floor('5min')
    else:
        alerts_df['time_bucket'] = alerts_df['timestamp'].dt.floor('h')
    
    # Group by time bucket and attack category
    time_series = alerts_df.groupby(['time_bucket', 'attack_category']).size().reset_index(name='count')
    
    fig_line = px.line(
        time_series,
        x='time_bucket',
        y='count',
        color='attack_category',
        labels={'time_bucket': 'Time', 'count': 'Number of Alerts', 'attack_category': 'Category'},
        color_discrete_map=colors,
        markers=True
    )
    fig_line.update_layout(
        xaxis_title='Time',
        yaxis_title='Alert Count',
        height=400,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
    )
    st.plotly_chart(fig_line, use_container_width=True)
    
    st.markdown("---")

# ================== LIVE TRAFFIC & ALERTS ==================
col1, col2 = st.columns(2)

with col1:
    st.header('Live Traffic')
    st.write(f"Total packets captured: **{len(packets):,}**")
    if not packets.empty:
        st.dataframe(packets.tail(20), use_container_width=True)
        st.line_chart(packets['packet_length'].tail(100))

with col2:
    st.header('Recent Alerts')
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

# ================== SIDEBAR: Quick Stats ==================
if not alerts_df.empty:
    st.sidebar.markdown("---")
    st.sidebar.header('Quick Stats')
    
    # Most common attack
    most_common = alerts_df['attack_type'].mode()
    if len(most_common) > 0:
        st.sidebar.write(f"**Most Common Attack:** {most_common[0]}")
    
    # Time range
    time_range = alerts_df['timestamp'].max() - alerts_df['timestamp'].min()
    st.sidebar.write(f"**Monitoring Duration:** {str(time_range).split('.')[0]}")
    
    # Alerts per minute average
    if time_range.total_seconds() > 0:
        alerts_per_min = len(alerts_df) / (time_range.total_seconds() / 60)
        st.sidebar.write(f"**Avg Alerts/Min:** {alerts_per_min:.1f}")

# ================== GEOIP LOOKUP ==================
try:
    import geoip2.database
    GEOIP_DB = os.path.join(os.path.dirname(__file__), '..', 'data', 'GeoLite2-City.mmdb')
    if os.path.exists(GEOIP_DB) and not packets.empty:
        st.header('GeoIP Lookup (last suspicious IP)')
        last_alert = alerts[0] if alerts else None
        if last_alert:
            match = re.search(r"src_ip': '([^']+)'", last_alert)
            if match:
                ip = match.group(1)
                reader = geoip2.database.Reader(GEOIP_DB)
                try:
                    response = reader.city(ip)
                    st.write(f"**IP:** {ip}")
                    st.write(f"**Country:** {response.country.name}")
                    st.write(f"**City:** {response.city.name}")
                except Exception as e:
                    st.write(f"GeoIP lookup failed: {e}")
                reader.close()
except ImportError:
    pass

st.markdown("---")
st.caption('AI-Powered IDS | Real-Time Security Monitoring Dashboard') 