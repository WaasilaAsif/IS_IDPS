
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import os
import time
import subprocess
from datetime import datetime
import ast

DATA_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'captured_packets.csv')
LOG_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'alerts.log')

# Legacy attack label mapping (mostly unused - port-based classification is primary method)
# Note: These are old NSL-KDD labels; actual model trained on CICIDS2017 may output different labels
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

# Custom CSS for green/cyan cybersecurity theme
st.markdown("""
<style>
    .main {
        background: linear-gradient(135deg, #0a0e27 0%, #16213e 100%);
    }
    h1, h2, h3 {
        color: #5de8b8 !important;
        text-shadow: 0 0 8px rgba(93, 232, 184, 0.3);
    }
    .stMetric {
        background: rgba(93, 232, 184, 0.05);
        border-radius: 15px;
        padding: 20px;
        box-shadow: 0 0 15px rgba(93, 232, 184, 0.15), inset 0 0 10px rgba(93, 232, 184, 0.05);
    }
    .stMetric label {
        color: #7dd3fc !important;
    }
    .stMetric [data-testid="stMetricValue"] {
        color: #5de8b8 !important;
        text-shadow: 0 0 5px rgba(93, 232, 184, 0.3);
    }
</style>
""", unsafe_allow_html=True)

st.title(' AI-Powered IDPS for Home Networks')

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

def load_all_alerts():
    """Parse all ALERT lines in alerts.log into a DataFrame with attack type/category/timestamp/src_ip"""
    # Port-based attack type mapping for more descriptive labels
    PORT_ATTACK_MAP = {
        21: 'FTP Brute Force',
        22: 'SSH Brute Force', 
        23: 'Telnet Attack',
        25: 'SMTP Attack',
        445: 'SMB Attack',
        3306: 'MySQL Attack',
        3389: 'RDP Brute Force',
        5432: 'PostgreSQL Attack',
        6379: 'Redis Attack',
        8080: 'Web Admin Attack',
        8888: 'Web Panel Attack',
        9200: 'Elasticsearch Attack',
        27017: 'MongoDB Attack',
    }
    
    records = []
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            for line in f:
                if line.startswith('ALERT:'):
                    try:
                        # Handle both formats:
                        # "ALERT: Suspicious activity detected: {dict} | Predicted label: X"
                        # "ALERT: Suspicious activity detected (confidence: X%): {dict} | Predicted label: X"
                        if 'detected:' in line:
                            dstr = line.split('detected:')[1].split('|')[0].strip()
                        elif 'detected (' in line:
                            # Extract from after the closing parenthesis
                            dstr = line.split('): ')[1].split('|')[0].strip()
                        else:
                            continue
                        
                        d = ast.literal_eval(dstr)
                        ts = pd.to_datetime(d.get('timestamp'))
                        src_ip = d.get('src_ip', 'Unknown')
                        dst_port = int(d.get('dst_port', 0))
                        
                        # Use port to determine specific attack type
                        if dst_port in PORT_ATTACK_MAP:
                            attack_type = PORT_ATTACK_MAP[dst_port]
                        else:
                            # Fallback to label-based type
                            label = line.split('Predicted label:')[-1].strip()
                            label_int = None
                            try:
                                label_int = int(label)
                            except:
                                pass
                            attack_type = ATTACK_LABELS.get(label_int, f'Port {dst_port}')
                        
                        # Determine category
                        if dst_port in [21, 22, 3306, 3389, 5432, 27017]:
                            attack_category = 'R2L'
                        elif dst_port in [8080, 8888, 9200]:
                            attack_category = 'Web Attack'
                        elif dst_port in [23, 25, 445, 6379]:
                            attack_category = 'DoS'
                        else:
                            attack_category = 'Other'
                        
                        records.append({
                            'timestamp': ts,
                            'src_ip': src_ip,
                            'attack_type': attack_type,
                            'attack_category': attack_category
                        })
                    except Exception:
                        continue
                elif line.startswith('ALERT: Port scan detected'):
                    # Handle port scan alerts
                    try:
                        src_ip = line.split('from ')[1].split(' -')[0].strip()
                        records.append({
                            'timestamp': pd.Timestamp.now(),
                            'src_ip': src_ip,
                            'attack_type': 'Port Scan',
                            'attack_category': 'Probe'
                        })
                    except:
                        continue
    if records:
        df = pd.DataFrame(records)
        df = df.sort_values('timestamp')
        return df
    return pd.DataFrame()

def load_blocked_ips():
    """Extract blocked and unblocked IPs from alerts log"""
    blocked = []
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
    
    # Verify blocked IPs against actual firewall rules (only check firewall state, not log history)
    verified_blocked = []
    for b in blocked:
        ip = b['ip']
        # Check if firewall rule actually exists
        try:
            check_cmd = f'netsh advfirewall firewall show rule name="IDS_Block_{ip}"'
            result = subprocess.run(check_cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                verified_blocked.append(b)
            # If rule doesn't exist, skip (was unblocked or deleted)
        except:
            # If check fails, assume blocked to be safe
            verified_blocked.append(b)
    
    # Deduplicate by IP (keep last occurrence)
    seen = {}
    for b in verified_blocked:
        seen[b['ip']] = b['reason']
    
    return [{'ip': ip, 'reason': reason, 'is_blocked': True} 
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
            color_continuous_scale=[[0, '#5de8b8'], [0.5, '#7dd3fc'], [1, '#a78bfa']]
        )
        fig_bar.update_layout(
            xaxis_title='Time',
            yaxis_title='Attacks',
            showlegend=False,
            height=350,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(93,232,184,0.05)',
            font=dict(color='#5de8b8'),
            xaxis=dict(gridcolor='rgba(93,232,184,0.15)'),
            yaxis=dict(gridcolor='rgba(93,232,184,0.15)')
        )
        st.plotly_chart(fig_bar, use_container_width=True)
    
    # ============ PIE CHART: Attack Categories ============
    with chart_col2:
        st.subheader('Attack Types Distribution')
        
        attack_counts = alerts_df['attack_type'].value_counts().reset_index()
        attack_counts.columns = ['attack_type', 'count']
        
        # Color scheme for attack types - distinguishable colors
        colors = {
            'RDP Brute Force': '#ef4444',      # Red
            'MySQL Attack': '#f97316',         # Orange
            'MongoDB Attack': '#eab308',       # Yellow
            'PostgreSQL Attack': '#84cc16',    # Lime
            'Web Admin Attack': '#22c55e',     # Green
            'Web Panel Attack': '#10b981',     # Emerald
            'Port Scan': '#14b8a6',            # Teal
            'SSH Brute Force': '#06b6d4',      # Cyan
            'FTP Brute Force': '#0ea5e9',      # Sky
            'Telnet Attack': '#3b82f6',        # Blue
            'SMTP Attack': '#6366f1',          # Indigo
            'SMB Attack': '#8b5cf6',           # Violet
            'Redis Attack': '#a855f7',         # Purple
            'Elasticsearch Attack': '#ec4899', # Pink
        }
        
        fig_pie = px.pie(
            attack_counts,
            values='count',
            names='attack_type',
            color='attack_type',
            color_discrete_map=colors,
            hole=0.4  # Donut chart
        )
        fig_pie.update_traces(textposition='inside', textinfo='percent+label', textfont=dict(color='white', size=11))
        fig_pie.update_layout(
            height=350,
            showlegend=True,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#5de8b8'),
            legend=dict(
                bgcolor='rgba(93,232,184,0.05)',
                bordercolor='rgba(0,0,0,0)',
                borderwidth=0
            )
        )
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
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(93,232,184,0.05)',
        font=dict(color='#5de8b8'),
        xaxis=dict(gridcolor='rgba(93,232,184,0.15)'),
        yaxis=dict(gridcolor='rgba(93,232,184,0.15)'),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1,
            bgcolor='rgba(93,232,184,0.05)',
            bordercolor='rgba(0,0,0,0)',
            borderwidth=0
        )
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
st.header('IP Block Management')
all_ips = load_blocked_ips()
blocked_ips = [ip for ip in all_ips if ip['is_blocked']]
unblocked_ips = [ip for ip in all_ips if not ip['is_blocked']]

if blocked_ips:
    st.write(f"**Currently blocked: {len(blocked_ips)} IPs | Previously unblocked: {len(unblocked_ips)} IPs**")
    
    for block in blocked_ips:
        with st.expander(f" {block['ip']} - BLOCKED"):
            st.write(f"**Reason:** {block['reason']}")
            if st.button(f"Unblock {block['ip']}", key=f"unblock_{block['ip']}"):
                success, message = unblock_ip(block['ip'])
                if success:
                    st.success(f"{block['ip']} has been unblocked")
                    st.rerun()
                else:
                    st.error(f" Failed to unblock: {message}")
    
    if unblocked_ips:
        st.write("---")
        st.subheader(" Previously Unblocked IPs")
        for block in unblocked_ips:
            with st.expander(f"{block['ip']} - UNBLOCKED"):
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
            import re
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
st.caption('AI-Powered IDPS | Real-Time Security Monitoring Dashboard') 