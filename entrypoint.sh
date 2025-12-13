#!/bin/bash
set -e

# Start packet sniffer in background
python src/sniffer.py &

# Start real-time detection in background
python src/realtime_detect.py &

# Start Streamlit dashboard (foreground)
exec streamlit run dashboard/app.py 