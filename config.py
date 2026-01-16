# config.py
import os

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
ALERTS_LOG = os.path.join(LOGS_DIR, "alerts.log")
TRAFFIC_LOG = os.path.join(LOGS_DIR, "traffic.log")

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 5  # Max failed attempts per minute
PORT_SCAN_THRESHOLD = 10   # Max port scan attempts per minute
SYN_FLOOD_THRESHOLD = 100  # Max SYN packets per second

# Network interface to monitor (use your actual interface)
NETWORK_INTERFACE = "Wi-Fi"  # Change to "eth0" on Linux or appropriate name

# GUI settings
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
USER_USERNAME = "user"
USER_PASSWORD = "user123"

# Ensure logs directory exists
os.makedirs(LOGS_DIR, exist_ok=True)