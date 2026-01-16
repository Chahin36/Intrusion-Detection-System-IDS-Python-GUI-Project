import time
import threading
import random
import pandas as pd
from datetime import datetime, timedelta

class IDSCore:
    def __init__(self):
        self.monitoring = False

        # Mémoire interne
        self.traffic_logs = []     # Liste de dictionnaires
        self.alerts = []           # Liste de dictionnaires

        # Pour détection brute-force
        self.recent_connections = []

        # Ports critiques surveillés
        self.sensitive_ports = [22, 23, 3389]  # SSH / Telnet / RDP

    # ---------------------------------------------------------
    #              MONITORING PRINCIPAL
    # ---------------------------------------------------------
    def start_monitoring(self):
        self.monitoring = True

        while self.monitoring:
            self.generate_fake_traffic()
            self.detect_bruteforce()
            time.sleep(0.25)

    def stop_monitoring(self):
        self.monitoring = False

    # ---------------------------------------------------------
    #              SIMULATION TRAFIC
    # ---------------------------------------------------------
    def generate_fake_traffic(self):
        ip = f"10.109.146.{random.randint(1, 255)}"
        port = random.choice([22, 23, 80, 443, 3389, random.randint(1024, 6000)])

        log = {
            "timestamp": datetime.now(),
            "event": f"{ip} attempted connection on port {port}",
            "ip": ip,
            "port": port
        }

        self.traffic_logs.append(log)
        self.recent_connections.append(log)

        # On garde seulement 5 secondes d'historique
        self.recent_connections = [
            c for c in self.recent_connections
            if datetime.now() - c["timestamp"] < timedelta(seconds=5)
        ]

    # ---------------------------------------------------------
    #              DÉTECTION BRUTE FORCE
    # ---------------------------------------------------------
    def detect_bruteforce(self):
        if not self.recent_connections:
            return

        df = pd.DataFrame(self.recent_connections)

        for port in self.sensitive_ports:
            subset = df[df["port"] == port]

            if len(subset) >= 5:  # 5 tentatives en <5 secondes
                ip = subset.iloc[-1]["ip"]
                msg = f"Brute Force Attack detected from {ip} on port {port}"
                self.register_alert(msg)

                # Évite le spam
                self.recent_connections = []

    # ---------------------------------------------------------
    #              ALERTES
    # ---------------------------------------------------------
    def register_alert(self, message):
        alert = {
            "timestamp": datetime.now(),
            "message": message
        }
        self.alerts.append(alert)
        print("🔔 ALERT:", message)

    def get_recent_alerts(self, limit=50):
        if not self.alerts:
            return pd.DataFrame(columns=["timestamp", "message"])
        df = pd.DataFrame(self.alerts)
        return df.sort_values(by="timestamp", ascending=False).head(limit)

    # ---------------------------------------------------------
    #              TRAFIC
    # ---------------------------------------------------------
    def get_recent_traffic_logs(self, limit=100):
        if not self.traffic_logs:
            return pd.DataFrame(columns=["timestamp", "event"])
        df = pd.DataFrame(self.traffic_logs)
        return df.sort_values(by="timestamp", ascending=False).head(limit)

    # ---------------------------------------------------------
    #              STATISTIQUES
    # ---------------------------------------------------------
    def get_statistics(self):
        alerts_df = self.get_recent_alerts()

        stats = {
            "total_alerts": len(alerts_df),
            "recent_packets": len(self.traffic_logs)
        }

        if not alerts_df.empty:
            stats["alerts_by_type"] = alerts_df["message"].value_counts().to_dict()

        return stats

    # ---------------------------------------------------------
    def clear_old_logs(self):
        limit = datetime.now() - timedelta(days=7)
        self.alerts = [a for a in self.alerts if a["timestamp"] > limit]
        self.traffic_logs = [l for l in self.traffic_logs if l["timestamp"] > limit]
