# ids_core.py
import threading
import time
from packet_analyzer import PacketAnalyzer
from detection_rules import DetectionRules
from logging_system import LoggingSystem
from config import NETWORK_INTERFACE

class IDSCore:
    def __init__(self):
        # initialise le packet analyzer mais sans démarrer le sniffing
        self.packet_analyzer = PacketAnalyzer(NETWORK_INTERFACE)
        self.detection_rules = DetectionRules()
        self.logging_system = LoggingSystem()

        self.is_monitoring = False
        self.monitor_thread = None
        self.alerts_history = []

    def start_monitoring(self, packet_count=0):
        """Start monitoring network traffic. This will start sniffing
        and pass each parsed packet to self.process_packet via callback."""
        if self.is_monitoring:
            print("[*] Monitoring already running")
            return

        self.is_monitoring = True
        print("[*] Starting IDS monitoring...")

        # start sniffing in the current thread (GUI spawns this in a background thread)
        try:
            # pass self.process_packet as callback so each packet_info is processed
            self.packet_analyzer.start_sniffing(count=packet_count, callback=self.process_packet)
        except Exception as e:
            print(f"[!] Error while starting sniffing: {e}")
            self.is_monitoring = False

    def stop_monitoring(self):
        """Stop monitoring"""
        if not self.is_monitoring:
            print("[*] Monitoring not running")
            return

        # ask packet analyzer to stop (if running)
        try:
            self.packet_analyzer.stop_sniffing()
        except Exception:
            pass

        self.is_monitoring = False
        print("[*] IDS monitoring stopped")

    def process_packet(self, packet_info):
        """Process a packet through the IDS pipeline"""
        if packet_info is None:
            return []

        # Run detection rules
        try:
            alerts = self.detection_rules.analyze_packet(packet_info)
        except Exception as e:
            print(f"[!] Error running detection rules: {e}")
            alerts = []

        # Store alerts locally and optionally pass to logging system
        for alert in alerts:
            # append to history (in-memory)
            self.alerts_history.append(alert)
            # also ensure logging_system knows about it (if logging_system supports it)
            try:
                # LoggingSystem should read ALERTS_LOG, but if it exposes a write api, use it
                if hasattr(self.logging_system, 'write_alert'):
                    self.logging_system.write_alert(alert)
            except Exception:
                pass

            # print for immediate debug
            print(f"[ALERT] {alert.get('message')}")

        return alerts

    def get_recent_alerts(self, limit=50):
        """Get recent alerts (DataFrame expected by GUI)"""
        # prefer logging_system (it likely reads ALERTS_LOG), fallback to in-memory
        try:
            df = self.logging_system.read_alerts(hours=24).head(limit)
            return df
        except Exception:
            # fallback: build DataFrame from alerts_history if pandas available there
            try:
                import pandas as pd
                if not self.alerts_history:
                    return pd.DataFrame(columns=["timestamp", "message"])
                df = pd.DataFrame(self.alerts_history)
                return df.sort_values(by="timestamp", ascending=False).head(limit)
            except Exception:
                return None

    def get_recent_traffic_logs(self, limit=100):
        """Get recent traffic logs"""
        try:
            return self.logging_system.read_traffic_logs(limit=limit)
        except Exception:
            # fallback to PacketAnalyzer memory
            try:
                return self.packet_analyzer.get_packet_dataframe().head(limit)
            except Exception:
                import pandas as pd
                return pd.DataFrame(columns=["timestamp", "event"])

    def get_statistics(self):
        """Get IDS statistics"""
        try:
            return self.logging_system.get_statistics()
        except Exception:
            # simple fallback stats
            stats = {
                "total_alerts": len(self.alerts_history),
                "recent_packets": self.packet_analyzer.packet_count if hasattr(self.packet_analyzer, "packet_count") else 0
            }
            # no breakdown available in fallback
            return stats

    def clear_old_logs(self, days=7):
        """Clear old logs"""
        try:
            return self.logging_system.clear_logs(days_old=days)
        except Exception:
            # best-effort fallback
            cutoff = None
            try:
                from datetime import datetime, timedelta
                cutoff = datetime.now() - timedelta(days=days)
            except Exception:
                pass
            if cutoff:
                self.alerts_history = [a for a in self.alerts_history if a.get("timestamp") and a["timestamp"] > cutoff]
            return True
