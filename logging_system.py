# logging_system.py
import pandas as pd
from datetime import datetime, timedelta
import json
from config import ALERTS_LOG, TRAFFIC_LOG, LOGS_DIR
import os

class LoggingSystem:
    def __init__(self):
        pass
    
    def read_alerts(self, hours=24):
        """Read alerts from the last N hours"""
        alerts = []
        try:
            with open(ALERTS_LOG, 'r') as f:
                for line in f:
                    try:
                        parts = line.strip().split(' - ALERT - ')
                        if len(parts) == 2:
                            timestamp = datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S,%f')
                            if datetime.now() - timestamp <= timedelta(hours=hours):
                                alerts.append({
                                    'timestamp': timestamp,
                                    'message': parts[1]
                                })
                    except:
                        continue
        except FileNotFoundError:
            pass
        
        return pd.DataFrame(alerts)
    
    def read_traffic_logs(self, limit=100):
        """Read recent traffic logs"""
        logs = []
        try:
            with open(TRAFFIC_LOG, 'r') as f:
                lines = f.readlines()[-limit:]  # Get last N lines
                for line in lines:
                    try:
                        parts = line.strip().split(' - ')
                        if len(parts) >= 2:
                            timestamp = datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S,%f')
                            logs.append({
                                'timestamp': timestamp,
                                'event': parts[1] if len(parts) > 1 else ''
                            })
                    except:
                        continue
        except FileNotFoundError:
            pass
        
        return pd.DataFrame(logs)
    
    def get_statistics(self):
        """Get IDS statistics"""
        stats = {}
        
        # Count alerts by type
        alerts_df = self.read_alerts(hours=24)
        if not alerts_df.empty:
            # Extract alert types from messages
            alert_types = {}
            for msg in alerts_df['message']:
                if 'Brute Force' in msg:
                    alert_types['Brute Force'] = alert_types.get('Brute Force', 0) + 1
                elif 'Port Scan' in msg:
                    alert_types['Port Scan'] = alert_types.get('Port Scan', 0) + 1
                elif 'SYN Flood' in msg:
                    alert_types['SYN Flood'] = alert_types.get('SYN Flood', 0) + 1
            
            stats['alerts_by_type'] = alert_types
            stats['total_alerts'] = len(alerts_df)
        
        # Get traffic volume
        traffic_df = self.read_traffic_logs(limit=1000)
        stats['recent_packets'] = len(traffic_df)
        
        return stats
    
    def clear_logs(self, days_old=7):
        """Clear logs older than specified days"""
        # For simplicity, we'll just note this should be implemented
        # In production, you would actually filter and rewrite log files
        print(f"[*] Log clearing for entries older than {days_old} days would be implemented here")
        return True