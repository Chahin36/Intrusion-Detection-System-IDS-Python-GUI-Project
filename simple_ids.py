# simple_ids.py
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from datetime import datetime, timedelta
from collections import defaultdict
import logging
import pandas as pd
import threading
import time

# Setup logging
logging.basicConfig(
    filename='simple_ids_alerts.log',
    level=logging.WARNING,
    format='%(asctime)s - ALERT - %(message)s'
)

print("[*] Simple IDS starting...")

class SimpleIDS:
    def __init__(self):
        self.packet_count = 0
        self.brute_force_attempts = defaultdict(list)
        self.port_scan_attempts = defaultdict(set)
        self.syn_packets = defaultdict(list)
        
        self.brute_threshold = 3
        self.port_scan_threshold = 5
        self.syn_flood_threshold = 20
        
        self.is_running = False
        
    def process_packet(self, packet):
        """Process and analyze each packet"""
        self.packet_count += 1
        
        # Basic packet info
        packet_info = {}
        
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            if TCP in packet:
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = packet[TCP].flags
                
                # BRUTE FORCE DETECTION
                if packet_info['dst_port'] in [22, 21, 23, 3389]:
                    current_time = datetime.now()
                    key = f"{packet_info['src_ip']}:{packet_info['dst_port']}"
                    
                    self.brute_force_attempts[key].append(current_time)
                    
                    # Clean old attempts (1 minute window)
                    self.brute_force_attempts[key] = [
                        t for t in self.brute_force_attempts[key]
                        if current_time - t < timedelta(minutes=1)
                    ]
                    
                    # Check threshold
                    if len(self.brute_force_attempts[key]) >= self.brute_threshold:
                        alert_msg = f"Brute Force from {packet_info['src_ip']} on port {packet_info['dst_port']} - {len(self.brute_force_attempts[key])} attempts"
                        print(f"[ALERT!] {alert_msg}")
                        logging.warning(alert_msg)
                        
                        # Clear to avoid repeated alerts
                        self.brute_force_attempts[key] = []
                
                # PORT SCAN DETECTION
                src_ip = packet_info['src_ip']
                if src_ip not in self.port_scan_attempts:
                    self.port_scan_attempts[src_ip] = set()
                
                self.port_scan_attempts[src_ip].add(packet_info['dst_port'])
                
                if len(self.port_scan_attempts[src_ip]) >= self.port_scan_threshold:
                    alert_msg = f"Port Scan from {src_ip} - {len(self.port_scan_attempts[src_ip])} ports"
                    print(f"[ALERT!] {alert_msg}")
                    logging.warning(alert_msg)
                    
                    self.port_scan_attempts[src_ip] = set()
                
                # SYN FLOOD DETECTION
                if packet_info['flags'] == 2:  # SYN flag only
                    dst_ip = packet_info['dst_ip']
                    current_time = datetime.now()
                    
                    self.syn_packets[dst_ip].append(current_time)
                    
                    # Clean old packets (1 second window)
                    self.syn_packets[dst_ip] = [
                        t for t in self.syn_packets[dst_ip]
                        if current_time - t < timedelta(seconds=1)
                    ]
                    
                    if len(self.syn_packets[dst_ip]) >= self.syn_flood_threshold:
                        alert_msg = f"SYN Flood on {dst_ip} - {len(self.syn_packets[dst_ip])} SYN/sec"
                        print(f"[ALERT!] {alert_msg}")
                        logging.warning(alert_msg)
        
        # Print progress every 100 packets
        if self.packet_count % 100 == 0:
            print(f"[*] Processed {self.packet_count} packets...")
    
    def start(self, interface="Loopback"):
        """Start the IDS"""
        self.is_running = True
        print(f"[*] Starting IDS on interface: {interface}")
        print("[*] Press Ctrl+C to stop")
        
        try:
            sniff(iface=interface, prn=self.process_packet, store=False)
        except KeyboardInterrupt:
            print("\n[*] Stopping IDS")
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def stop(self):
        """Stop the IDS"""
        self.is_running = False

# Run the simple IDS
if __name__ == "__main__":
    ids = SimpleIDS()
    
    # Test in background
    def run_attack_test():
        """Simulate attacks while IDS is running"""
        time.sleep(2)  # Let IDS start
        
        print("\n" + "="*50)
        print("STARTING ATTACK SIMULATION")
        print("="*50)
        
        # Simulate brute force
        import socket
        print("\n[1] Simulating Brute Force on port 22...")
        for i in range(5):
            try:
                sock = socket.socket()
                sock.settimeout(0.1)
                sock.connect(("127.0.0.1", 22))
                sock.close()
            except:
                print(f"  Brute force attempt {i+1}/5")
            time.sleep(0.1)
        
        # Simulate port scan
        print("\n[2] Simulating Port Scan...")
        for port in [80, 443, 21, 25, 110, 143, 3389, 8080, 8888]:
            try:
                sock = socket.socket()
                sock.settimeout(0.1)
                sock.connect(("127.0.0.1", port))
                sock.close()
            except:
                pass
            time.sleep(0.05)
        
        print("\n[3] Attacks simulated. Check for alerts!")
        print("[*] Alerts saved to: simple_ids_alerts.log")
    
    # Start attack simulation in background
    attack_thread = threading.Thread(target=run_attack_test, daemon=True)
    attack_thread.start()
    
    # Start IDS
    ids.start(interface="Loopback")