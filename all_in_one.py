# attack_all_in_one.py
import socket
import time
import random
import threading

def attack_all(target_ip="172.20.10.5"):
    """Launch multiple attack types simultaneously"""
    print("=" * 60)
    print("🚀 LAUNCHING COMPREHENSIVE ATTACK SUITE")
    print(f"Target: {target_ip}")
    print("=" * 60)
    
    # PHASE 1: Rapid brute force (triggers immediately)
    print("\n[PHASE 1] RAPID BRUTE FORCE (10 attempts in 3 seconds)")
    for i in range(10):
        port = random.choice([22, 23, 3389])
        try:
            sock = socket.socket()
            sock.settimeout(0.05)
            sock.connect((target_ip, port))
            sock.close()
        except:
            print(f"  💥 Bruteforce attempt {i+1} on port {port}")
        time.sleep(0.2)
    
    # PHASE 2: Port scan (triggers after ~5 ports)
    print("\n[PHASE 2] PORT SCAN (15 different ports)")
    for i in range(15):
        port = 8000 + i  # Scan ports 8000-8014
        try:
            sock = socket.socket()
            sock.settimeout(0.1)
            sock.connect((target_ip, port))
            sock.close()
            print(f"  🟢 Port {port} open")
        except:
            pass  # Don't print closed ports
        time.sleep(0.15)
    
    # PHASE 3: Rapid sequential attacks
    print("\n[PHASE 3] RAPID SEQUENTIAL ATTACKS")
    attacks = [
        ("SSH brute", 22, 5),
        ("FTP brute", 21, 3),
        ("Telnet brute", 23, 4),
        ("RDP brute", 3389, 4)
    ]
    
    for attack_name, port, attempts in attacks:
        print(f"  🔄 {attack_name} on port {port}")
        for i in range(attempts):
            try:
                sock = socket.socket()
                sock.settimeout(0.1)
                sock.connect((target_ip, port))
                sock.close()
            except:
                pass
            time.sleep(0.1)
    
    print("\n" + "=" * 60)
    print("✅ ALL ATTACKS COMPLETE!")
    print("Expected IDS alerts:")
    print("1. 'Brute Force Attack detected'")
    print("2. 'Port Scan detected'")
    print("3. Multiple alerts for different ports")
    print("=" * 60)

if __name__ == "__main__":
    attack_all(target_ip="172.20.10.5")