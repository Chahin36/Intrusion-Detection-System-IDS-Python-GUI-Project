# guaranteed_attack.py
import socket
import time
import sys

print("=" * 70)
print("🚀 GUARANTEED ALERT-GENERATING ATTACK")
print("This WILL trigger alerts in your IDS!")
print("=" * 70)

TARGET_IP = "172.20.10.5"  # Your IP

# PHASE 1: Massive brute force (will definitely trigger)
print("\n🔥 PHASE 1: MASSIVE BRUTE FORCE (20 attempts)")
for i in range(20):
    try:
        sock = socket.socket()
        sock.settimeout(0.05)
        result = sock.connect_ex((TARGET_IP, 22))  # SSH
        print(f"  SSH attempt {i+1}/20")
        sock.close()
    except Exception as e:
        print(f"  SSH attempt {i+1}/20 - Error")
    time.sleep(0.05)  # Very fast!

# PHASE 2: Massive port scan (will definitely trigger)
print("\n🔍 PHASE 2: MASSIVE PORT SCAN (30 ports)")
for port in range(8000, 8030):
    try:
        sock = socket.socket()
        sock.settimeout(0.05)
        result = sock.connect_ex((TARGET_IP, port))
        if result == 0:
            print(f"  ⭐ Port {port} is OPEN!")
        else:
            print(f"  Scanning port {port}")
        sock.close()
    except:
        print(f"  Scanning port {port}")
    time.sleep(0.03)  # Super fast!

# PHASE 3: Mixed attacks
print("\n⚡ PHASE 3: MIXED ATTACKS")
for port in [21, 22, 23, 3389]:
    print(f"  Attacking port {port}")
    for attempt in range(5):
        try:
            sock = socket.socket()
            sock.settimeout(0.05)
            sock.connect((TARGET_IP, port))
            sock.close()
        except:
            pass
        time.sleep(0.05)

print("\n" + "=" * 70)
print("✅ ATTACK COMPLETE!")
print("Your IDS console SHOULD show:")
print("  '[BRUTE] 172.20.10.5:22 = X attempts'")
print("  '[PORTSCAN] 172.20.10.5 scanned X ports'")
print("  '🚨 ALERT FIRED: ...' messages")
print("=" * 70)

# Verify alerts were written
print("\n📋 Checking alerts.log...")
try:
    with open("logs/alerts.log", "r") as f:
        content = f.read()
        if content:
            print("✅ SUCCESS! Alerts found in logs/alerts.log")
            print("Last few alerts:")
            print(content[-500:] if len(content) > 500 else content)
        else:
            print("❌ alerts.log exists but is EMPTY")
except FileNotFoundError:
    print("❌ alerts.log not found!") 