# test_portscan.py
import socket
import time

def simulate_port_scan(target_ip="172.20.10.5", start_port=20, end_port=40):
    """Simulate a port scan"""
    print(f"[*] Simulating port scan on {target_ip}")
    
    open_ports = []
    for port in range(start_port, end_port + 1):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((target_ip, port))
            
            if result == 0:
                print(f"  Port {port}: OPEN")
                open_ports.append(port)
            else:
                print(f"  Port {port}: Closed/filtered")
            
            sock.close()
            time.sleep(0.05)  # Small delay
            
        except Exception as e:
            print(f"  Port {port}: Error - {e}")
    
    print(f"\n[*] Scan complete. Found {len(open_ports)} open ports.")
    return open_ports

if __name__ == "__main__":
    # Scan common ports
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3389]
    
    for port in common_ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.2)
            sock.connect(("192.168.1.100", port))
            print(f"Port {port}: OPEN")
            sock.close()
        except:
            print(f"Port {port}: Closed")
        time.sleep(0.1)