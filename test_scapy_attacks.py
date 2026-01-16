from scapy.all import *
import time

def run_scapy_attack():
    print("[INFO] Launching Scapy test attacks")

    pkt = IP(dst="172.20.10.5") / TCP(dport=80, flags="S")
    send(pkt, count=5, verbose=False)
    print("[INFO] SYN packets sent")

    def packet_handler(packet):
        if packet.haslayer(TCP):
            print(f"[PACKET] TCP packet detected from {packet[IP].src}")

    print("[INFO] Sniffing packets (10 seconds)")
    sniff(prn=packet_handler, timeout=10)

    print("[INFO] Scapy attack finished")


if __name__ == "__main__":
    run_scapy_attack()
