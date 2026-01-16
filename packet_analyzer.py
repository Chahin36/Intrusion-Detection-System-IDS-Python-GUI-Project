# packet_analyzer.py
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import pandas as pd
from datetime import datetime
import logging
from config import TRAFFIC_LOG

# Set up logging to traffic log file
logging.basicConfig(
    filename=TRAFFIC_LOG,
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

class PacketAnalyzer:
    def __init__(self, interface):
        self.interface = interface
        self.packet_count = 0
        self.packets_data = []
        self._sniffing = False
        self._sniff_thread = None

    def process_packet(self, packet):
        """Process each captured packet and return a clean dict (packet_info)."""
        self.packet_count += 1

        packet_info = {
            'timestamp': datetime.now(),
            'packet_number': self.packet_count
        }

        try:
            # Extract IP layer info
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                packet_info['protocol'] = packet[IP].proto

                # Extract TCP info
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    # normalize flags to a short string (e.g. 'S', 'SA', etc.)
                    packet_info['flags'] = str(packet[TCP].flags)
                # Extract UDP info
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    packet_info['flags'] = 'UDP'
                # Extract ICMP info
                elif ICMP in packet:
                    packet_info['type'] = packet[ICMP].type
                    packet_info['flags'] = 'ICMP'

            # Extract ARP info
            elif ARP in packet:
                packet_info['src_ip'] = packet[ARP].psrc
                packet_info['dst_ip'] = packet[ARP].pdst
                packet_info['operation'] = packet[ARP].op
                packet_info['flags'] = 'ARP'
        except Exception as e:
            # be tolerant: ensure packet_info exists
            packet_info['error'] = str(e)

        # Log packet for traffic auditing
        try:
            logging.info(f"Packet #{self.packet_count}: {packet_info}")
        except Exception:
            pass

        # Store in memory for GUI access
        self.packets_data.append(packet_info)
        if len(self.packets_data) > 1000:
            self.packets_data.pop(0)

        return packet_info

    def _prn_wrapper(self, pkt, callback):
        """Internal wrapper called by scapy sniff: process packet and then call IDS callback."""
        try:
            info = self.process_packet(pkt)
            if callback:
                try:
                    # callback is expected to accept packet_info dict
                    callback(info)
                except Exception as e:
                    # callback errors should not stop sniffing
                    print(f"[!] Error in callback: {e}")
        except Exception as e:
            print(f"[!] Error processing packet: {e}")

    def start_sniffing(self, count=0, callback=None):
        """Start packet sniffing. If callback provided, it will be called with packet_info for each packet."""
        if self._sniffing:
            print("[*] Already sniffing")
            return

        print(f"[*] Starting packet capture on interface {self.interface}")
        self._sniffing = True

        # Use scapy sniff in the current thread; GUI/IDS should call start_monitoring in a background thread.
        try:
            sniff(iface=self.interface,
                  prn=lambda pkt: self._prn_wrapper(pkt, callback),
                  count=count,
                  store=False)
        except KeyboardInterrupt:
            print("\n[*] Stopping packet capture")
        except Exception as e:
            print(f"[!] Error in sniff(): {e}")
        finally:
            self._sniffing = False

    def stop_sniffing(self):
        """Stop sniffing - scapy sniff is blocking; best used by stopping thread or using timeout/count.
        This method is best-effort: scapy sniff doesn't expose a direct stop() call in all environments."""
        # Setting _sniffing False is a flag for future improvements; in many setups sniff blocks until ctrl+c or count reached.
        self._sniffing = False
        print("[*] stop_sniffing() called - scapy sniff may still be blocking until it returns.")

    def get_packet_dataframe(self):
        """Return packets as pandas DataFrame"""
        try:
            return pd.DataFrame(self.packets_data)
        except Exception:
            return pd.DataFrame(self.packets_data)
