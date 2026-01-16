# detection_rules.py
from datetime import datetime, timedelta
from collections import defaultdict
import logging
from config import ALERTS_LOG, BRUTE_FORCE_THRESHOLD, PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD

# --------------------------
# Setup alert logging to file
# --------------------------
alert_logger = logging.getLogger("alerts")
alert_logger.setLevel(logging.WARNING)

handler = logging.FileHandler(ALERTS_LOG)
handler.setFormatter(logging.Formatter('%(asctime)s - ALERT - %(message)s'))

# Prevent adding multiple handlers if reloaded
if not alert_logger.handlers:
    alert_logger.addHandler(handler)


class DetectionRules:
    def __init__(self):
        self.failed_logins = defaultdict(list)     # For brute force
        self.port_attempts = defaultdict(list)     # For port scan
        self.syn_packets = defaultdict(list)       # For SYN flood

    # ---------------------------------------------------
    # UTILITY : Normalize TCP flags (e.g. "S", "SA", "RA")
    # ---------------------------------------------------
    def _normalize_flags(self, flags):
        if flags is None:
            return ""

        # Scapy can return flags as "S" or as internal repr
        if isinstance(flags, str):
            return flags
        try:
            return str(flags)
        except:
            return ""

    # ---------------------------------------
    # BRUTE FORCE detection via NLP patterns
    # ---------------------------------------
    def detect_brute_force(self, packet_info):
        """
        Detects repetitive failed attempts on SSH/Telnet/RDP
        based on SYN-only TCP packets.
        """
        dst_port = packet_info.get("dst_port")
        flags = self._normalize_flags(packet_info.get("flags"))

        # Targeted ports
        if dst_port not in [22, 21, 23, 3389]:
            return None

        # SYN-only (SYN flag without ACK/FIN/RST)
        if (
            "S" in flags
            and "A" not in flags
            and "F" not in flags
            and "R" not in flags
        ):
            src_ip = packet_info.get("src_ip")
            now = datetime.now()

            # Record failed attempt
            self.failed_logins[src_ip].append(now)

            # Remove older than 1 minute
            self.failed_logins[src_ip] = [
                t for t in self.failed_logins[src_ip]
                if now - t < timedelta(minutes=1)
            ]

            # Trigger alert
            if len(self.failed_logins[src_ip]) >= BRUTE_FORCE_THRESHOLD:
                msg = (
                    f"Brute Force Attack detected from {src_ip} - "
                    f"{len(self.failed_logins[src_ip])} attempts on port {dst_port}"
                )
                alert_logger.warning(msg)

                return {
                    "type": "BRUTE_FORCE",
                    "source": src_ip,
                    "port": dst_port,
                    "message": msg,
                    "timestamp": now
                }

        return None

    # ------------------------
    # PORT SCAN detection
    # ------------------------
    def detect_port_scan(self, packet_info):
        dst_port = packet_info.get("dst_port")
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")

        if dst_port is None:
            return None

        now = datetime.now()
        key = f"{src_ip}->{dst_ip}"

        # Record attempt
        self.port_attempts[key].append((dst_port, now))

        # Keep only recent (<1 min)
        self.port_attempts[key] = [
            (port, t) for port, t in self.port_attempts[key]
            if now - t < timedelta(minutes=1)
        ]

        # Count unique ports
        unique_ports = set(port for port, _ in self.port_attempts[key])

        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            msg = (
                f"Port Scan detected from {src_ip} to {dst_ip} - "
                f"{len(unique_ports)} ports probed"
            )
            alert_logger.warning(msg)

            return {
                "type": "PORT_SCAN",
                "source": src_ip,
                "destination": dst_ip,
                "ports": list(unique_ports),
                "message": msg,
                "timestamp": now
            }

        return None

    # ----------------------
    # SYN FLOOD detection
    # ----------------------
    def detect_syn_flood(self, packet_info):
        flags = self._normalize_flags(packet_info.get("flags"))
        dst_ip = packet_info.get("dst_ip")

        # Count only SYN
        if "S" in flags and "A" not in flags:
            now = datetime.now()

            # Record SYN
            self.syn_packets[dst_ip].append(now)

            # Keep only 1-second window
            self.syn_packets[dst_ip] = [
                t for t in self.syn_packets[dst_ip]
                if now - t < timedelta(seconds=1)
            ]

            # Exceeds threshold?
            if len(self.syn_packets[dst_ip]) >= SYN_FLOOD_THRESHOLD:
                msg = (
                    f"SYN Flood detected on {dst_ip} - "
                    f"{len(self.syn_packets[dst_ip])} SYN packets/sec"
                )
                alert_logger.warning(msg)

                return {
                    "type": "SYN_FLOOD",
                    "target": dst_ip,
                    "rate": len(self.syn_packets[dst_ip]),
                    "message": msg,
                    "timestamp": now
                }

        return None

    # -------------------------
    # SPOOFING detection (basic)
    # -------------------------
    def detect_spoofing(self, packet_info):
        src_ip = packet_info.get("src_ip")

        # Basic private-IP misuse example
        if src_ip and src_ip.startswith("192.168."):
            # Needs network context to confirm—placeholder
            return None

        return None

    # ------------------------------------------------
    # MASTER FUNCTION : runs all detection components
    # ------------------------------------------------
    def analyze_packet(self, packet_info):
        alerts = []

        try:
            brute = self.detect_brute_force(packet_info)
            if brute:
                alerts.append(brute)

            port_scan = self.detect_port_scan(packet_info)
            if port_scan:
                alerts.append(port_scan)

            syn_flood = self.detect_syn_flood(packet_info)
            if syn_flood:
                alerts.append(syn_flood)

            spoof = self.detect_spoofing(packet_info)
            if spoof:
                alerts.append(spoof)

        except Exception as e:
            print(f"[!] ERROR in detection_rules.analyze_packet(): {e}")

        return alerts
