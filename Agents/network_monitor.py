from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict, deque
from datetime import datetime
import time
import json

class NetworkMonitoringAgent:
    def __init__(self):
        # Example blacklisted IPs (replace with real threat intel later)
        self.blacklisted_ips = {
            "10.10.10.10",
            "192.168.1.250"
        }

        # Ports often abused or worth monitoring
        self.suspicious_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            135: "RPC",
            137: "NetBIOS",
            138: "NetBIOS",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            4444: "Metasploit / Backdoor",
            8080: "HTTP-Alt"
        }

        # Track packet rates per source IP
        self.packet_count = defaultdict(int)

        # Track destination ports hit by each source IP for scan detection
        self.port_scan_tracker = defaultdict(lambda: deque())

        # Thresholds
        self.packet_rate_threshold = 100   # packets from one IP before flagging
        self.port_scan_threshold = 10      # unique ports in window before flagging
        self.scan_time_window = 10         # seconds

    def generate_alert(self, alert_type, severity, src_ip=None, dst_ip=None, port=None, protocol=None, reason=None):
        alert = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "agent": "Network Monitoring Agent",
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "port": port,
            "protocol": protocol,
            "reason": reason
        }

        print("\n[ALERT]")
        print(json.dumps(alert, indent=4))
        return alert

    def detect_blacklisted_ip(self, src_ip, dst_ip, protocol):
        if src_ip in self.blacklisted_ips:
            self.generate_alert(
                alert_type="Blacklisted IP Activity",
                severity="High",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                reason=f"Source IP {src_ip} is in blacklist"
            )

    def detect_suspicious_port(self, src_ip, dst_ip, port, protocol):
        if port in self.suspicious_ports:
            self.generate_alert(
                alert_type="Suspicious Port Access",
                severity="Medium",
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=port,
                protocol=protocol,
                reason=f"Traffic detected on monitored port {port} ({self.suspicious_ports[port]})"
            )

    def detect_high_traffic(self, src_ip, dst_ip, protocol):
        self.packet_count[src_ip] += 1
        if self.packet_count[src_ip] == self.packet_rate_threshold:
            self.generate_alert(
                alert_type="High Traffic Volume",
                severity="Medium",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                reason=f"Source IP {src_ip} exceeded {self.packet_rate_threshold} packets"
            )

    def detect_port_scan(self, src_ip, dst_ip, port, protocol):
        current_time = time.time()
        tracker = self.port_scan_tracker[src_ip]

        tracker.append((port, current_time))

        # Remove old entries outside time window
        while tracker and (current_time - tracker[0][1] > self.scan_time_window):
            tracker.popleft()

        unique_ports = {entry[0] for entry in tracker}

        if len(unique_ports) >= self.port_scan_threshold:
            self.generate_alert(
                alert_type="Possible Port Scan",
                severity="High",
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                reason=f"Source IP {src_ip} touched {len(unique_ports)} unique ports within {self.scan_time_window} seconds"
            )
            # Clear tracker to avoid repeated spam alerts
            self.port_scan_tracker[src_ip].clear()

    def process_packet(self, packet):
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "OTHER"
        dst_port = None

        if packet.haslayer(TCP):
            protocol = "TCP"
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"

        # Basic detections
        self.detect_blacklisted_ip(src_ip, dst_ip, protocol)
        self.detect_high_traffic(src_ip, dst_ip, protocol)

        if dst_port is not None:
            self.detect_suspicious_port(src_ip, dst_ip, dst_port, protocol)
            self.detect_port_scan(src_ip, dst_ip, dst_port, protocol)

        # Optional packet log
        print(f"[INFO] {src_ip} -> {dst_ip} | Protocol: {protocol} | Port: {dst_port}")

    def start(self):
        print("[*] Starting Network Monitoring Agent...")
        print("[*] Monitoring live network traffic. Press Ctrl+C to stop.\n")
        sniff(prn=self.process_packet, store=False)

if __name__ == "__main__":
    agent = NetworkMonitoringAgent()
    agent.start()