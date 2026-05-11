#!/usr/bin/env python3
"""
Advanced Network Sniffer
Requires: scapy (pip install scapy)
Run with: sudo python network_sniffer.py
"""

import sys
import os
import signal
import time
from datetime import datetime
from collections import defaultdict
import argparse
from scapy.all import *

class NetworkSniffer:
    def __init__(self, interface=None, count=0, filter_expr=None, verbose=False, save_file=None):
        self.interface = interface
        self.count = count
        self.filter_expr = filter_expr
        self.verbose = verbose
        self.save_file = save_file

        self.packet_count = 0
        self.total_bytes = 0
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(int)
        self.captured_packets = []
        self.start_time = time.time()
        self.running = True

        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

    def signal_handler(self, signum, frame):
        print("\n[!] Stopping sniffer gracefully...")
        self.running = False
        self.print_statistics()
        if self.save_file:
            self.save_packets()
        sys.exit(0)

    def packet_handler(self, packet):
        if not self.running:
            return True

        self.packet_count += 1
        packet_len = len(packet)
        self.total_bytes += packet_len

        if self.save_file:
            self.captured_packets.append(packet)

        packet_info = self.analyze_packet(packet)

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {packet_info}")

        self.update_statistics(packet)

        if self.count > 0 and self.packet_count >= self.count:
            self.running = False
            return True

    def analyze_packet(self, packet):
        info = []

        if packet.haslayer(IP):
            ip = packet[IP]
            info.append(f"{ip.src} → {ip.dst}")

            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info.append(f"TCP {tcp.sport}->{tcp.dport} [{tcp.flags}]")

            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info.append(f"UDP {udp.sport}->{udp.dport}")

            elif packet.haslayer(ICMP):
                info.append("ICMP")

        elif packet.haslayer(ARP):
            arp = packet[ARP]
            info.append(f"ARP {arp.psrc} → {arp.pdst}")

        else:
            info.append("Other Protocol")

        info.append(f"{len(packet)} bytes")

        if self.verbose and packet.haslayer(Raw):
            payload = packet[Raw].load[:40]
            info.append(f"Data: {payload}")

        return " | ".join(info)

    def update_statistics(self, packet):
        if packet.haslayer(TCP):
            self.protocol_stats["TCP"] += 1
        elif packet.haslayer(UDP):
            self.protocol_stats["UDP"] += 1
        elif packet.haslayer(ICMP):
            self.protocol_stats["ICMP"] += 1
        elif packet.haslayer(ARP):
            self.protocol_stats["ARP"] += 1
        else:
            self.protocol_stats["Other"] += 1

        if packet.haslayer(IP):
            self.ip_stats[packet[IP].src] += 1

    def print_statistics(self):
        duration = time.time() - self.start_time
        bandwidth = self.total_bytes / duration if duration > 0 else 0

        print("\n" + "="*60)
        print("📊 SNIFFER STATISTICS")
        print("="*60)
        print(f"Total Packets : {self.packet_count}")
        print(f"Total Data    : {self.total_bytes} bytes")
        print(f"Duration      : {duration:.2f} sec")
        print(f"Bandwidth     : {bandwidth:.2f} bytes/sec")

        print("\nProtocol Breakdown:")
        for proto, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percent = (count / self.packet_count * 100) if self.packet_count else 0
            print(f"  {proto:8} : {count:5} ({percent:.1f}%)")

        print("\nTop Talkers (Source IPs):")
        for ip, count in sorted(self.ip_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  {ip:15} : {count} packets")

        print("="*60)

    def save_packets(self):
        if self.captured_packets:
            wrpcap(self.save_file, self.captured_packets)
            print(f"[+] Packets saved to {self.save_file}")

    def start(self):
        print("="*60)
        print("🚀 Advanced Network Sniffer Started")
        print("="*60)
        print(f"Interface : {self.interface if self.interface else 'Default'}")
        print(f"Filter    : {self.filter_expr if self.filter_expr else 'None'}")
        print(f"Verbose   : {'Yes' if self.verbose else 'No'}")
        print("="*60)
        print("Press Ctrl+C to stop\n")

        sniff(
            iface=self.interface,
            prn=self.packet_handler,
            filter=self.filter_expr,
            store=False
        )

        self.print_statistics()
        if self.save_file:
            self.save_packets()


def main():
    parser = argparse.ArgumentParser(description="Advanced Network Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-f", "--filter", help="BPF filter expression")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show packet payload")
    parser.add_argument("-s", "--save", help="Save packets to PCAP file")

    args = parser.parse_args()

    sniffer = NetworkSniffer(
        interface=args.interface,
        count=args.count,
        filter_expr=args.filter,
        verbose=args.verbose,
        save_file=args.save
    )

    sniffer.start()


if __name__ == "__main__":
    # Root check (Linux/macOS)
    if os.name != "nt" and os.geteuid() != 0:
        print("[!] Please run with sudo/root privileges.")
        sys.exit(1)

    main()