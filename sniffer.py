# CTEC 450 - Network Packet Sniffer
# Author: Eric Ryans
# Description: captures packets on a network interface using scapy
# Note: only run this on your own machine or a lab network you have permission to use

from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw
import re
import argparse
import json
from datetime import datetime

# -- redaction functions --

def mask_ip(ip):
    # hide the last part of the IP address
    parts = ip.split(".")
    if len(parts) == 4:
        return parts[0] + "." + parts[1] + "." + parts[2] + ".xxx"
    return ip

def clean_payload(text):
    # remove emails
    text = re.sub(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]", text)
    # remove passwords and tokens from URLs
    text = re.sub(r"(password|token|api_key)=[^\s&\"']+", r"\1=[REDACTED]", text, flags=re.IGNORECASE)
    # remove cookie headers
    text = re.sub(r"Cookie:.+", "Cookie: [REDACTED]", text, flags=re.IGNORECASE)
    # remove auth headers
    text = re.sub(r"Authorization:.+", "Authorization: [REDACTED]", text, flags=re.IGNORECASE)
    return text

# -- packet handler --

def handle_packet(pkt):
    info = {}
    info["time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    # get IP info
    if pkt.haslayer(IP):
        info["src"] = mask_ip(pkt[IP].src)
        info["dst"] = mask_ip(pkt[IP].dst)
    else:
        info["src"] = "N/A"
        info["dst"] = "N/A"

    # TCP
    if pkt.haslayer(TCP):
        info["protocol"] = "TCP"
        info["src_port"] = pkt[TCP].sport
        info["dst_port"] = pkt[TCP].dport

    # UDP
    elif pkt.haslayer(UDP):
        info["protocol"] = "UDP"
        info["src_port"] = pkt[UDP].sport
        info["dst_port"] = pkt[UDP].dport

    # DNS
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        info["dns_query"] = pkt[DNSQR].qname.decode().strip(".")

    # HTTP - only works on port 80 unencrypted
    if pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode("utf-8", errors="ignore")
        except:
            payload = ""

        if payload.startswith(("GET", "POST", "PUT", "DELETE")):
            lines = payload.split("\r\n")
            info["http"] = clean_payload(lines[0])
            for line in lines:
                if line.lower().startswith("host:"):
                    info["host"] = line.split(":", 1)[1].strip()
        elif payload:
            info["payload"] = clean_payload(payload[:100])

    print(json.dumps(info))

# -- main --

def main():
    parser = argparse.ArgumentParser(description="CTEC 450 Packet Sniffer")
    parser.add_argument("--iface", help="network interface to sniff (e.g. eth0, lo)")
    parser.add_argument("--pcap", help="read from a .pcap file instead of live capture")
    parser.add_argument("--count", type=int, default=25, help="number of packets (default 25)")
    parser.add_argument("--filter", dest="bpf", default="", help='BPF filter e.g. "tcp port 80"')
    args = parser.parse_args()

    if args.pcap:
        print(f"[*] Reading from file: {args.pcap}")
        packets = rdpcap(args.pcap)
        for pkt in packets[:args.count]:
            handle_packet(pkt)
    else:
        print(f"[*] Sniffing on {args.iface or 'all interfaces'} | count={args.count} | filter='{args.bpf}'")
        sniff(iface=args.iface, prn=handle_packet, count=args.count, filter=args.bpf, store=False)

    print("[*] Done.")

if __name__ == "__main__":
    main()
