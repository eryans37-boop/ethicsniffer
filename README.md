# Packet Sniffer: Seeing the Network (Ethically)
### CTEC 450 — Ethical Network Analysis Project
**Author:** Eric Ryans | **GitHub:** [eryans37-boop](https://github.com/eryans37-boop)

---

## Ethics Notice

> Capturing network traffic without authorization violates federal law
> **(18 U.S.C. § 2511 — Wiretap Act)** and institutional policy.
>
> This tool may **only** be used on:
> - Your own machine (loopback `lo`)
> - An instructor-provided lab VM or isolated lab network
> - Traffic you personally generated and own

---

## Setup

### Requirements
- Python 3.10+
- Linux VM (Ubuntu/Kali), Windows WSL2, or macOS
- Root/sudo for live capture (not needed for `--pcap` mode)

### Install dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Sniffer

### Mode 1 — Live capture (requires root/sudo)

```bash
# Loopback, 25 packets, DNS only
sudo python sniffer.py --iface lo --count 25 --filter "udp port 53"

# HTTP traffic on eth0
sudo python sniffer.py --iface eth0 --count 25 --filter "tcp port 80"

# All interfaces, no filter
sudo python sniffer.py --count 25
```

### Mode 2 — Read from .pcap file (no root needed, recommended for Windows)

```bash
python sniffer.py --pcap capture.pcap --count 25
```

### Save output to JSON

```bash
sudo python sniffer.py --iface lo --count 25 --output results.json
```

---

## Key Parameters

| Flag | Description | Example |
|------|-------------|---------|
| `--iface` | Network interface to sniff | `lo`, `eth0`, `wlan0` |
| `--pcap` | Read from saved .pcap file | `capture.pcap` |
| `--count` | Packets to capture (default: 25) | `25` |
| `--filter` | BPF filter string | `"tcp port 80"` |
| `--output` | Write JSON results to file | `results.json` |

### BPF Filter Examples

```
udp port 53          # DNS queries only
tcp port 80          # HTTP traffic
tcp or udp           # All TCP and UDP
icmp                 # Ping/ICMP only
```

---

## What Gets Redacted

| Sensitive Field | Redaction |
|----------------|-----------|
| IP last octet | `192.168.1.42` → `192.168.1.xxx` |
| Email addresses | → `[REDACTED_EMAIL]` |
| `password=`, `token=`, `api_key=` | value → `[REDACTED]` |
| `Authorization:` header | → `[REDACTED]` |
| `Cookie:` / `Set-Cookie:` | → `[REDACTED]` |

---

## Running Tests

```bash
pytest tests/ -v
```

---

## Decoded Layers

| Layer | Fields Extracted |
|-------|-----------------|
| IP | src/dst IP (redacted) |
| TCP | ports, flags |
| UDP | ports |
| DNS | query domain name |
| HTTP (port 80) | method, path, host (redacted) |

---

## Generating Your Own Lab Traffic

```bash
# Terminal 1 — start a local HTTP server
python -m http.server 8080

# Terminal 2 — generate DNS + HTTP traffic
curl http://localhost:8080
nslookup google.com

# Terminal 3 — sniff it
sudo python sniffer.py --iface lo --count 25 --filter "tcp port 8080 or udp port 53"
```

---

## Project Structure

```
ctec450-packet-sniffer/
├── sniffer.py                      # Packet sniffer — capture, decode, redact
├── ai_security.py                  # AI Security project — MNIST, FGSM, defense
├── requirements.txt                # Python dependencies (all projects)
├── README.md                       # This file
├── CTEC450_Deliverable.md          # Packet sniffer project report
├── CTEC450_AI_Security_Paper.md    # AI Security research paper (APA)
├── CTEC450_AI_Security_Slides.html # 10-slide presentation
└── tests/
    ├── __init__.py
    └── test_sniffer.py             # Unit tests for redaction logic
```

### Running the AI Security Project

```bash
# Install all dependencies first
pip install -r requirements.txt

# Run the full pipeline (train → attack → defend → save graphs)
python ai_security.py

# Output files generated:
#   baseline_model.pth      saved CNN weights
#   defended_model.pth      adversarially-trained weights
#   fgsm_comparison.png     clean vs adversarial image comparison
#   results.png             accuracy bar chart
```

---

## Risk Memo Summary

Packet sniffers are powerful because they operate at the kernel level, capturing all traffic flowing through an interface — not just your own sessions. A malicious actor on a shared network can silently record credentials, session tokens, and private communications.

**How defenders detect sniffer misuse:**
- **Promiscuous mode alerts** — NICs in promiscuous mode appear in `ip link` and can be detected by IDS tools
- **ARP anomaly detection** — sniffers often cause ARP table irregularities
- **Traffic volume analysis** — unexpected outbound spikes may indicate exfiltration
- **Endpoint EDR tools** — flag processes with raw socket access

This is why our tool defaults to loopback, redacts output, and includes no stealth features.
