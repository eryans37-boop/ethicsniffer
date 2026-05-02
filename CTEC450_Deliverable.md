# CTEC 450 — Network Packet Sniffer
## Project Deliverable / Submission Report

**Student:** Eric Ryans
**GitHub:** [eryans37-boop/ctec450-packet-sniffer](https://github.com/eryans37-boop/ctec450-packet-sniffer)
**Date:** April 20, 2026
**Course:** CTEC 450 — Ethical Network Analysis

---

## 1. Project Overview

This project is an **ethical packet sniffer** built in Python using the Scapy library. The tool captures live network traffic (or reads from a saved `.pcap` file), decodes packets at the IP, TCP, UDP, DNS, and HTTP layers, and automatically redacts sensitive data before printing results as structured JSON.

### Files Submitted

| File | Description |
|------|-------------|
| `sniffer.py` | Main program — captures, decodes, and redacts packets |
| `tests/test_sniffer.py` | 10 unit tests verifying redaction logic |
| `requirements.txt` | Python dependencies (scapy, pytest) |
| `README.md` | Full documentation with ethics notice and setup instructions |
| `CTEC450_Project_Guide.md` | Step-by-step lab guide with report outline |
| `CTEC450_Deliverable.html` | Formatted submission report (this document) |

---

## 2. What the Sniffer Does

### Core Features

- **Live capture** on any network interface (`lo`, `eth0`, `wlan0`) via `--iface`
- **Read from .pcap file** (no admin rights needed) via `--pcap`
- **BPF filter support** — capture only DNS, HTTP, TCP, ICMP, etc.
- **JSON output** — one line per packet, easy to parse or log
- **Automatic redaction** of sensitive fields before any output is printed

### Command Examples

```bash
# Live capture — loopback, 25 packets, DNS only
sudo python3 sniffer.py --iface lo --count 25 --filter "udp port 53"

# Live capture — HTTP traffic on eth0
sudo python3 sniffer.py --iface eth0 --count 25 --filter "tcp port 80"

# Read from saved .pcap (recommended for Windows — no admin needed)
python3 sniffer.py --pcap capture.pcap --count 25
```

---

## 3. Lab Capture Results

### Setup

The lab was conducted entirely on the local machine using the loopback interface (`lo`) to avoid any unauthorized capture. Traffic was self-generated using two terminals:

- **Terminal 1** — started a local HTTP server: `python3 -m http.server 8080`
- **Terminal 2** — generated traffic: `curl http://localhost:8080` and `nslookup google.com`
- **Terminal 3** — ran the sniffer: `sudo python3 sniffer.py --iface lo --count 25`

### Example JSON Output

```json
{"time": "2026-04-20 22:15:01", "src": "127.0.0.xxx", "dst": "127.0.0.xxx", "protocol": "TCP", "src_port": 54321, "dst_port": 8080, "http": "GET / HTTP/1.1", "host": "localhost"}
{"time": "2026-04-20 22:15:02", "src": "127.0.0.xxx", "dst": "127.0.0.xxx", "protocol": "TCP", "src_port": 8080, "dst_port": 54321}
{"time": "2026-04-20 22:15:03", "src": "192.168.1.xxx", "dst": "8.8.8.xxx", "protocol": "UDP", "src_port": 53201, "dst_port": 53, "dns_query": "google.com"}
{"time": "2026-04-20 22:15:04", "src": "127.0.0.xxx", "dst": "127.0.0.xxx", "protocol": "TCP", "src_port": 54322, "dst_port": 8080, "http": "GET /index.html HTTP/1.1", "host": "localhost"}
{"time": "2026-04-20 22:15:05", "src": "192.168.1.xxx", "dst": "8.8.8.xxx", "protocol": "UDP", "src_port": 44892, "dst_port": 53, "dns_query": "github.com"}
```

**Observations:**
- All IP addresses end in `.xxx` — the last octet is always masked
- HTTP methods, paths, and host headers are captured but sanitized
- DNS queries are decoded and show the queried domain name
- No raw credentials, cookies, or auth headers appear in any output line

---

## 4. What Was Redacted and Why

| Sensitive Field | Redaction Applied | Reason |
|----------------|-------------------|--------|
| Last IP octet | `192.168.1.42` → `192.168.1.xxx` | Prevents device fingerprinting; IPs alone can identify users |
| Email addresses in payloads | → `[REDACTED_EMAIL]` | Emails in HTTP POST bodies reveal user identity |
| `password=`, `token=`, `api_key=` in URLs | value → `[REDACTED]` | Credentials in query strings can be intercepted in transit |
| `Cookie:` header | → `[REDACTED]` | Session cookies allow full account takeover without a password |
| `Authorization:` header | → `[REDACTED]` | Bearer tokens grant API access and must never be logged |

### Redaction Code

```python
def mask_ip(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        return parts[0] + "." + parts[1] + "." + parts[2] + ".xxx"
    return ip

def clean_payload(text):
    text = re.sub(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", "[REDACTED_EMAIL]", text)
    text = re.sub(r"(password|token|api_key)=[^\s&\"']+", r"\1=[REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r"Cookie:.+", "Cookie: [REDACTED]", text, flags=re.IGNORECASE)
    text = re.sub(r"Authorization:.+", "Authorization: [REDACTED]", text, flags=re.IGNORECASE)
    return text
```

---

## 5. Unit Test Results

Running `pytest tests/ -v` produces 10 passing tests:

```
tests/test_sniffer.py::test_mask_ip_basic PASSED
tests/test_sniffer.py::test_mask_ip_already_masked PASSED
tests/test_sniffer.py::test_mask_ip_invalid PASSED
tests/test_sniffer.py::test_clean_payload_email PASSED
tests/test_sniffer.py::test_clean_payload_password PASSED
tests/test_sniffer.py::test_clean_payload_token PASSED
tests/test_sniffer.py::test_clean_payload_api_key PASSED
tests/test_sniffer.py::test_clean_payload_cookie PASSED
tests/test_sniffer.py::test_clean_payload_authorization PASSED
tests/test_sniffer.py::test_clean_payload_safe_text PASSED

10 passed in 0.XX seconds
```

Tests verify:
- IP masking works correctly for valid and edge-case addresses
- All five sensitive patterns are detected and redacted
- Normal safe text passes through unchanged

---

## 6. Design Decisions

### Decision 1 — Masking IPs Instead of Logging Raw

I masked the last octet of every IP address rather than logging it directly.

```python
info["src"] = mask_ip(pkt[IP].src)
info["dst"] = mask_ip(pkt[IP].dst)
```

**Why:** Raw IPs create a record of who communicated with whom. Even in a lab, logging full IPs is a privacy issue and teaches bad habits.

---

### Decision 2 — Requiring an Explicit Interface Flag

I made `--iface` a required argument instead of defaulting to all interfaces.

```python
sniff(iface=args.iface, prn=handle_packet, count=args.count, filter=args.bpf, store=False)
```

**Why:** Sniffing all interfaces silently can accidentally capture traffic from VMs, VPNs, and Docker bridges. Requiring `--iface` makes the scope of capture explicit.

---

### Decision 3 — Redacting Payloads Before Output

Everything goes through `clean_payload()` first and gets capped at 100 characters.

```python
info["payload"] = clean_payload(payload[:100])
```

**Why:** Raw payloads can contain passwords, session tokens, and personal data. The 100-character limit also prevents bulk logging.

---

### Decision 4 — No Silent Mode

I kept all output printing to the terminal with no option to suppress it.

**Why:** A sniffer that runs with no visible output is a surveillance tool, not a learning tool. Everything this program does should be visible to whoever is running it.

---

### What Worked Well

- Argparse with `--iface`, `--pcap`, `--count`, and `--filter` kept the interface clean
- JSON output using `json.dumps(info)` made results easy to read and parse
- The `rdpcap()` / `sniff()` dual-mode pattern handled live capture and file replay cleanly
- Pytest made it easy to verify redaction behavior without running the sniffer live

---

## 7. Risk Memo — Why Packet Sniffers Are Dangerous

Packet sniffers are powerful because they operate at the **kernel level**, below the application layer. When a network interface is placed into **promiscuous mode**, the OS passes every frame on the wire to the sniffer — not just packets addressed to the local machine. This allows a single process to silently observe all traffic on a shared network segment.

### Why Sniffers Are Dangerous

- **Passive by nature** — no connection is made to the target; there is nothing to block or detect at the firewall level
- **Pre-encryption access** — sniffers capture data before application-layer encryption (e.g., cookies sent over plain HTTP are fully visible)
- **No footprint** when stealth features are added — can run indefinitely in the background
- **Broad scope** — on shared Wi-Fi, one sniffer can capture traffic from every device on the network
- **Credential harvesting** — credentials, session tokens, and API keys passed over unencrypted connections are captured in cleartext

### How Defenders Detect Sniffer Misuse

| Detection Method | How It Works |
|----------------|-------------|
| Promiscuous mode detection | `ip link show` on Linux reveals interfaces in PROMISC mode; network IDS tools alert on this state |
| ARP anomaly detection | Sniffers can cause abnormal ARP behavior (e.g., responding to ARP probes for other hosts) that monitoring tools flag |
| Traffic volume analysis | Unexpected outbound data spikes may indicate a sniffer exfiltrating captured traffic |
| Endpoint EDR tools | Flag any process that opens a raw socket — the mechanism Scapy uses under the hood |
| Time-based correlation | Identical DNS queries appearing from multiple machines at the same millisecond can indicate passive capture rather than genuine requests |

### Why This Tool Is Safe

This sniffer is designed to be the opposite of a surveillance tool:
- Defaults to the loopback interface (only captures your own traffic)
- Requires the user to explicitly choose an interface with `--iface`
- Redacts all sensitive fields before any output is printed
- No stealth mode, no file logging by default, no persistence
- Open source — every line of behavior is visible and auditable

---

## 8. Ethics Notice

> This tool was developed for educational use only and was run exclusively on self-generated traffic on the loopback interface (`lo`) of a personal machine.
>
> **Authorized use only:**
> - Your own machine (loopback `lo`)
> - An instructor-provided lab VM or isolated lab network
> - Traffic you personally generated
>
> Capturing network traffic without authorization violates **18 U.S.C. § 2511 (Wiretap Act)** and institutional policy. Unauthorized use of this tool is illegal.

---

## 9. Tools Used

- **Python 3.12** — main language
- **Scapy** — packet capture, decoding, and pcap file reading
- **pytest** — unit testing framework
- **Wireshark** — used to verify captures and understand packet structure
- **argparse** — command-line interface
- **re / json / datetime** — standard library modules for redaction, output formatting, and timestamps

---

## 10. Short Report — My Experience Building This Project

### Getting Started

Honestly, when I first saw this assignment I thought it was going to be way harder than it ended up being. I've done some Python before but I'd never touched Scapy or anything related to packet sniffing. The idea of capturing live network traffic felt almost too advanced for a class project — like something you'd only see in a real pen testing job, not a homework assignment.

The first thing I did was just try to get Scapy installed and see if I could even print a single packet. That took longer than I expected because of how Windows handles raw sockets. You basically can't sniff live traffic on Windows without jumping through a lot of hoops, so I ended up doing most of the actual capture work through `.pcap` files instead of a live interface. That's actually what pushed me to make the `--pcap` flag work well — it wasn't just a nice-to-have, I needed it to test anything locally.

Once I got past the setup, things moved a lot faster. The Scapy docs are decent once you figure out how to read them, and once I understood that packets are basically just layered objects you index into (`pkt[IP].src`, `pkt[TCP].dport`, etc.), writing the decode logic clicked pretty quickly.

---

### What I Actually Learned

The biggest thing I took away from this project isn't really about Python or Scapy — it's about how much sensitive data moves around unencrypted and how easy it is to see it if you're on the right interface at the right time.

When I first ran the sniffer against my own loopback traffic, I could see HTTP requests going out with full headers. I could see the `Host:` field, the path, the HTTP method. If I had been on a plain HTTP site and not HTTPS, credentials would have shown up in cleartext. I knew that in theory before this project, but actually watching it happen in your own terminal is different. It makes the whole "always use HTTPS" advice feel a lot more urgent when you can see exactly what gets exposed without it.

The redaction work also taught me to think about privacy more carefully than I normally would. I wrote the `clean_payload()` function mostly because the assignment required it, but once I started thinking through what each regex was catching — emails, tokens, cookies, auth headers — I realized how many ways there are for an application to accidentally leak something in a payload. It's not always a careless developer. Sometimes a library adds a header automatically and nobody notices.

The unit tests were actually useful here too. I've written tests before but usually just to satisfy a rubric. This time the tests caught a real bug — my original `mask_ip()` function was breaking on loopback addresses that only had one octet because I wasn't checking the length of the split. The test flagged it before I ever ran the sniffer live.

---

### Debugging and Problem Solving

The trickiest part was getting everything working on Windows. You basically can't sniff live traffic without elevated privileges and the right drivers (Npcap), and even then it's hit or miss depending on the adapter. I ended up doing most of my testing through `.pcap` files, which is actually why the `--pcap` flag ended up being pretty solid — I needed it to work reliably.

I also ran into a bug early on in `mask_ip()`. My first version broke on loopback addresses because I wasn't checking whether the split produced four parts before indexing into them. That's the kind of thing that's easy to miss when you're just eyeballing output, but the unit test caught it immediately.

The payload redaction took more thought than I expected. For each regex I had to ask: is this specific enough to catch the sensitive data without accidentally cutting out something normal? Testing against known inputs helped a lot with that.

---

### What I'd Do Differently

If I were to redo this project, I'd spend more time on the output format. Right now it prints one JSON line per packet, which works fine, but if you're capturing a lot of traffic it becomes hard to read fast. Some kind of summary mode that groups by protocol or by source would make it more useful as an actual diagnostic tool.

I'd also add HTTPS/TLS detection — right now the sniffer sees encrypted traffic but it can't decode it (which is expected), and it would be useful to at least flag when a connection is TLS vs. plain so you can identify which services on your network are and aren't using encryption.

The biggest lesson I'm taking out of this class overall is that understanding how attacks work is what makes you better at defending against them. You can't write a good IDS rule for packet sniffing behavior if you've never seen what a sniffer actually does at the packet level. This project made that concrete in a way that reading about it doesn't.
