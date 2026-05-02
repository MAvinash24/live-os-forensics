#  Live OS Forensics — Academic Project

> Evidence collection tool for live operating systems  
> Authorised use only

---

##  Project Structure

```
live-os-forensics/
├── agent/
│   ├── agent.sh                   # Linux/Kali forensic evidence collector
│   └── collect-usb-forensics.ps1  # Windows USB evidence collector
├── server/
│   ├── c2-server.py               # Flask C2 dashboard server
│   └── requirements.txt
└── README.md
```

---

##  Setup

### 1. Start the C2 Server (Windows host)

```bash
cd server
pip install -r requirements.txt
python c2-server.py
```

Dashboard opens at: **http://localhost:5000**

---

### 2. Run the Forensic Agent (Kali VM)

```bash
# Basic — saves evidence locally
sudo bash agent.sh --consent

# With C2 upload — sends to dashboard
sudo bash agent.sh --consent --server http://192.168.153.1:5000/capture
```

>  **`--consent` flag is mandatory.** The agent will not run without it.

---

### 3. USB Evidence Collection (Windows, run as Admin)

```powershell
.\collect-usb-forensics.ps1 -Consent
```

---

##  VMware Network Fix (Kali → Windows)

If `ping 192.168.153.1` fails from Kali:

1. VM Settings → Network Adapter
2. Set to **NAT (VMnet8)** or **Host-only (VMnet1)**
3. Confirm: `ping 192.168.153.1` should succeed

---

##  What Evidence is Collected

| Category | Data Points |
|---|---|
| OS Identity | Name, version, kernel, architecture, machine ID |
| Hardware | CPU model/cores, RAM total/free |
| Boot | Live/installed, forensic mode, uptime, cmdline |
| Processes | Total count, top processes by CPU |
| Network | Interfaces, IPs, DNS, connections, TOR/VPN detection |
| Users | Logged-in sessions, current user |
| Storage | Block devices, mounts, disk usage |
| Security | Installed + actively running tools, firewall, SELinux |
| Indicators | SUID in /tmp, deleted-but-open files, high port listeners |
| Risk Score | Evidence-based 0–100 with factor breakdown |

---

##  Design Principles

- **Consent required** — `--consent` flag mandatory, no silent execution
- **Read-only** — collects evidence, never modifies the target system
- **Local first** — saves JSON report locally before any upload
- **Evidence-based risk** — scoring uses observed facts, not OS assumptions
- **Chain of custody** — every session logged with operator, timestamp, UUID

---

##  Talking Points

**Q: What makes this forensics and not malware?**  
A: It requires explicit consent, runs transparently, saves locally first, is read-only, and has an audit log of every collection step.

**Q: How is risk calculated?**  
A: Evidence-based: TOR active (+20), VPN detected (+10), live boot (+15), actively running attack tools (+10 each), suspicious file indicators (+8 each). Not assumed from OS name alone.

**Q: What volatile evidence do you capture?**  
A: Running processes (lost on shutdown), logged-in users, active network connections, currently mounted devices — classic volatile forensics data.

**Q: Why is USB forensics separate?**  
A: USB devices are external evidence sources. The PowerShell script reads from them (chain of custody), unlike a dropper which writes to them.
