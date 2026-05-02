#!/usr/bin/env python3
"""
Live OS Forensics — C2 Dashboard Server
Academic Project | Receives evidence from agent.sh and serves dashboard
Usage: python c2-server.py [--port 5000] [--host 0.0.0.0]
"""

import json
import sqlite3
import threading
import argparse
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

# ── App setup ────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

DB_PATH = 'forensics.db'
db_lock = threading.Lock()

# ── Database (thread-safe, one conn per request) ─────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS captures (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                uuid      TEXT UNIQUE,
                hostname  TEXT,
                os_name   TEXT,
                os_type   TEXT,
                risk      INTEGER,
                threat    TEXT,
                data      TEXT,
                timestamp TEXT,
                client_ip TEXT
            )
        ''')
        conn.commit()
    print("✔ Database ready: forensics.db")

# ── Routes ────────────────────────────────────────────────────────

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint — agent uses this to test connectivity."""
    return jsonify({"status": "online", "server": "Live OS Forensics C2"}), 200


@app.route('/capture', methods=['POST'])
def capture():
    """Receive forensic evidence from agent.sh"""
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({"error": "No JSON received"}), 400

        # Validate required fields
        if not data.get('meta', {}).get('uuid'):
            return jsonify({"error": "Missing uuid"}), 400

        if not data.get('meta', {}).get('consent'):
            return jsonify({"error": "No consent flag in evidence — agent must use --consent"}), 403

        uuid      = data['meta']['uuid']
        timestamp = datetime.now().isoformat()
        client_ip = request.remote_addr or 'unknown'
        hostname  = data.get('system', {}).get('hostname', 'unknown')
        os_name   = data.get('system', {}).get('os', {}).get('name', 'unknown')
        os_type   = data.get('system', {}).get('os', {}).get('type', 'unknown')
        risk      = int(data.get('risk_assessment', {}).get('score', 0))
        threat    = data.get('risk_assessment', {}).get('level', 'UNKNOWN')

        with db_lock:
            with get_db() as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO captures
                    (uuid, hostname, os_name, os_type, risk, threat, data, timestamp, client_ip)
                    VALUES (?,?,?,?,?,?,?,?,?)
                ''', (uuid, hostname, os_name, os_type, risk, threat,
                      json.dumps(data), timestamp, client_ip))
                conn.commit()

        print(f"  ▸ CAPTURE #{uuid[:8]}  {os_name} ({os_type}) | "
              f"Risk: {risk} [{threat}] | IP: {client_ip}")

        return jsonify({"status": "captured", "uuid": uuid, "risk": risk}), 200

    except Exception as e:
        print(f"  ✗ Capture error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/captures', methods=['GET'])
def api_captures():
    """Return all captures as JSON for the dashboard."""
    try:
        with get_db() as conn:
            rows = conn.execute(
                'SELECT * FROM captures ORDER BY id DESC LIMIT 100'
            ).fetchall()

        result = []
        for row in rows:
            try:
                parsed = json.loads(row['data'])
            except Exception:
                parsed = {}
            result.append({
                "id":        row['id'],
                "uuid":      row['uuid'],
                "hostname":  row['hostname'],
                "os_name":   row['os_name'],
                "os_type":   row['os_type'],
                "risk":      row['risk'],
                "threat":    row['threat'],
                "timestamp": row['timestamp'],
                "client_ip": row['client_ip'],
                "data":      parsed
            })

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Aggregate statistics for dashboard."""
    try:
        with get_db() as conn:
            total    = conn.execute('SELECT COUNT(*) FROM captures').fetchone()[0]
            critical = conn.execute("SELECT COUNT(*) FROM captures WHERE threat='CRITICAL'").fetchone()[0]
            high     = conn.execute("SELECT COUNT(*) FROM captures WHERE threat='HIGH'").fetchone()[0]
            medium   = conn.execute("SELECT COUNT(*) FROM captures WHERE threat='MEDIUM'").fetchone()[0]
            low      = conn.execute("SELECT COUNT(*) FROM captures WHERE threat='LOW'").fetchone()[0]
            avg_risk = conn.execute('SELECT AVG(risk) FROM captures').fetchone()[0] or 0
            by_os    = conn.execute(
                'SELECT os_type, COUNT(*) as n FROM captures GROUP BY os_type'
            ).fetchall()

        return jsonify({
            "total": total, "critical": critical, "high": high,
            "medium": medium, "low": low,
            "avg_risk": round(avg_risk, 1),
            "by_os_type": {r['os_type']: r['n'] for r in by_os}
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/capture/<uuid>', methods=['GET'])
def api_capture_detail(uuid):
    """Full detail for one capture."""
    try:
        with get_db() as conn:
            row = conn.execute(
                'SELECT * FROM captures WHERE uuid=?', (uuid,)
            ).fetchone()
        if not row:
            return jsonify({"error": "Not found"}), 404
        return jsonify(json.loads(row['data'])), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/', methods=['GET'])
def dashboard():
    return render_template_string(HTML_DASHBOARD)


# ── Dashboard HTML (served by Flask, loaded by browser) ──────────
HTML_DASHBOARD = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Live OS Forensics — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;600;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg:       #080b10;
  --surface:  #0d1117;
  --card:     #111720;
  --border:   #1e2a38;
  --accent:   #00d4ff;
  --purple:   #7c3aed;
  --green:    #00ff9d;
  --yellow:   #fbbf24;
  --red:      #f87171;
  --text:     #e2e8f0;
  --muted:    #64748b;
  --font-mono: 'JetBrains Mono', monospace;
  --font-ui:   'Syne', sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font-ui);min-height:100vh;overflow-x:hidden}

/* Noise texture overlay */
body::before{content:'';position:fixed;inset:0;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)' opacity='0.03'/%3E%3C/svg%3E");pointer-events:none;z-index:0;opacity:.4}

/* Scanline */
body::after{content:'';position:fixed;inset:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.015) 2px,rgba(0,212,255,.015) 4px);pointer-events:none;z-index:0}

.wrap{position:relative;z-index:1;max-width:1400px;margin:0 auto;padding:2rem 1.5rem}

/* ── Header ── */
header{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem;gap:1rem;flex-wrap:wrap}
.logo{display:flex;flex-direction:column}
.logo-title{font-size:1.6rem;font-weight:800;letter-spacing:-.02em;line-height:1}
.logo-title span{color:var(--accent)}
.logo-sub{font-family:var(--font-mono);font-size:.72rem;color:var(--muted);margin-top:.3rem;letter-spacing:.05em}
.status-pill{display:flex;align-items:center;gap:.5rem;font-family:var(--font-mono);font-size:.75rem;padding:.35rem .85rem;border-radius:999px;border:1px solid var(--border);color:var(--muted)}
.status-pill .dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);animation:blink 2s ease infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}

/* ── Stat cards ── */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:2rem}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem 1.5rem;position:relative;overflow:hidden;transition:border-color .2s}
.stat-card::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.02),transparent);pointer-events:none}
.stat-card:hover{border-color:var(--accent)}
.stat-label{font-family:var(--font-mono);font-size:.65rem;letter-spacing:.1em;color:var(--muted);text-transform:uppercase;margin-bottom:.5rem}
.stat-value{font-size:2.4rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.stat-value.red{color:var(--red)}
.stat-value.yellow{color:var(--yellow)}
.stat-value.green{color:var(--green)}
.stat-value.accent{color:var(--accent)}
.stat-value.purple{color:#a78bfa}
.stat-sub{font-family:var(--font-mono);font-size:.65rem;color:var(--muted);margin-top:.4rem}

/* ── Controls ── */
.controls{display:flex;gap:.75rem;margin-bottom:1.5rem;flex-wrap:wrap;align-items:center}
.search-box{flex:1;min-width:200px;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.6rem 1rem;font-family:var(--font-mono);font-size:.8rem;color:var(--text);outline:none;transition:border-color .2s}
.search-box:focus{border-color:var(--accent)}
.filter-btn{padding:.5rem 1rem;border-radius:8px;border:1px solid var(--border);background:var(--card);color:var(--muted);font-family:var(--font-mono);font-size:.72rem;cursor:pointer;transition:all .2s;letter-spacing:.05em}
.filter-btn.active,.filter-btn:hover{border-color:var(--accent);color:var(--accent)}
.refresh-btn{padding:.5rem 1.2rem;border-radius:8px;border:1px solid var(--accent);background:transparent;color:var(--accent);font-family:var(--font-mono);font-size:.72rem;cursor:pointer;transition:all .2s}
.refresh-btn:hover{background:rgba(0,212,255,.08)}

/* ── Captures list ── */
.section-title{font-family:var(--font-mono);font-size:.7rem;letter-spacing:.12em;color:var(--muted);text-transform:uppercase;margin-bottom:1rem}
.captures-list{display:flex;flex-direction:column;gap:.75rem}

.capture-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.25rem 1.5rem;cursor:pointer;transition:all .2s;position:relative;overflow:hidden}
.capture-card::after{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--border);transition:background .2s}
.capture-card:hover{border-color:rgba(0,212,255,.3);transform:translateX(2px)}
.capture-card.CRITICAL::after{background:var(--red)}
.capture-card.HIGH::after{background:var(--yellow)}
.capture-card.MEDIUM::after{background:var(--accent)}
.capture-card.LOW::after{background:var(--green)}
.capture-card.expanded{border-color:rgba(0,212,255,.4)}

.card-header{display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.card-left{display:flex;align-items:center;gap:1rem}
.threat-badge{font-family:var(--font-mono);font-size:.65rem;font-weight:700;padding:.2rem .6rem;border-radius:4px;letter-spacing:.08em}
.threat-badge.CRITICAL{background:rgba(248,113,113,.15);color:var(--red);border:1px solid rgba(248,113,113,.3)}
.threat-badge.HIGH{background:rgba(251,191,36,.15);color:var(--yellow);border:1px solid rgba(251,191,36,.3)}
.threat-badge.MEDIUM{background:rgba(0,212,255,.1);color:var(--accent);border:1px solid rgba(0,212,255,.25)}
.threat-badge.LOW{background:rgba(0,255,157,.1);color:var(--green);border:1px solid rgba(0,255,157,.25)}

.hostname{font-weight:700;font-size:1rem;letter-spacing:-.01em}
.os-name{font-family:var(--font-mono);font-size:.75rem;color:var(--muted);margin-top:.1rem}
.risk-score{text-align:right}
.risk-num{font-size:1.8rem;font-weight:800;line-height:1;letter-spacing:-.03em}
.risk-label{font-family:var(--font-mono);font-size:.6rem;color:var(--muted);letter-spacing:.08em}

.card-meta{display:flex;gap:1.5rem;margin-top:.75rem;flex-wrap:wrap}
.meta-item{font-family:var(--font-mono);font-size:.7rem;color:var(--muted)}
.meta-item strong{color:var(--text)}

.tag-list{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.75rem}
.tag{font-family:var(--font-mono);font-size:.62rem;padding:.18rem .55rem;border-radius:4px;background:rgba(255,255,255,.04);border:1px solid var(--border);color:var(--muted)}
.tag.running{background:rgba(248,113,113,.1);color:var(--red);border-color:rgba(248,113,113,.25)}
.tag.indicator{background:rgba(251,191,36,.1);color:var(--yellow);border-color:rgba(251,191,36,.25)}

/* Expanded detail */
.detail-panel{margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border);display:none;animation:fadeIn .2s ease}
.capture-card.expanded .detail-panel{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
.detail-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:1rem}
.detail-section{background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1rem}
.detail-section-title{font-family:var(--font-mono);font-size:.65rem;letter-spacing:.1em;color:var(--accent);text-transform:uppercase;margin-bottom:.75rem;display:flex;align-items:center;gap:.4rem}
.detail-row{display:flex;justify-content:space-between;gap:.5rem;margin-bottom:.4rem;font-family:var(--font-mono);font-size:.72rem}
.detail-row .key{color:var(--muted)}
.detail-row .val{color:var(--text);text-align:right;word-break:break-all;max-width:200px}

/* Empty state */
.empty-state{text-align:center;padding:5rem 2rem;color:var(--muted)}
.empty-state .icon{font-size:3rem;margin-bottom:1rem;opacity:.5}
.empty-state h3{font-family:var(--font-mono);font-size:1rem;margin-bottom:.5rem;color:var(--text)}
.empty-state p{font-family:var(--font-mono);font-size:.75rem;line-height:1.6}
.empty-state code{color:var(--accent);background:rgba(0,212,255,.08);padding:.1rem .4rem;border-radius:4px}

/* Risk bar */
.risk-bar-bg{height:3px;background:var(--border);border-radius:2px;margin-top:.4rem;overflow:hidden}
.risk-bar{height:100%;border-radius:2px;transition:width .6s ease}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">
      <div class="logo-title">Live OS <span>Forensics</span></div>
      <div class="logo-sub">EVIDENCE COLLECTION DASHBOARD &nbsp;·&nbsp; ACADEMIC PROJECT</div>
    </div>
    <div style="display:flex;align-items:center;gap:1rem;flex-wrap:wrap">
      <div class="status-pill">
        <span class="dot"></span>
        <span id="server-status">CONNECTING</span>
      </div>
      <div style="font-family:var(--font-mono);font-size:.7rem;color:var(--muted)" id="last-updated">--</div>
    </div>
  </header>

  <!-- Stats -->
  <div class="stats-grid" id="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Captures</div>
      <div class="stat-value accent" id="s-total">0</div>
      <div class="stat-sub">evidence sessions</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Critical</div>
      <div class="stat-value red" id="s-critical">0</div>
      <div class="stat-sub">risk ≥ 80</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High</div>
      <div class="stat-value yellow" id="s-high">0</div>
      <div class="stat-sub">risk 60–79</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Medium / Low</div>
      <div class="stat-value green" id="s-medlow">0</div>
      <div class="stat-sub">risk &lt; 60</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Avg Risk Score</div>
      <div class="stat-value purple" id="s-avgrisk">0</div>
      <div class="stat-sub">out of 100</div>
    </div>
  </div>

  <!-- Controls -->
  <div class="controls">
    <input class="search-box" id="search-box" placeholder="Search hostname, OS, IP..." oninput="renderCaptures()">
    <button class="filter-btn active" data-level="ALL"     onclick="setFilter(this)">ALL</button>
    <button class="filter-btn"       data-level="CRITICAL" onclick="setFilter(this)">CRITICAL</button>
    <button class="filter-btn"       data-level="HIGH"     onclick="setFilter(this)">HIGH</button>
    <button class="filter-btn"       data-level="MEDIUM"   onclick="setFilter(this)">MEDIUM</button>
    <button class="filter-btn"       data-level="LOW"      onclick="setFilter(this)">LOW</button>
    <button class="refresh-btn" onclick="fetchData()">↻ REFRESH</button>
  </div>

  <div class="section-title">Evidence Captures</div>
  <div class="captures-list" id="captures-list">
    <div class="empty-state">
      <div class="icon">⏳</div>
      <h3>Loading captures...</h3>
    </div>
  </div>
</div>

<script>
let captures = [];
let activeFilter = 'ALL';

// ── Risk colour ──────────────────────────────────────────────────
function riskColor(level) {
  return {CRITICAL:'var(--red)',HIGH:'var(--yellow)',MEDIUM:'var(--accent)',LOW:'var(--green)'}[level] || 'var(--muted)';
}

// ── Fetch data ───────────────────────────────────────────────────
async function fetchData() {
  try {
    const [capRes, statRes] = await Promise.all([
      fetch('/api/captures'), fetch('/api/stats')
    ]);
    captures = await capRes.json();
    const stats = await statRes.json();

    document.getElementById('s-total').textContent    = stats.total || 0;
    document.getElementById('s-critical').textContent = stats.critical || 0;
    document.getElementById('s-high').textContent     = stats.high || 0;
    document.getElementById('s-medlow').textContent   = (stats.medium||0) + (stats.low||0);
    document.getElementById('s-avgrisk').textContent  = stats.avg_risk || 0;
    document.getElementById('server-status').textContent = 'ONLINE';
    document.getElementById('last-updated').textContent  =
      'Updated ' + new Date().toLocaleTimeString();

    renderCaptures();
  } catch(e) {
    document.getElementById('server-status').textContent = 'ERROR';
    console.error(e);
  }
}

// ── Filter ───────────────────────────────────────────────────────
function setFilter(btn) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  activeFilter = btn.dataset.level;
  renderCaptures();
}

// ── Render list ──────────────────────────────────────────────────
function renderCaptures() {
  const q = document.getElementById('search-box').value.toLowerCase();
  let list = captures.filter(c => {
    if (activeFilter !== 'ALL' && c.threat !== activeFilter) return false;
    if (q) {
      const hay = `${c.hostname} ${c.os_name} ${c.os_type} ${c.client_ip}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const el = document.getElementById('captures-list');
  if (!list.length) {
    el.innerHTML = `<div class="empty-state">
      <div class="icon">🔍</div>
      <h3>${captures.length ? 'No matches' : 'Waiting for captures'}</h3>
      <p>${captures.length ? 'Try a different filter.' :
        'Boot your Kali VM and run:<br><code>sudo bash agent.sh --consent --server http://&lt;THIS_IP&gt;:5000/capture</code>'}</p>
    </div>`;
    return;
  }

  el.innerHTML = list.map(c => buildCard(c)).join('');
}

// ── Build a capture card ─────────────────────────────────────────
function buildCard(c) {
  const d = c.data || {};
  const sys = d.system || {};
  const net = d.network || {};
  const sec = d.security_profile || {};
  const vol = d.volatile_evidence || {};
  const risk = d.risk_assessment || {};
  const toolsInstalled = (sec.tools_installed?.list || '').split(',').filter(Boolean);
  const toolsRunning   = (sec.tools_running?.list   || '').split(',').filter(Boolean);
  const indicators     = (sec.suspicious_indicators?.list || '').split(',').filter(Boolean);

  const barPct = c.risk || 0;
  const barColor = riskColor(c.threat);

  return `<div class="capture-card ${c.threat}" onclick="toggleCard(this)">
    <div class="card-header">
      <div class="card-left">
        <span class="threat-badge ${c.threat}">${c.threat}</span>
        <div>
          <div class="hostname">${c.hostname || 'Unknown'}</div>
          <div class="os-name">${c.os_name || '?'} · ${sys.os?.type || '?'} · ${sys.os?.kernel || '?'}</div>
        </div>
      </div>
      <div class="risk-score">
        <div class="risk-num" style="color:${barColor}">${c.risk}</div>
        <div class="risk-label">RISK SCORE</div>
        <div class="risk-bar-bg" style="width:80px">
          <div class="risk-bar" style="width:${barPct}%;background:${barColor}"></div>
        </div>
      </div>
    </div>

    <div class="card-meta">
      <span class="meta-item">IP: <strong>${c.client_ip}</strong></span>
      <span class="meta-item">Boot: <strong>${sys.boot?.type || '?'}</strong></span>
      <span class="meta-item">Procs: <strong>${vol.processes?.total_count || 0}</strong></span>
      <span class="meta-item">TOR: <strong>${net.tor_active ? '⚠ YES' : 'no'}</strong></span>
      <span class="meta-item">VPN: <strong>${net.vpn_detected ? '⚠ YES' : 'no'}</strong></span>
      <span class="meta-item">Uptime: <strong>${sys.boot?.uptime_seconds || 0}s</strong></span>
      <span class="meta-item">${new Date(c.timestamp).toLocaleString()}</span>
    </div>

    ${toolsRunning.length ? `<div class="tag-list">${toolsRunning.map(t=>`<span class="tag running">▶ ${t}</span>`).join('')}</div>` : ''}
    ${indicators.length   ? `<div class="tag-list">${indicators.map(i=>`<span class="tag indicator">⚠ ${i}</span>`).join('')}</div>` : ''}
    ${toolsInstalled.length && !toolsRunning.length ? `<div class="tag-list">${toolsInstalled.slice(0,10).map(t=>`<span class="tag">${t}</span>`).join('')}${toolsInstalled.length>10?`<span class="tag">+${toolsInstalled.length-10} more</span>`:''}</div>` : ''}

    <div class="detail-panel">
      <div class="detail-grid">
        <div class="detail-section">
          <div class="detail-section-title">💻 System</div>
          <div class="detail-row"><span class="key">OS</span><span class="val">${sys.os?.pretty || '?'}</span></div>
          <div class="detail-row"><span class="key">Architecture</span><span class="val">${sys.os?.architecture || '?'}</span></div>
          <div class="detail-row"><span class="key">CPU</span><span class="val">${sys.hardware?.cpu_model || '?'}</span></div>
          <div class="detail-row"><span class="key">CPU Cores</span><span class="val">${sys.hardware?.cpu_cores || '?'}</span></div>
          <div class="detail-row"><span class="key">RAM Total</span><span class="val">${sys.hardware?.ram_total_mb || 0} MB</span></div>
          <div class="detail-row"><span class="key">RAM Free</span><span class="val">${sys.hardware?.ram_free_mb || 0} MB</span></div>
          <div class="detail-row"><span class="key">Machine ID</span><span class="val">${sys.machine_id || 'N/A'}</span></div>
          <div class="detail-row"><span class="key">Boot Time</span><span class="val">${sys.boot?.time || '?'}</span></div>
          <div class="detail-row"><span class="key">Forensic Mode</span><span class="val">${sys.boot?.forensic_mode || '?'}</span></div>
          <div class="detail-row"><span class="key">Disk (root)</span><span class="val">${sys.storage?.disk_usage_root || '?'}</span></div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">🌐 Network</div>
          <div class="detail-row"><span class="key">Interfaces</span><span class="val">${net.interfaces || '?'}</span></div>
          <div class="detail-row"><span class="key">IP Addresses</span><span class="val">${net.ip_addresses || '?'}</span></div>
          <div class="detail-row"><span class="key">DNS Servers</span><span class="val">${net.dns_servers || '?'}</span></div>
          <div class="detail-row"><span class="key">Active Connections</span><span class="val">${net.active_connections || 0}</span></div>
          <div class="detail-row"><span class="key">TOR</span><span class="val">${net.tor_active ? '⚠ Active ('+net.tor_processes+' procs)' : 'Not detected'}</span></div>
          <div class="detail-row"><span class="key">VPN</span><span class="val">${net.vpn_detected ? '⚠ Detected' : 'Not detected'}</span></div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">🔐 Security Profile</div>
          <div class="detail-row"><span class="key">Tools Installed</span><span class="val">${sec.tools_installed?.count || 0}</span></div>
          <div class="detail-row"><span class="key">Tools Running</span><span class="val">${sec.tools_running?.count || 0}</span></div>
          <div class="detail-row"><span class="key">Firewall</span><span class="val">${sec.firewall_active ? '✔ Active' : 'Inactive'}</span></div>
          <div class="detail-row"><span class="key">SELinux</span><span class="val">${sec.selinux || '?'}</span></div>
          <div class="detail-row"><span class="key">AppArmor</span><span class="val">${sec.apparmor || '?'}</span></div>
          <div class="detail-row"><span class="key">Indicators</span><span class="val">${sec.suspicious_indicators?.count || 0}</span></div>
        </div>
        <div class="detail-section">
          <div class="detail-section-title">📊 Risk Factors</div>
          ${(risk.factors||'').split(',').filter(Boolean).map(f=>`<div class="detail-row"><span class="key">${f.split(':')[0]}</span><span class="val" style="color:var(--yellow)">${f.split(':')[1]||''}</span></div>`).join('')||'<div class="detail-row"><span class="key">No elevated factors</span></div>'}
          <div style="margin-top:.75rem;padding-top:.75rem;border-top:1px solid var(--border)">
            <div class="detail-row"><span class="key">Users logged in</span><span class="val">${vol.users?.logged_in || '?'}</span></div>
            <div class="detail-row"><span class="key">Total processes</span><span class="val">${vol.processes?.total_count || 0}</span></div>
            <div class="detail-row"><span class="key">Collect UUID</span><span class="val" style="font-size:.6rem">${d.meta?.uuid?.substring(0,16)||'?'}...</span></div>
          </div>
        </div>
      </div>
    </div>
  </div>`;
}

function toggleCard(el) {
  el.classList.toggle('expanded');
}

// ── Init ─────────────────────────────────────────────────────────
fetchData();
setInterval(fetchData, 5000);
</script>
</body>
</html>
'''

# ── CLI args ──────────────────────────────────────────────────────
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Live OS Forensics C2 Server')
    parser.add_argument('--port', type=int, default=5000)
    parser.add_argument('--host', default='0.0.0.0')
    args = parser.parse_args()

    init_db()
    print("")
    print("  ┌─────────────────────────────────────────────┐")
    print("  │   LIVE OS FORENSICS — C2 DASHBOARD SERVER   │")
    print("  │   Academic Project                          │")
    print("  └─────────────────────────────────────────────┘")
    print(f"  Dashboard : http://localhost:{args.port}")
    print(f"  Capture   : http://localhost:{args.port}/capture")
    print(f"  API       : http://localhost:{args.port}/api/captures")
    print(f"  Health    : http://localhost:{args.port}/health")
    print("")
    print(f"  Agent cmd : sudo bash agent.sh --consent --server http://YOUR_IP:{args.port}/capture")
    print("")
    app.run(host=args.host, port=args.port, debug=False)
