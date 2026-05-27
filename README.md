<!-- Banner -->
<div align="center">

```
███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗  ███████╗██║     ███████║██╔██╗ ██║
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝  ╚════██║██║     ██╔══██║██║╚██╗██║
███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
```

**`[ PASSIVE WEB VULNERABILITY SCANNER ]`**

[![Python](https://img.shields.io/badge/Python-3.11-00ff41?style=for-the-badge&logo=python&logoColor=black&labelColor=0d1117)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-00ff41?style=for-the-badge&logo=flask&logoColor=black&labelColor=0d1117)](https://flask.palletsprojects.com)
[![PostgreSQL](https://img.shields.io/badge/Neon-PostgreSQL-00ff41?style=for-the-badge&logo=postgresql&logoColor=black&labelColor=0d1117)](https://neon.tech)
[![Render](https://img.shields.io/badge/Backend-Render-00ff41?style=for-the-badge&logo=render&logoColor=black&labelColor=0d1117)](https://render.com)
[![Netlify](https://img.shields.io/badge/Frontend-Netlify-00ff41?style=for-the-badge&logo=netlify&logoColor=black&labelColor=0d1117)](https://netlify.com)
[![License](https://img.shields.io/badge/License-MIT-00ff41?style=for-the-badge&logoColor=black&labelColor=0d1117)](LICENSE)

<br/>

> *"Know your weaknesses before the adversary does."*

</div>

---

## `> OVERVIEW`

**SecureScan** is a passive web vulnerability scanner that audits any public-facing URL for common security misconfigurations — no active exploitation, no traffic floods. Just clean, structured findings delivered through a slick dark-mode UI.

Designed for developers, security researchers, and bug bounty hunters who want fast security insights without spinning up a full pentest suite.

---

## `> THREAT DETECTION MODULES`

```
┌─────────────────────────────────────────────────────────────┐
│  MODULE                      CHECKS                         │
├─────────────────────────────────────────────────────────────┤
│  🛡️  Security Headers        Content-Security-Policy        │
│                               X-Frame-Options               │
│                               Strict-Transport-Security     │
│                               X-Content-Type-Options        │
│                               Referrer-Policy               │
├─────────────────────────────────────────────────────────────┤
│  🍪  Cookie Analysis         HttpOnly flag missing          │
│                               Secure flag missing           │
│                               SameSite attribute            │
├─────────────────────────────────────────────────────────────┤
│  💉  SQLi Error Detection    Database error leakage         │
│                               Stack trace exposure          │
├─────────────────────────────────────────────────────────────┤
│  🔀  Open Redirect           Redirect chain analysis        │
│                               Parameter-based redirects     │
├─────────────────────────────────────────────────────────────┤
│  🌐  Form Analysis           CSRF protection checks         │
│                               Input field enumeration       │
└─────────────────────────────────────────────────────────────┘
```

---

## `> ARCHITECTURE`

```
                     ┌─────────────────┐
         User ──────▶│  Netlify CDN    │
                     │   index.html    │
                     └────────┬────────┘
                              │  fetch() REST calls
                              ▼
                     ┌─────────────────┐
                     │  Render.com     │
                     │  Flask API      │◀──── Background scan threads
                     │  (Python 3.11)  │
                     └────────┬────────┘
                              │  psycopg2
                              ▼
                     ┌─────────────────┐
                     │  Neon (Serverless│
                     │  PostgreSQL)    │
                     │  scans+findings │
                     └─────────────────┘
```

---

## `> SEVERITY LEVELS`

| Badge | Level | Description |
|-------|-------|-------------|
| 🔴 `CRITICAL` | Immediate action required | Exploitable vulnerabilities with direct impact |
| 🟠 `HIGH` | Urgent fix needed | Significant security weaknesses |
| 🟡 `MEDIUM` | Should be addressed | Notable misconfigurations |
| ⚪ `INFO` | Informational | Best practice deviations |

---

## `> TECH STACK`

```python
stack = {
    "frontend"  : "Vanilla HTML / CSS / JS  →  Netlify",
    "backend"   : "Flask 2.3  +  Python 3.11  →  Render",
    "database"  : "PostgreSQL (Neon serverless)",
    "scanner"   : "requests + BeautifulSoup4 + lxml",
    "server"    : "gunicorn (production WSGI)",
    "cors"      : "flask-cors",
    "env"       : "python-dotenv",
}
```

---

## `> QUICK START`

### Prerequisites
```bash
python >= 3.11
postgresql (or a Neon account)
```

### 1 · Clone
```bash
git clone https://github.com/slokesh2905/securescan.git
cd securescan
```

### 2 · Install dependencies
```bash
pip install -r requirements.txt
```

### 3 · Configure environment
```bash
# Create a .env file in the project root
echo "DATABASE_URL=postgresql://user:pass@host/dbname?sslmode=require" > .env
```

### 4 · Launch
```bash
python app.py
# API listening on http://localhost:5000
```

### 5 · Open the UI
Open `index.html` in your browser (or serve it via any static server).

> Make sure `BASE_URL` in `index.html` points to your API host.

---

## `> API REFERENCE`

### `POST /scan`
Submit a URL for scanning.

```bash
curl -X POST http://localhost:5000/scan \
  -H "Content-Type: application/json" \
  -d '{"url": "https://target.example.com"}'
```

```json
{ "scan_id": 42 }
```

---

### `GET /results/<scan_id>`
Poll for scan results.

```bash
curl http://localhost:5000/results/42
```

```json
{
  "status": "done",
  "scan_id": 42,
  "url": "https://target.example.com",
  "created_at": "2026-05-27T09:41:00+00:00",
  "findings": [
    {
      "id": 1,
      "check_name": "Missing Content-Security-Policy",
      "severity": "high",
      "description": "No CSP header was detected...",
      "recommendation": "Add a Content-Security-Policy header..."
    }
  ]
}
```

**Status values:** `pending` · `done` · `error`

---

### `GET /health`
Uptime check.

```bash
curl http://localhost:5000/health
# {"status": "ok"}
```

---

## `> DEPLOYMENT`

### Backend → Render
| Setting | Value |
|---------|-------|
| Runtime | Python 3 |
| Build command | `pip install -r requirements.txt` |
| Start command | `gunicorn app:app` |
| Env var | `DATABASE_URL` = your Neon connection string |

### Database → Neon
1. Create a project at [neon.tech](https://neon.tech)
2. Copy the connection string
3. Set it as `DATABASE_URL` in Render's environment variables

### Frontend → Netlify
1. Update `BASE_URL` in `index.html` to your Render service URL
2. Drag-and-drop `index.html` at [netlify.com](https://netlify.com)

---

## `> PROJECT STRUCTURE`

```
securescan/
├── app.py              # Flask REST API + SSRF guard
├── models.py           # PostgreSQL persistence layer (psycopg2)
├── index.html          # Single-file frontend (HTML/CSS/JS)
├── requirements.txt    # Python dependencies
├── Procfile            # Render/gunicorn start command
├── .python-version     # Pins Python 3.11.9 for Render
├── .gitignore          # Excludes .env, __pycache__, *.db
└── scanner/
    ├── engine.py       # Orchestrates all scan modules
    ├── headers.py      # Security header checks
    ├── cookies.py      # Cookie flag analysis
    ├── forms.py        # Form & CSRF analysis
    ├── redirects.py    # Open redirect detection
    └── scope.py        # URL scope / SSRF guard helpers
```

---

## `> SECURITY NOTES`

- **Passive only** — SecureScan never modifies, writes to, or exploits target systems
- **SSRF protection** — Private IP ranges (RFC-1918, loopback, link-local) are blocked server-side
- **No auth storage** — Zero credentials or session data from scanned targets are persisted
- **Rate limiting** — Consider adding rate limiting before exposing to the public internet

---

## `> LICENSE`

```
MIT License — use freely, hack responsibly.
```

---

<div align="center">

**`[ SCAN. DETECT. SECURE. ]`**

*Built with 🖤 by [slokesh2905](https://github.com/slokesh2905)*

</div>
