# Risk-Adaptive Zero-Trust Security Architecture for Hybrid Cloud Infrastructure

A locally runnable, deployable research prototype of a zero-trust decision plane for hybrid
cloud environments. It continuously evaluates identity, device posture, behaviour and resource
context, converts them into a 0–100 risk score, and enforces one of four adaptive outcomes:
**Allow**, **Challenge**, **Restrict** or **Block**.

Everything runs on one host with SQLite and synthetic telemetry. No cloud account, external
service or production data is required.

---

## Quick start

### Windows

Double-click `start.bat`, or from a terminal:

```bat
start.bat
```

### macOS / Linux / WSL

```bash
chmod +x start.sh
./start.sh
```

### Manual

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python run.py --open
```

Open <http://127.0.0.1:8000/login>. The first launch creates `data/zerotrust.db`, seeds the demo
inventory, trains the behavioural model and stores a baseline evaluation run.

Useful launcher options:

```bash
python run.py --port 9000       # different port
python run.py --host 0.0.0.0    # expose on the LAN (local prototype only)
python run.py --reload          # auto-reload during development
python run.py --open            # open the browser automatically
```

---

## Demo identities

| Identity | Password | Role | MFA |
| --- | --- | --- | --- |
| `admin@hybridcloud.io` | `Admin#2026` | Security administrator | TOTP |
| `analyst@hybridcloud.io` | `Analyst#2026` | SOC analyst | TOTP |
| `dev@hybridcloud.io` | `Dev#2026` | Developer | TOTP |
| `finance@hybridcloud.io` | `Finance#2026` | Finance | TOTP |
| `contractor@hybridcloud.io` | `Guest#2026` | Contractor | TOTP |
| `svc-backup@hybridcloud.io` | `Service#2026` | Service account | Not enrolled |

The login page lists the same accounts; click one to fill the form. TOTP codes are shown only
inside the local console (Access console → **Get demo code**), because this prototype has no
enrolled phone. In a real deployment the code lives on the authenticator.

The admin console is available only to the security administrator.

---

## What the prototype covers

| Project objective | Where it lives |
| --- | --- |
| Hybrid cloud topology | Architecture page; private data-centre and public-cloud trust zones |
| Identity and least privilege | Login, PBKDF2-SHA256, session tokens, role and resource policies |
| Behavioural anomaly detection | IsolationForest over nine contextual features plus rule floors |
| Risk-adaptive decisions | Six weighted signals + policy escalation → Allow / Challenge / Restrict / Block |
| Monitoring and response | Live dashboard, filterable event log, alert triage, CSV export |
| Controlled attack simulation | Twelve MITRE-mapped scenarios executed inside the local process |
| Quantitative evaluation | Accuracy, precision/recall, FPR/FNR, latency, auth overhead, availability |
| Architecture design | Interactive reference topology and request lifecycle |

### Pages

- **Trust overview** — estate counts, decision mix, risk distribution, open alerts, recent decisions.
- **Access console** — choose an identity, device, resource and request context; inspect the
  decision, signal contributions, anomaly attributions and matched policies. Step-up MFA
  re-evaluates the request in place; Allow/Restrict decisions can open a synthetic protected
  resource through the policy enforcement point.
- **Monitoring** — filter by decision, ground truth, scenario or identity; inspect full event
  context; acknowledge alerts; export the current page to CSV.
- **Attack simulation** — run any of the twelve scenarios with one to five labelled variants, or
  generate normal traffic. The full evaluation button runs the labelled corpus and stores a run.
- **Evaluation** — confusion matrix, per-scenario outcomes, latency measurements, anomaly-model
  metrics, availability and browseable run history.
- **Architecture** — the reference topology, trust boundaries, control mapping and request lifecycle.
- **Administration** — identities, devices, resources, policy toggles, thresholds and model
  retraining (administrator only).

---

## How the decision engine works

Each request produces six signals, each normalised to a factor between 0 and 1 and weighted to
sum to 100 points:

| Signal | Weight | Examples |
| --- | --- | --- |
| Behavioural anomaly | 30 | IsolationForest score blended with contextual rule floors |
| Device posture | 20 | Managed, compliant, trust score, new device |
| Identity | 12 | Role, MFA state, recent failed logins, threat intel |
| Resource | 14 | Sensitivity and zone of the target |
| Request | 14 | Hour, request rate, egress volume |
| Session | 10 | Session age, concurrent sessions, geo-velocity |

The weighted score is raised by least-privilege policy violations (role, MFA, device-trust floor)
and hard controls can block immediately. Default bands:

- **Allow** — risk below 40
- **Challenge** — 40 to 59 (TOTP step-up, then re-evaluation)
- **Restrict** — 60 to 79 (read-only, masked fields, enhanced monitoring)
- **Block** — 80 or above, or a hard control

Every decision is stored with its signals, reasons, context and latency so that the evaluation
and monitoring views are grounded in real execution rather than hand-written numbers.

The behavioural detector is trained on a deterministic synthetic baseline of 1,200 normal
sessions. Contextual rules (impossible travel, high failed-login counts, request bursts, mass
egress, off-hours access, new devices) act as explainable floors so the prototype does not
depend on an opaque model alone.

---

## Attack simulations

All scenarios are local and authorised. They only submit synthetic context to the same risk
engine used by the access console; no packets are sent anywhere.

1. Impossible Travel
2. Credential Stuffing
3. Distributed Brute Force
4. Compromised Developer Endpoint
5. Insider Data Exfiltration
6. Privilege Escalation
7. MFA Fatigue
8. Rogue Service Account
9. Off-Hours Access Drift
10. Unmanaged Contractor Device
11. Lateral Movement
12. API Abuse / Key Misuse

Each scenario carries a MITRE ATT&CK technique, severity, ground-truth label and one to five
context variants. Results are tagged as attack traffic and can be compared with normal traffic.

---

## API

Interactive OpenAPI documentation is served at <http://127.0.0.1:8000/api/docs>.

Key endpoints:

```
POST /api/auth/login                 POST /api/auth/logout
GET  /api/auth/me                    GET  /api/auth/totp
GET  /api/context/inventory          GET  /api/topology
POST /api/access/evaluate            POST /api/access/challenge
POST /api/access/preview
GET  /api/events                     GET  /api/events/{id}
GET  /api/alerts                     POST /api/alerts/{id}/ack
GET  /api/dashboard
GET  /api/sim/scenarios              POST /api/sim/scenario
POST /api/sim/normal                 POST /api/sim/evaluation
GET  /api/evaluation/runs            GET  /api/evaluation/runs/{id}
GET  /api/admin/inventory            POST /api/admin/model/train
PUT  /api/admin/settings             POST /api/admin/policies/{id}/toggle
GET  /api/health
```

Authentication uses an HttpOnly, SameSite=Lax session cookie. API clients may also send the
token as `Authorization: Bearer <token>`.

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

Tests use a temporary data directory, so they never touch the demo database.

---

## Project structure

```
app/
  main.py          FastAPI pages, APIs, auth and security headers
  config.py        Paths, thresholds, weights, PBKDF2 work factor
  database.py      SQLite schema, settings and helpers
  security.py      PBKDF2-SHA256, HS256 session tokens, TOTP
  seed.py          Demo identities, devices, resources and policies
  anomaly.py       IsolationForest baseline, scoring and explanations
  risk.py          Six-signal risk engine, policy escalation, challenges
  simulator.py     Normal traffic and twelve attack scenarios
  evaluation.py    Labelled evaluation, metrics and stored runs
  templates/       Jinja2 pages
  static/          CSS, vanilla JS and the shield icon
data/              Runtime database, model and signing key (git-ignored)
docs/              Architecture and evaluation notes
tests/             Focused API and engine tests
run.py             Local launcher
start.bat/start.sh Convenience launchers
```

---

## Security and deployment notes

This is a research prototype, not a hardened production service.

- All telemetry, identities, resources and records are synthetic.
- Passwords use PBKDF2-SHA256 with 120,000 iterations. The signing key is generated locally in
  `data/signing.key` (or supplied with `ZT_SESSION_SECRET`).
- Login attempts are throttled: five failures within five minutes lock the account temporarily.
- Step-up challenge state is held in memory, so the app must run as a single worker. Do not run
  multiple Uvicorn workers with this prototype.
- Cookies are HttpOnly and SameSite=Lax but not `Secure`, because the default deployment is
  plain HTTP on localhost. Terminate TLS in front of the app before exposing it.
- The app sets a strict Content-Security-Policy (`script-src 'self'`), HSTS is left to the
  reverse proxy, and admin APIs check `is_admin` server-side.

For a production deployment, replace SQLite with a shared database, move challenge state and
sessions to Redis or another shared store, use a managed IdP for TOTP/WebAuthn, put TLS and an
authenticating reverse proxy in front of the app, and forward events to a SIEM.

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design, trust boundaries, data model and API.
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — evaluation methodology, metric definitions and
  how to interpret the reported numbers.
