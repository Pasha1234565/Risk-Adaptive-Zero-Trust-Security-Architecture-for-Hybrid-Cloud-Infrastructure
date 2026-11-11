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

#### Reproducible install

`requirements*.txt` pin only the direct dependencies. `constraints.txt` pins the whole tree
(including Starlette, Pydantic and SciPy) at the versions verified with the test suite on
CPython 3.13.5:

```bash
python -m pip install -r requirements-dev.txt -c constraints.txt
```

SciPy 1.18.1 needs Python 3.12 or newer; on Python 3.11 install without `-c constraints.txt`.

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

The login page lists the same accounts; click one to fill the form.

The admin console is available only to the security administrator.

### Step-up MFA and the local demo TOTP helper

A **Challenge** decision asks for a 6-digit TOTP code, verified by `POST /api/access/challenge`.
The demo identities have TOTP secrets but no enrolled phone, so the prototype includes a
*demonstration helper* (`GET /api/auth/totp`, the **Get demo code** button in the Access
console) that reveals the current code to the signed-in user.

That helper defeats the purpose of step-up MFA: anyone who knows a password could also pass the
second factor. It is therefore **disabled by default** and must be switched on explicitly:

```powershell
# PowerShell (current terminal only)
$env:ZT_ENABLE_DEMO_TOTP = "true"
python run.py
```

```bash
# macOS / Linux / WSL
ZT_ENABLE_DEMO_TOTP=true python run.py
```

Only `1`, `true`, `yes` or `on` enable it. When enabled:

- the endpoint answers only **direct loopback requests**: the TCP peer must be `127.0.0.1` or
  `::1`, the `Host` header must be a loopback name, and no proxy forwarding header
  (`Forwarded`, `X-Forwarded-For`, `X-Forwarded-Host`, `X-Real-IP`) may be present. Other
  clients get `403`;
- the console shows a **Demo MFA helper on · local only** badge and the **Get demo code** button;
- a warning is logged at startup.

When disabled, the endpoint returns `404` (as if it did not exist), it is omitted from the API
schema, and the Challenge panel asks for the code from an enrolled authenticator. TOTP
verification itself is unchanged. **Never enable the helper on a shared, LAN-exposed or real
deployment**; in production the code exists only on the user's authenticator.

Each 30-second code is accepted **once** (see below). If you request a demo code for a step that
has already been used, the helper says so and asks you to wait for the next code.

### Step-up verification rules

| Rule | Behaviour |
| --- | --- |
| Storage | Challenges are rows in the SQLite table `mfa_challenges`, shared by every worker process. Only SHA-256 hashes of the challenge id and of the session id are stored. Each verification runs in one `BEGIN IMMEDIATE` transaction with conditional updates, so concurrent answers (threads or processes) cannot both succeed or exceed the attempt limit. Rows are purged 24 h after expiry. |
| Lifetime | A challenge expires 180 s after it is issued (`CHALLENGE_TTL_SECONDS`). |
| Single use | A completed challenge cannot be used again. |
| Ownership | Only the **same user in the same session** that triggered the challenge may answer it. Another user, an administrator, or the same user in another session (including after logout) gets `400 Challenge expired or already used`, and such attempts do not count against the owner. |
| Attempts per challenge | 3 incorrect codes cancel the challenge (`429`); earlier failures return `400` with the attempts remaining. Default `ZT_MFA_MAX_ATTEMPTS=3`. |
| Attempts per identity | 6 incorrect codes within 15 minutes, across all of that identity's challenges, pause verification (`429` + `Retry-After`) until the oldest failure leaves the window. A success starts a new window. Defaults `ZT_MFA_USER_MAX_FAILURES=6`, `ZT_MFA_USER_WINDOW_SECONDS=900`. Password login is not affected and nothing locks permanently. |
| Replay | The matched TOTP time step is stored per user (`totp_counters`); a step that was already accepted, or an older one, is rejected even inside the ±1 step tolerance. Only counters are stored, never codes. |

Failed and successful verifications are recorded in `mfa_attempts` (identity, signed-in actor,
time, outcome, `live`/`simulation` mode; no codes).

### Simulated step-up (operators)

A challenge has a **mode**. It is `simulation` when an operator evaluates another identity or
the request comes from the attack/normal-traffic simulator, and `live` otherwise.

| | Live challenge | Simulation challenge |
| --- | --- | --- |
| Answer | `{"challenge_id", "code"}` (the subject's TOTP code) | `{"challenge_id", "simulated_outcome": "success" \| "failure"}` |
| Who may answer | the user and session that triggered it | the operator session that triggered it; `simulated_outcome` needs a simulation role (`403` otherwise) |
| Subject's TOTP counter / throttle | used | never touched |
| Attempt limit | 3 per challenge, 6 per identity per 15 min | 3 simulated failures per challenge |
| Wrong kind of answer | `400`, not counted | `400`, not counted |
| Recorded as | `mfa_attempts.mode = 'live'`, outcome `step_up_verified` | `mfa_attempts.mode = 'simulation'` with the operator as actor, outcome `step_up_simulated` |

Sending both or neither of `code` and `simulated_outcome` is `422`. Event APIs return a
computed `simulated` flag, and the access console shows **Simulate MFA success / failure**
buttons instead of the code field for simulation challenges.

### Who can evaluate whom

The access console and `POST /api/access/evaluate` always take the **actor** from the session.

| Role | Evaluate own identity | Evaluate another identity | Run `/api/sim/scenario`, `/api/sim/normal`, `/api/sim/evaluation` | Admin APIs |
| --- | --- | --- | --- | --- |
| `security_admin` | yes | yes (simulation) | yes | yes |
| `analyst` (SOC) | yes | yes (simulation) | yes | no |
| `developer`, `finance`, `contractor`, `service` | yes | no (`403`) | no (`403`) | no |

- `user_id` in the request body is optional and defaults to the signed-in user. Any other value
  from a role outside `config.SIMULATION_ROLES` is refused with `403` and nothing is recorded.
- The device must belong to the evaluated identity (`400` otherwise).
- Every stored event keeps the evaluated **subject** (`events.user_id`) and the **actor**
  (`events.actor_user_id`). Monitoring shows "Initiated by" and marks simulations. System
  traffic, and events recorded before this column existed, have no actor.
- A challenge raised by a simulation belongs to the operator's session and is answered with a
  simulated outcome, never with the subject's code (see above).
- For non-simulation roles the console's identity selector shows only the signed-in user, and the
  simulation page explains the restriction. The server rule is the control; the UI mirrors it.

### What each role can see

Visibility is enforced on the server (`inventory_scope` in `app/main.py`):

| Role | `/api/context/inventory` | Resources listed | Events, alerts, dashboard | Alert acknowledgement |
| --- | --- | --- | --- | --- |
| `security_admin` | every identity and device (`scope: "full"`) | all | all | yes |
| `analyst` (SOC) | every identity and device (`scope: "soc"`) | all | all | yes |
| `developer`, `finance`, `contractor` | own identity and devices (`scope: "self"`) | those whose enabled role-restricting policies admit the role | own identity only | no (`403`) |
| `service` | own identity and devices (`scope: "self"`) | same rule; no role-restricted policy names `service`, so only unrestricted categories (3 in the demo data) | own identity only | no (`403`) |

- Another identity's event is answered `404`, exactly like a missing one.
- Account flags, timestamps, policies and record counts stay in the admin-only
  `/api/admin/inventory`. No endpoint returns password hashes, MFA secrets, device fingerprints
  or session ids.
- `/api/topology` (resource names, zones and sensitivity for the architecture page) is still
  visible to every signed-in user; it contains no identities or devices.

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

Interactive OpenAPI documentation is served at <http://127.0.0.1:8000/api/docs>, and the
machine-readable schema at <http://127.0.0.1:8000/api/openapi.json>. FastAPI's default `/docs`,
`/redoc` and `/openapi.json` routes are disabled so there is one documented location. Swagger UI
is served from pinned local assets (`app/static/vendor/swagger-ui/`, see `VENDORED.md` there),
so the page works offline under the application's unchanged Content-Security-Policy.

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
token as `Authorization: Bearer <token>`. `GET /api/auth/totp` exists only when the demo TOTP
helper is enabled (see above).

`POST /api/auth/logout` revokes the session on the server: the token's `jti` is stored in the
`revoked_sessions` table until the token's own expiry, and every authenticated request checks
it. A copied cookie or Bearer token therefore stops working immediately after logout, while
other sessions of the same user are unaffected. Expired revocation rows are purged at startup
and on each logout.

Request validation: ids are limited to SQLite's INTEGER range (path ids must be at least 1),
numeric context fields are bounded and finite, enumerations (`threat_intel`, `geo`, `decision`,
`truth`, alert `status`, `scenario_id`, `simulated_outcome`) are checked, and unknown context
fields are refused. Invalid input is `422` with a readable message and field list, without
echoing the rejected values:

```json
{"detail": "Invalid request: event_id: Input should be a valid integer, unable to parse string as an integer",
 "errors": [{"loc": ["body", "event_id"], "msg": "Input should be a valid integer, ...", "type": "int_parsing"}]}
```

Unexpected server errors return `{"detail": "Internal server error"}` (with the security
headers); the traceback is written to the server log only.

---

## Tests

```bash
pip install -r requirements-dev.txt -c constraints.txt
pytest -q              # or: python -m pytest -q
```

`pytest.ini` puts the repository root on the import path, so both commands work from the
repository root. Tests use a temporary data directory, so they never touch the demo database.

---

## Project structure

```
app/
  main.py          FastAPI pages, APIs, auth and security headers
  config.py        Paths, thresholds, weights, PBKDF2 work factor
  database.py      SQLite schema, settings and helpers
  security.py      PBKDF2-SHA256, HS256 session tokens, TOTP
  mfa_crypto.py    AES-256-GCM encryption of TOTP secrets, key loading, migration
  keystore.py      Atomic creation of local key files (safe with several workers)
  seed.py          Demo identities, devices, resources and policies
  anomaly.py       IsolationForest baseline, scoring and explanations
  risk.py          Six-signal risk engine, policy escalation, challenges
  simulator.py     Normal traffic and twelve attack scenarios
  evaluation.py    Labelled evaluation, metrics and stored runs
  templates/       Jinja2 pages (including api_docs.html for Swagger UI)
  static/          CSS, vanilla JS, the shield icon and vendor/swagger-ui (pinned)
data/              Runtime database, model, signing key and MFA key (git-ignored)
docs/              Architecture and evaluation notes
tests/             API, engine, session, MFA, docs and hygiene tests
run.py             Local launcher
start.bat/start.sh Convenience launchers
pytest.ini         Test discovery and import path
constraints.txt    Verified versions of the full dependency tree
```

---

## Security and deployment notes

This is a research prototype, not a hardened production service.

- All telemetry, identities, resources and records are synthetic.
- Passwords use PBKDF2-SHA256 with 120,000 iterations. The signing key is generated locally in
  `data/signing.key` (or supplied with `ZT_SESSION_SECRET`).
- Login attempts are throttled: five failures within five minutes lock the account temporarily.
- Logout revokes the session server-side (`revoked_sessions`, keyed by the token `jti`).
- TOTP secrets are encrypted at rest with AES-256-GCM (see *MFA secret encryption* below).
- The demo TOTP helper is off by default (`ZT_ENABLE_DEMO_TOTP`) and loopback-only when on.
- Step-up challenges are owned by the requesting user and session, limited to 3 wrong codes per
  challenge and 6 per identity per 15 minutes, and each TOTP time step is accepted once.
- Access evaluation trusts only the session identity; acting for another identity and running
  simulations require the `security_admin` or `analyst` role, and the actor is audited.
  Simulated step-up never touches the subject's real MFA state.
- Identities, devices, events and alerts are visible by role (see *What each role can see*).
- Local environment files (`.env`, `.env.*`, `*.env`) are git-ignored; only `.env.example`
  may be committed.
- Challenges, revocations, TOTP counters and throttles are in SQLite, so several worker
  processes on **one host** sharing one database file work. This was tested with two separate
  Uvicorn processes on one database (`tests/test_challenge_persistence.py`) and with
  `uvicorn app.main:app --workers 2` on Windows (7 of 7 challenge lifecycles succeeded; with
  the earlier in-memory challenges 5 of 6 failed and a worker crashed during seeding).
  Start-up seeding, history bootstrap, the baseline evaluation and key-file creation are safe
  when workers start together.
  An admin model retrain only replaces the model in the worker that handled it; restart the
  workers afterwards.
- Cookies are HttpOnly and SameSite=Lax but not `Secure`, because the default deployment is
  plain HTTP on localhost. Terminate TLS in front of the app before exposing it.
- The app sets a strict Content-Security-Policy (`script-src 'self'`), HSTS is left to the
  reverse proxy, and admin APIs check `is_admin` server-side.

For a production deployment, replace SQLite with a shared database server, keep the MFA key in
a KMS or HSM, use a managed IdP for TOTP/WebAuthn, put TLS and an
authenticating reverse proxy in front of the app, and forward events to a SIEM.

### Security issues from the Phase 2 review

The four issues recorded after Phase 2 were addressed in Phase 2.1 and are covered by
regression tests:

| Issue | Status | Tests |
| --- | --- | --- |
| No attempt limit on step-up verification | Fixed: 3 per challenge, 6 per identity per 15 min | `tests/test_mfa_attempts.py` |
| Challenges not bound to the session user | Fixed: bound to user, session, device, resource and event | `tests/test_challenge_ownership.py` |
| TOTP replay within the ±1 step window | Fixed: per-user accepted-step counter, atomic in SQLite | `tests/test_totp_replay.py` |
| PDP trusted the identity in the request body | Fixed: session identity, simulation roles, actor audit | `tests/test_identity_enforcement.py` |

Cross-control negative tests are in `tests/test_security_negative.py`.

### Security issues addressed in Phase 2.2

| Issue | Status | Tests |
| --- | --- | --- |
| TOTP secrets stored in plaintext | Fixed: AES-256-GCM at rest, key outside the database, automatic migration | `tests/test_mfa_encryption.py` |
| Every user could list all identities, devices and events | Fixed: role-based visibility, own-records scope, triage limited to SOC roles | `tests/test_inventory_visibility.py` |
| Challenges in process memory (single worker only) | Fixed: `mfa_challenges` table with atomic updates; multi-worker start-up made safe | `tests/test_challenge_persistence.py` |
| Operator simulations consumed the subject's real MFA | Fixed: simulation challenges take simulated outcomes only | `tests/test_simulated_mfa.py` |
| Malformed requests returned 500 | Fixed: validation on every endpoint, sanitised 422 and 500 bodies | `tests/test_malformed_input.py` |

End-to-end checks across these controls are in `tests/test_phase22_cross_cutting.py`.

### MFA secret encryption and key backup

`users.mfa_secret` holds `enc:v1:<key id>:<base64url(nonce | ciphertext | tag)>`: AES-256-GCM
(`cryptography`), a random 96-bit nonce per value, and the user id as associated data, so a
ciphertext copied to another account does not decrypt. The key is never stored in the database.

| Source (first match wins) | Use |
| --- | --- |
| `ZT_MFA_ENCRYPTION_KEY` | base64url-encoded 32-byte key. Generate one with `python -m app.mfa_crypto generate-key`. |
| `ZT_MFA_KEY_PATH` (default `data/mfa.key`) | key file, git-ignored. Created automatically on first start **only** if the database has no encrypted secrets yet. |

- On start-up, plaintext secrets left by older versions are encrypted in one transaction
  (all or nothing; repeated starts change nothing).
- If the database has encrypted secrets and the key is missing or different, the app **refuses
  to start** with an explanatory error instead of generating a new key. A secret that cannot be
  decrypted at verification time returns `503` and does not count as a failed attempt. Keys and
  secrets are never logged or returned by an API.
- **Back up the key separately from the database.** Without it no enrolled authenticator can
  be verified, and a database backup alone cannot restore step-up MFA. To recover, restore the
  key file to `data/mfa.key` (or set `ZT_MFA_ENCRYPTION_KEY` to its content) and restart.
- Database backups taken **before** Phase 2.2 still contain plaintext secrets; delete or protect
  them.
- This is local key storage for a prototype: the key file sits on the same host as the database
  and is protected only by file-system permissions. It is not enterprise key management, and
  there is no key-rotation command yet (the key id in each value makes rotation possible).

### Known limitations

These remain true and are acceptable only for a local research prototype:

- **One host, one SQLite file.** Several workers are supported only on the same machine and
  file system; SQLite serialises writes, and an admin model retrain updates only the worker
  that handled it until the others restart.
- **Local key management.** The MFA key is a file next to the database (or an environment
  variable); there is no KMS, HSM or rotation tooling.
- **SOC roles see every identity.** Analysts and security administrators see all identities,
  devices and events, which their triage and simulation work needs.
- **Guessing is limited, not impossible.** With the defaults an attacker who already has a
  password gets at most 6 guesses per identity per 15 minutes, each with about a 3-in-a-million
  chance.
- **Demo-grade MFA.** TOTP remains the only second factor, and the optional demo helper reveals
  codes on loopback.
- **Transport and deployment.** No `Secure` cookie flag, no HSTS, SQLite, synthetic data, and no
  external IdP. The system is not production-ready.

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — design, trust boundaries, data model and API.
- [`docs/EVALUATION.md`](docs/EVALUATION.md) — evaluation methodology, metric definitions and
  how to interpret the reported numbers.
