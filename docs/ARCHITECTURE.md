# Architecture

## 1. Purpose and scope

This prototype implements the architecture described in the project brief: a shared policy
plane that removes implicit trust from a hybrid cloud estate. It is a **single-host research
prototype**. The private data centre and public cloud are represented as explicit trust zones in
one SQLite inventory rather than separate cloud subscriptions, so the complete decision path can
be reproduced without credentials, billing or network access.

The design goals are:

1. Every request is authenticated and authorised on its own context.
2. Access is least-privilege and tied to the target resource.
3. Behaviour is scored continuously rather than only at login.
4. Risk maps to an adaptive outcome, not a binary allow/deny.
5. Every decision is explainable and stored for audit and evaluation.
6. The whole system runs locally and deterministically.

## 2. Component view

```
                       ┌──────────────────────────────────────────┐
 Users / devices ─────▶ │  Console (Jinja2 + vanilla JS)           │
 Services              │  login · access · monitoring · simulation│
                       │  evaluation · architecture · admin       │
                       └───────────────┬──────────────────────────┘
                                       │ JSON APIs (HttpOnly session cookie)
                       ┌───────────────▼──────────────────────────┐
                       │  FastAPI application (app/main.py)        │
                       │                                           │
                       │  Auth ──▶ PBKDF2 / HS256 / TOTP           │
                       │  PDP  ──▶ risk.py                         │
                       │  PEP  ──▶ /api/access/preview             │
                       │  Telemetry ──▶ events / alerts / eval     │
                       └───────┬───────────────────┬──────────────┘
                               │                   │
                    ┌──────────▼─────────┐  ┌──────▼──────────────┐
                    │ anomaly.py          │  │ SQLite              │
                    │ IsolationForest     │  │ users, devices,     │
                    │ + contextual rules  │  │ resources, policies,│
                    │                     │  │ events, alerts,     │
                    │ model on disk       │  │ eval_runs, settings │
                    └─────────────────────┘  └─────────────────────┘
```

### Policy Decision Point (PDP)

`risk.evaluate()` is the PDP. It loads the identity, device, resource and enabled policies,
normalises the request context, asks the anomaly model for a score, computes six weighted
signals, applies policy escalation and hard controls, and persists the event.

### Policy Enforcement Point (PEP)

`/api/access/preview` is the PEP. It checks the **stored** decision for the referenced event and
returns synthetic resource records only for `ALLOW` (full) or `RESTRICT` (read-only, masked).
`CHALLENGE` and `BLOCK` are refused. This split makes the enforcement boundary explicit instead
of letting the UI decide what to show.

### Trust zones

| Zone | Examples | Characteristics |
| --- | --- | --- |
| Private data centre | `identity-provider`, `finance-db`, `k8s-prod`, `vpn-gateway` | Higher sensitivity, stricter device-trust floors |
| Public cloud | `api-gateway`, `analytics-lake`, `backup-vault` | Internet-facing or data-egress risk |

The link between zones is modelled as a managed VPN tunnel with mTLS. The prototype does not
simulate packet transport; it evaluates the authorisation decision that would precede it.

## 3. Identity and session design

- Passwords are hashed with **PBKDF2-HMAC-SHA256**, 120,000 iterations, 16-byte salt, stored as
  `pbkdf2_sha256$iterations$salt$hash`.
- Login compares hashes in constant time. Five failures within five minutes temporarily lock
  the identity; failures since the last successful login are counted.
- Sessions are signed HS256 tokens with `sub` (user id), `iat`, `exp` and a random `jti`,
  delivered as an **HttpOnly, SameSite=Lax** cookie. The signing key is generated locally under
  `data/signing.key` or supplied via `ZT_SESSION_SECRET`.
- TOTP step-up uses RFC 6238 (30-second period, 6 digits, ±1 step tolerance). Interactive demo
  identities have secrets enrolled; the service account deliberately does not.
- Admin routes and APIs require `is_admin` on the server, not just a hidden navigation link.

## 4. Behavioural anomaly detection

`anomaly.py` trains an **IsolationForest** on a deterministic synthetic baseline of normal
sessions (1,200 by default, seed 7). Nine features are used:

| Feature | Rationale |
| --- | --- |
| `hour` | Working-hours deviation |
| `requests_last_5m` | Request bursts / automation |
| `geo_distance_km` | Distance from the Bengaluru baseline |
| `failed_attempts_24h` | Credential attacks |
| `device_trust` | Device posture |
| `bytes_out_mb` | Exfiltration |
| `session_minutes` | Long-lived sessions |
| `sensitivity` | Target criticality (1–4) |
| `new_device` | Unrecognised fingerprint |

The raw isolation score is calibrated so a higher value means more anomalous, then combined with
**contextual rule floors**: impossible travel (≥1,500 km and ≥3,000 km), failed logins ≥ 6,
requests ≥ 40 per five minutes, egress ≥ 250 MB, off-hours access and new devices. The maximum
of the model score and any matching floor becomes the behaviour score.

Each result includes the top z-score attributions (`feature`, observed value, baseline, σ), which
the console shows as "Baseline deviation". This keeps the detector explainable even though the
underlying model is unsupervised.

The trained model is stored at `data/behaviour_model.joblib`; `/api/admin/model/train` retrains
and replaces it without a restart.

## 5. Risk scoring

For each of six signals, a factor in `[0, 1]` is multiplied by a weight. The default weights sum
to 100:

| Signal | Weight | Main inputs |
| --- | --- | --- |
| Behaviour | 30 | Anomaly score |
| Device | 20 | Trust, managed, compliant, new device |
| Identity | 12 | Status, MFA verification, privileged/service role |
| Resource | 14 | Sensitivity classification |
| Request | 14 | Hour, failures, rate, distance, country, threat intel |
| Session | 10 | Concurrent sessions, duration, new device |

`base_risk = Σ(factor × weight)`, rounded to one decimal. Policies can then add escalation
points:

- Role not permitted by a category-specific policy: **+18**, minimum **Restrict**
- MFA required but not verified: **+20**, minimum **Challenge**
- Device trust below the policy floor: **+15**, minimum **Challenge**

Hard controls override the band entirely:

- Suspended identity → **Block**
- Device trust < 20 → **Block**
- Threat intelligence `malicious` → **Block**

Final risk is capped at 100. Bands are configurable in the admin console:

| Risk | Outcome | Enforcement |
| --- | --- | --- |
| < 40 | Allow | Full access |
| 40–59 | Challenge | TOTP step-up; request re-evaluated on success |
| 60–79 | Restrict | Read-only, masked fields, enhanced monitoring |
| ≥ 80 | Block | Denied; session terminated; alert raised |

Thresholds must satisfy `allow_max < challenge_max < restrict_max`, so a configuration mistake
cannot create an unreachable band.

### Step-up flow

A `CHALLENGE` persists the event and creates an in-memory challenge token valid for 180 seconds.
`POST /api/access/challenge` verifies the TOTP, marks the token used, sets `mfa_verified = true`
in the stored context, re-evaluates, and updates the event's decision and reasons. The re-scored
result can therefore *recover* from Challenge to Allow if the remaining risk is low, or remain
elevated if other signals are still bad. Challenge tokens are single-use and are not persisted;
this is why the prototype must run with one worker.

## 6. Data model

```
users(id, name, email, password_hash, role, department, status, is_admin,
      mfa_secret, mfa_enabled, created_at)
devices(id, user_id, name, kind, os, managed, compliant, trust_score,
        fingerprint, last_seen)
resources(id, name, zone, service, category, sensitivity, owner, description)
policies(id, name, description, resource_category, required_device_trust,
         mfa_required, allowed_roles, effect, enabled)
events(id, ts, user_id, device_id, resource_id, action, decision, risk_score,
       anomaly_score, base_risk, signals, reasons, context, source_ip, geo,
       latency_ms, ground_truth, scenario, outcome)
alerts(id, ts, severity, title, detail, event_id, status)
eval_runs(id, ts, name, samples, metrics, config, duration_ms)
settings(key, value)
login_attempts(id, email, ts, success, source_ip)
```

`signals`, `reasons`, `context` and `metrics` are JSON text. Keeping the full decision payload
means the monitoring and evaluation views do not need to re-run the engine to explain history.

## 7. Traffic sources

- **Live console** requests are persisted with `scenario = 'live'` and `ground_truth = 0`.
- **Simulator** scenarios are persisted with `ground_truth = 1`, a scenario id and a MITRE
  technique. Each run creates one to five variants with deterministic context perturbations.
- **Normal traffic** is generated from role-appropriate resources/devices with realistic
  working hours, benign geos and low request rates; ground truth `0`.
- **Evaluation** runs the same generators with `persist = False`, so metrics do not contaminate
  the operational event log. A single summary row is stored in `eval_runs`.

Startup seeds 80 normal events only if the event table is empty, then stores a baseline
evaluation run if none exists.

## 8. Security headers and browser policy

The app sets:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
  img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: geolocation=(), microphone=(), camera=()
Cache-Control: no-store  (API responses)
```

There are no inline scripts or event-handler attributes. All JavaScript is loaded from
`/static/js/` and attaches listeners with `addEventListener`.

## 9. Production gaps

A real deployment would need:

- an external IdP with WebAuthn/passkeys and device attestation;
- a shared policy store and a shared cache for challenge/session state;
- TLS termination, HSTS and an authenticating reverse proxy;
- a relational database with backups, migrations and row-level audit;
- an actual enforcement layer (service mesh, API gateway, VPN policy) rather than synthetic
  resource records;
- SIEM/log forwarding, alert deduplication and on-call integration;
- multi-worker operation with distributed state.

These are intentionally out of scope for the local prototype; the seams are called out in the
code so they can be replaced without redesigning the decision logic.
