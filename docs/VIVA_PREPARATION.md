# Viva preparation

Answers describe what the code in this repository does. Numbers come from
`docs/FINAL_EVALUATION.md` (measured on 2026-11-12).

## 1. Two-minute explanation

Zero Trust means no request is trusted because of where it comes from; every access is verified
against identity, device and context. Our project is a locally runnable prototype of the decision
plane for a hybrid cloud. A FastAPI application plays three roles: an identity provider (password
login, signed sessions, TOTP step-up), a Policy Decision Point that scores every request, and a
Policy Enforcement Point that only releases a resource if the stored decision allows it.

The PDP combines six weighted signals into a 0–100 risk score: behaviour (an Isolation Forest
anomaly score over nine features such as login hour, request rate, distance from home and data
egress), device posture, identity assurance, resource sensitivity, request context and session
context. Organisational policies add escalation points and minimum decisions, and hard controls
block malicious IPs, suspended identities and very low device trust. The result is Allow,
Challenge (step-up MFA), Restrict (read-only) or Block, with ranked reasons.

The private and public cloud are simulated as zones in a SQLite inventory, and attacks are
simulated by 12 labelled scenarios. On 176 evaluation requests the engine detected all 36
attacks, contained 30 of them, and raised 13 false positives on 140 normal sessions (accuracy
92.6 %, FPR 9.3 %), at about 13.5 ms per decision on one machine.

## 2. Five-minute explanation

1. **Problem.** Perimeter security trusts the network; hybrid estates have no single perimeter.
   NIST SP 800-207 describes Zero Trust, but turning behaviour into concrete access decisions
   and measuring the result is the gap our literature survey identified.
2. **Architecture.** One FastAPI process with SQLite. IdP functions in `security.py` (PBKDF2
   passwords, HS256 tokens with a `jti`, TOTP). PDP in `risk.py`. Anomaly model in
   `anomaly.py`. PEP is `/api/access/preview`. Simulator and evaluation in `simulator.py` and
   `evaluation.py`. Pages for dashboard, access console, monitoring, simulation, evaluation,
   architecture and administration.
3. **Behaviour model.** An Isolation Forest (180 trees) trained on 1,200 synthetic normal
   sessions. Scores are normalised to 0–1; the 95th percentile of the baseline (0.786) is the
   anomaly threshold. Contextual rules can only raise the score (for example impossible travel).
   Z-scores against the baseline explain which features were unusual.
4. **Risk and decisions.** Weighted sum of six signals, plus policy escalation (role not
   allowed +18 and at least Restrict; MFA required but not done +20 and at least Challenge;
   device below policy trust +15 and at least Challenge), thresholds 40/60/80 and hard blocks.
5. **Security engineering we added** (Phases 2–2.2): server-side session revocation, MFA
   attempt limits, TOTP replay prevention, challenges bound to user and session and stored in
   SQLite, identity taken from the session not the request body, actor attribution, role-based
   visibility, AES-256-GCM encryption of TOTP secrets, separation of simulated and real MFA,
   validated inputs and sanitised errors, multi-worker safe start-up.
6. **Evaluation.** 140 normal sessions + 12 scenarios × 3 variants. Engine: recall 1.0,
   precision 0.735, F1 0.847, FPR 0.093. Anomaly detector alone: precision 0.706, FPR 0.107.
   Two scenarios (insider exfiltration, off-hours drift) are only challenged. 439 automated
   tests pass.
7. **Limits.** Synthetic data, simulated attacks and zones, SQLite on one host, local key file,
   no real network enforcement; not production-ready.

## 3. Ten-minute demonstration sequence

| Time | Action | Point to make |
| --- | --- | --- |
| 0:00 | Login page, sign in as Rohan (developer) | demo identities, throttled login, HttpOnly session |
| 0:45 | Dashboard | non-SOC users see only their own decisions |
| 1:30 | Demo A: dev-vm-01 → dev-vm-01, clean context → **Allow**, Open resource | six signals, policy match, PEP releases data |
| 3:00 | Sign in as Priya; Demo B: finance-db from Mumbai, MFA off → **Challenge** | policy escalation +20, risk-triggered step-up |
| 4:00 | Three wrong codes → cancelled (429) | attempt limit; challenge bound to session; replay protection |
| 5:00 | Sign in as Aisha (analyst); Attack simulation → Insider Data Exfiltration | labelled scenario, anomaly 1.00, decision Challenge |
| 6:00 | Access console as Aisha for Priya, same context → **Simulate MFA success** | simulation never touches Priya's real MFA |
| 7:00 | Contractor unmanaged laptop → internal-wiki → **Restrict**; malicious IP → **Block** | device trust, hard controls |
| 8:00 | Monitoring: event detail, Initiated by, Mode; Export CSV; Ack an alert | audit attribution, triage limited to SOC |
| 9:00 | Evaluation page: confusion matrix, latency, per-scenario table | measured results and their limits |
| 9:40 | Architecture page | zones are simulated inventory, logical IdP/PDP/PEP |

## 4. Likely questions and answers

**1. What is Zero Trust, and how does your project apply it?**
Zero Trust removes implicit trust based on network location or asset ownership and evaluates each
access request on identity, device and context (NIST SP 800-207). In our prototype every request
to a resource goes through `POST /api/access/evaluate`; nothing is allowed because the client is
"inside". Even an administrator gets Challenge or Block if the context is risky.

**2. What are the PDP and PEP in your system?**
The Policy Decision Point is `risk.evaluate()`, called by `/api/access/evaluate`; it computes the
risk score and decision and stores the event. The Policy Enforcement Point is
`/api/access/preview`: it looks up the stored decision and returns full records for Allow,
masked read-only records for Restrict, and 403 for Challenge or Block. Both are logical roles
inside one process; there is no separate gateway.

**3. How is identity and access management implemented?**
Passwords are PBKDF2-SHA256 with 120,000 iterations and a random salt. Login issues an HS256
token (`sub`, `iat`, `exp` 8 h, random `jti`) in an HttpOnly SameSite=Lax cookie. Six roles exist;
`is_admin` guards administration APIs; only `security_admin` and `analyst` may act for another
identity or run simulations. The acting user always comes from the session, never from the
request body.

**4. How does logout work if the token is a self-contained JWT-style token?**
A signed token stays valid until it expires, so logout writes its `jti` to `revoked_sessions`
until the token's `exp`. Every authenticated request checks that table, so a copied cookie or
Bearer token stops working immediately after logout. Rows are purged once the token would have
expired anyway.

**5. Why Isolation Forest?**
It is unsupervised, so it only needs examples of normal behaviour, which is what we can model;
it handles mixed-scale numeric features and trains in under a second on 1,200 samples (0.29 s measured). It
isolates unusual points with few random splits, so anomalies get short path lengths. We use
scikit-learn's implementation with 180 trees.

**6. What are the nine behavioural features?**
Login hour, requests in the last 5 minutes, distance from the home location in km, failed logins
in 24 h, device trust score, egress volume in MB, session duration in minutes, resource
sensitivity level (1–4), and a new-device flag.

**7. Where does the training data come from?**
`anomaly.baseline_samples()` generates 1,200 synthetic normal sessions from seeded distributions
(office hours with some early shifts, travel to a second office, some older devices). It is not
real user data, which is our largest validity limitation.

**8. How is the anomaly threshold chosen?**
Raw scores are normalised to 0–1 using the 1st and 99th percentiles of the training scores. The
threshold is the 95th percentile of the normalised training scores, clipped to 0.35–0.85; with
the default seed it is 0.786. Contextual rules can raise a score to a floor (for example 0.80 for
travel ≥ 1,500 km) but never lower it.

**9. How is the risk score calculated?**
Six factors between 0 and 1 (behaviour, device, identity, resource, request, session) are
multiplied by weights 30, 20, 12, 14, 14, 10 (normalised to 100) and summed. Policies then add
escalation points: +18 when the role is not permitted (minimum Restrict), +20 when MFA is required
but not verified (minimum Challenge), +15 when device trust is below the policy (minimum
Challenge). The score is capped at 100.

**10. How is the score mapped to a decision?**
Below 40 Allow, 40–60 Challenge, 60–80 Restrict, 80 and above Block. The decision is the stricter
of the band and the policy minimum. Hard controls force Block for a suspended identity, device
trust below 20 or a malicious source IP. Thresholds can be changed in the admin console.

**11. How does step-up MFA work?**
A Challenge creates a row in `mfa_challenges` holding only a SHA-256 hash of the challenge id,
bound to the subject, the acting user, a hash of the session id, device, resource and event,
valid 180 s. The answer is checked in one `BEGIN IMMEDIATE` transaction: wrong code increments
`failed_attempts` (third cancels, 429), correct code consumes the row once, and the request is
re-evaluated with `mfa_verified = true`.

**12. How do you prevent TOTP replay?**
TOTP accepts the current 30-second step and one either side. After a successful match we store the
matched step in `totp_counters` with a conditional UPSERT that only succeeds if the step is newer
than the last accepted one. The same code, or an older one still inside the window, is refused,
and two concurrent requests with the same code cannot both succeed.

**13. How are brute-force attacks on MFA limited?**
Three wrong codes cancel a challenge, and six wrong live codes for one identity within 15 minutes
pause verification for that identity (429 with Retry-After), so issuing new challenges does not
reset the budget. Password login has its own limit: five failures in five minutes.

**14. How are TOTP secrets protected?**
They are stored as AES-256-GCM ciphertext (`cryptography` library) with a random 96-bit nonce and
the user id as associated data, in the format `enc:v1:<key id>:<data>`. The key comes from
`ZT_MFA_ENCRYPTION_KEY` or `data/mfa.key`, never from the database. Start-up refuses to run with
a wrong or missing key rather than generating a new one. This protects a copied database file;
it is not a KMS or HSM.

**15. What is the difference between real and simulated MFA?**
A challenge raised when an operator evaluates another identity, or by the simulator, has mode
`simulation`. It can only be answered with a simulated outcome by the operator's session; it
never checks or consumes the subject's TOTP and never counts towards the subject's throttle.
This was added because operators' wrong codes used to lock real users out.

**16. How does role-based access to data work?**
`inventory_scope()` gives security administrators and analysts all identities, devices, events
and alerts (they need them for triage and simulation). Developers, finance, contractors and
service accounts see only their own identity, devices and events, and only resources whose
policies admit their role. Another user's event returns 404, and only SOC roles can acknowledge
alerts.

**17. What are your detection results?**
On 140 normal sessions and 36 attack requests: TP 36, FN 0, FP 13, TN 127. Accuracy 92.6 %,
precision 73.5 %, recall 100 %, F1 0.847, FPR 9.3 %. The anomaly detector alone has precision
70.6 % and FPR 10.7 %. Results were identical over three runs because the data is seeded.

**18. Why is the false-positive rate 9.3 %, and is a Challenge a false positive?**
We count any non-Allow decision on a normal session as a false positive, which is strict because a
Challenge only asks for MFA. Four are Restrict decisions where the traffic generator sends
analysts to `k8s-prod`, which policy reserves for administrators and developers. Nine are
Challenges with risk 40–48 caused by the upper tail of the normal generator (about 52 MB egress,
11 requests per 5 minutes). We did not tune thresholds to hide them.

**19. Does detection mean the attack was stopped?**
No. 30 of 36 attacks were contained (Restrict or Block). Insider exfiltration and off-hours drift
end in Challenge; an insider with a valid authenticator would pass. We report detection and
containment separately for this reason.

**20. Why is the data synthetic, and what does that mean for the results?**
We had no access to real enterprise authentication logs, and using them would raise privacy
issues. Synthetic seeded data makes results reproducible but optimistic: the model is trained and
evaluated on data from the same assumptions, attacks are hand-written patterns, and there is no
concept drift. The metrics show the design works as intended, not how it would perform in a real
organisation.

**21. Why SQLite?**
It needs no server, so the prototype runs anywhere with one command, and it gives real
transactions. We rely on its write lock (`BEGIN IMMEDIATE`, conditional updates) for single-use
challenges and replay protection across worker processes. It limits us to one host; a
production system would use a database server.

**22. How is the hybrid cloud modelled?**
Resources have a `zone` of `private` (identity provider, finance database, HR portal, wiki, dev VM,
Kubernetes, VPN gateway) or `public` (web, API gateway, analytics lake, ML training, backup
vault), with a category, sensitivity and owner. The zone appears in decisions and the
architecture page. No real network, VPC or cloud account exists; enforcement is the PEP returning
synthetic records.

**23. What are the main security limitations?**
Local key file next to the database; demo TOTP helper (off by default); no `Secure` cookie flag or
HSTS without a TLS proxy; SQLite on one host; synthetic data; the PEP is not an actual network
control; model retrain only updates the worker that handled it; old database backups from before
encryption still contain readable TOTP seeds on the development machine.

**24. How would you deploy this in production?**
Put the PDP behind an API gateway or service mesh that enforces decisions, use a managed IdP with
WebAuthn or passkeys, keep keys in a KMS or HSM, move to a database server, terminate TLS with
HSTS, forward events to a SIEM, train the model on real (privacy-reviewed) telemetry with drift
monitoring, and run the engine as several stateless instances.

**25. How do you know the system works?**
439 automated tests (unit, API, security negative tests, migration, concurrency with two
processes), a 52-check functional audit (`scripts/final_audit.py`), browser verification with
screenshots, and a reproducible evaluation script.

**26. What did you personally contribute?** *(answer in your own words)*
The Git history shows the Phase 2, 2.1, 2.2 and final-phase commits: session
revocation, anomaly-rule fix, MFA limits, replay protection, identity enforcement, challenge
binding and persistence, encryption of secrets, role-based visibility, simulated-MFA separation,
input validation, the multi-worker start-up fixes, tests and the final documentation.
