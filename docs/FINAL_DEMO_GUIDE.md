# Final demonstration guide

A step-by-step script for demonstrating the prototype to an examiner. Every expected result
below was checked in a real browser (headless Microsoft Edge) on a fresh database; the
screenshots in [`docs/evidence/`](evidence/) come from that run.

> **What the examiner is looking at.** A locally running zero-trust decision plane. The users,
> devices, "private cloud" and "public cloud" resources are synthetic records in SQLite;
> attacks are simulated by changing request context. Nothing connects to a real cloud.

## 1. Environment setup

| Requirement | Value |
| --- | --- |
| OS | Windows 10/11 (also works on macOS/Linux) |
| Python | 3.13.5 verified (3.11+ supported without `constraints.txt`) |
| Browser | any current Chromium, Edge or Firefox |
| Network | not needed after installing dependencies |

```powershell
# from the repository root
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt -c constraints.txt   # exact verified versions
python -m pytest -q                                                 # optional: 439 tests
python run.py --open
```

`start.bat` (Windows) or `./start.sh` does the same without the constraints file.

**Database initialisation is automatic.** On first start the app creates `data/zerotrust.db`,
seeds 6 identities, 10 devices, 12 resources and 11 policies, generates `data/signing.key` and
`data/mfa.key`, trains the behaviour model (`data/behaviour_model.joblib`), adds 80 normal
history events and stores a baseline evaluation. To start from a clean state, stop the server
and point it at a new folder rather than deleting files:

```powershell
$env:ZT_DATA_DIR = "$env:TEMP\zt-demo-data"   # fresh synthetic data for this terminal only
python run.py
```

| URL | Purpose |
| --- | --- |
| <http://127.0.0.1:8000/login> | sign-in page with one-click demo accounts |
| <http://127.0.0.1:8000/> | trust overview dashboard |
| <http://127.0.0.1:8000/api/docs> | interactive API documentation |
| <http://127.0.0.1:8000/api/health> | health check |

### Demo identities (synthetic, shown on the login page)

| Identity | Role | Password | Sees |
| --- | --- | --- | --- |
| Farhaan Pasha · admin@hybridcloud.io | security_admin | `Admin#2026` | everything, administration |
| Aisha Rahman · analyst@hybridcloud.io | analyst (SOC) | `Analyst#2026` | all identities, simulation, triage |
| Rohan Mehta · dev@hybridcloud.io | developer | `Dev#2026` | own identity and permitted resources |
| Priya Nair · finance@hybridcloud.io | finance | `Finance#2026` | own identity and permitted resources |
| Imran Khan · contractor@hybridcloud.io | contractor | `Guest#2026` | own identity, 3 resources |
| svc-backup@hybridcloud.io | service | `Service#2026` | own identity, 3 resources |

### Completing a real MFA challenge in a demo

The demo identities have no phone. To show a *successful* step-up, start the server with the
local demo helper, which reveals the current code to the signed-in user on loopback only:

```powershell
$env:ZT_ENABLE_DEMO_TOTP = "true"
python run.py
```

A **Get demo code** button then appears in challenge panels. Explain that this helper exists only
for the demonstration and is disabled by default. Never enable it on a shared machine.

## 2. Tour of the application (about 6 minutes)

1. **Login** (`01-login.png`): one-click demo accounts; wrong passwords show remaining attempts
   and five failures lock the e-mail for five minutes.
2. **Dashboard** (`16-dashboard-soc.png`): 24-hour decision counts, risk distribution, open alerts,
   latest evaluation metrics. Sign in as a non-SOC user to show the "own identity only" note
   (`02-dashboard-developer-own-scope.png`).
3. **Access console**: compose identity, device, resource and context; the result shows the
   decision, risk gauge, six signal contributions, reasons, matched policies and, for Allow or
   Restrict, the PEP button **Open resource**.
4. **Monitoring** (`12-monitoring.png`, `13-monitoring-event-detail.png`): filters, event detail with
   "Initiated by" and Live/Simulation mode, alert queue with **Ack** (SOC roles only), **Export CSV**.
5. **Attack simulation** (`09-simulation-insider-exfiltration.png`): 12 labelled scenarios, normal
   traffic, full evaluation. Only security_admin and analyst can run them.
6. **Evaluation** (`14-evaluation.png`): confusion matrix, precision/recall/F1, FPR/FNR, latency,
   authentication overhead, availability, per-scenario table, run history.
7. **Architecture** (`15-architecture.png`): live inventory drawn as private and public zones
   around the IdP/PDP/PEP boundary.
8. **Administration** (`17-administration.png`, admin only): identities, devices, resources,
   policies (toggle), thresholds and model retraining.

## 3. Demonstration scenarios

The access console fields are: Identity, Device posture, Requested resource, Source location,
Access hour, Requests / 5 min, Failed logins (24 h), Egress volume (MB), Session duration (min),
Concurrent sessions, Threat intelligence, **MFA completed this session**, **Unrecognised device**.

### A. Normal developer access

| Item | Value |
| --- | --- |
| Sign in as | Rohan Mehta (dev@hybridcloud.io), developer |
| Device | `dev-vm-01` (managed, compliant, trust 90) |
| Resource | `dev-vm-01 · medium · compute` (private zone) |
| Context | Bengaluru, hour 13, 5 requests / 5 min, 0 failed logins, 18 MB, 25 min, 1 session, Clean, MFA completed **on**, Unrecognised device **off** |
| Expected result | **Allow**, risk 9 (measured: anomaly 0.02, base 8.8, no escalation); **Open resource** returns full synthetic records |
| Evidence | `03-access-normal-allow.png`, `04-pep-resource-preview.png` |

What to demonstrate: the identity selector is locked to Rohan (a developer cannot evaluate
anyone else); the six signal bars are all low; the policy box shows "Developer compute
sandbox"; the PEP releases records with scope *full*.

What to explain: the PDP scored six signals and applied the policies matching the resource
category. The PEP only releases data because the stored decision is Allow. The event appears in
Monitoring with Rohan as both subject and actor.

### B. Suspicious login and MFA challenge

| Item | Value |
| --- | --- |
| Sign in as | Priya Nair (finance@hybridcloud.io), finance |
| Device | `PRIYA-LT-03` (trust 92) |
| Resource | `finance-db · critical · database` |
| Context | Source location **Mumbai, IN**, hour 13, other values as in A, MFA completed **off** |
| Expected result | **Challenge**, risk 58 (measured: anomaly 0.50, base risk 37.8, policy escalation +20) |
| Evidence | `05-access-suspicious-mfa-challenge.png`, `06-mfa-attempt-limit.png` |

What to demonstrate:

1. The reasons list the unusual distance from home and "Policy requires step-up MFA".
2. Enter `000000`, then `111111`, then `222222`: the first two say "attempt(s) remaining", the
   third cancels the challenge and disables the form (HTTP 429).
3. Evaluate again. With the demo helper enabled, press **Get demo code** and **Verify &
   re-evaluate**: the request is re-scored with MFA verified and the chip shows
   **Step-up verified**. Evaluate once more and press **Get demo code** within the same 30
   seconds: the console reports that the current code was already used (replay protection).

What to explain: step-up is risk-triggered, not always-on. The challenge is stored in SQLite as
a SHA-256 hash, bound to Priya, her session, device, resource and event, valid for 180 s and 3
attempts; 6 failures in 15 minutes pause verification for the identity. Each TOTP time step is
accepted once. Her TOTP seed is stored encrypted with AES-256-GCM.

### C. Simulated insider data exfiltration

| Item | Value |
| --- | --- |
| Sign in as | Aisha Rahman (analyst@hybridcloud.io), SOC analyst |
| Step 1 | Attack simulation → **Insider Data Exfiltration** → **Run scenario** |
| Scenario context | Priya · PRIYA-LT-03 → `analytics-lake` (medium, public zone), Singapore, 02:00, 40 requests / 5 min, 3 failed logins, 950 MB egress, 480-min session, 5 sessions, Suspicious IP, MFA completed |
| Expected result | **Challenge**, risk 58, anomaly score 1.00 for each variant (detected, not contained) |
| Step 2 | Access console: Identity **Priya Nair · finance**, the same device, resource and context |
| Expected result | **Challenge** with a **Simulated step-up authentication** panel instead of a code field |
| Step 3 | Press **Simulate MFA success** |
| Expected result | chip **Step-up simulated**; decision stays **Challenge** (risk 58) because MFA was already marked complete in this context |
| Evidence | `09-simulation-insider-exfiltration.png`, `10-access-simulated-exfiltration.png`, `11-simulated-step-up.png` |

What to demonstrate: the baseline-deviation chips (egress about 81σ above the baseline);
Monitoring → the events are labelled *Simulation*, initiated by Aisha, ground truth *attack*.

What to explain, honestly: this is one of the two scenarios that the engine only challenges.
The anomaly detector is certain (1.00), but a weighted sum of 58 stays below the Restrict
threshold of 60, and an insider with valid credentials and MFA would pass. This is a known
limitation recorded in `docs/FINAL_EVALUATION.md`. Simulations are answered with a simulated
outcome, so the analyst can never consume or lock Priya's real MFA.

### Extra one-step examples

| Goal | Identity → device → resource | Context change | Expected |
| --- | --- | --- | --- |
| Restrict (`07-access-restrict.png`) | Imran (contractor) → CONTRACTOR-LT-11 → internal-wiki | Chennai, hour 11, Unrecognised device **on** | Restrict, risk 71, read-only masked records |
| Block (`08-access-block.png`) | Aisha (analyst) → AISHA-LT-02 → internal-wiki | Threat intelligence **Malicious** | Block (hard control), no data released |
| Least-privilege visibility | Imran (contractor) → open the resource list | none | only hr-portal, internal-wiki and public-web are listed; the API returns only his own identity and two devices |

## 4. Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `py -3.13` not found | Install Python 3.13 from python.org, or use any 3.11+ and install without `-c constraints.txt`. |
| Port 8000 already in use | `python run.py --port 9000`, or stop the other server. |
| Login says "Too many failed attempts" | Five failures within five minutes lock that e-mail; wait 5 minutes or use another demo account. |
| No **Get demo code** button | Start with `$env:ZT_ENABLE_DEMO_TOTP = "true"` and open the site via `127.0.0.1` or `localhost`. |
| "Too many incorrect verification codes for this identity" | Six wrong codes in 15 minutes; wait for the Retry-After time. |
| "The current code was already used" | Each 30-second code is accepted once; wait for the next code. |
| Start-up error about the MFA encryption key | `data/mfa.key` is missing or different from the one that encrypted the database. Restore the backed-up key (or set `ZT_MFA_ENCRYPTION_KEY`) and restart; do not delete the database. |
| Changes in the browser not visible | Hard-refresh (Ctrl+F5); static files may be cached. |
| Want a clean demo | Use a new `ZT_DATA_DIR` folder (section 1) instead of deleting `data/`. |

Do not show or share anything inside `data/` during the demonstration: it holds the database,
the signing key and the MFA encryption key.
