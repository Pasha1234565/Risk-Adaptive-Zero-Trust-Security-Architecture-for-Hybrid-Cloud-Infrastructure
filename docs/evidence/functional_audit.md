# Functional audit

Generated 2026-11-12T01:52:31+00:00 by `python scripts/final_audit.py` against the real FastAPI application (TestClient) on a new temporary data directory with synthetic demo data. PBKDF2 uses 1,000 iterations here for speed. `BROWSER` rows were verified in a real browser (see docs/FINAL_EVALUATION.md and docs/evidence/).

| Area | Feature | Test performed | Expected behaviour | Actual behaviour | Result |
| --- | --- | --- | --- | --- | --- |
| Authentication | Login | POST /api/auth/login with analyst demo credentials | 200, HttpOnly SameSite=Lax session cookie | 200; cookie HttpOnly=True, SameSite=Lax | PASS |
| Authentication | Invalid password | Login as finance with a wrong password | 401 with attempts remaining | 401 Invalid email or password. 4 attempt(s) remaining. | PASS |
| Authentication | Session creation | GET /api/auth/me with the new cookie | 200 with the analyst identity | 200, role=analyst, no hash in body | PASS |
| Authentication | Session expiry | Bearer token whose exp is in the past | 401 | 401 | PASS |
| Authentication | Logout and session revocation | Log out, then replay the copied token as Bearer | logout 200, replay 401, jti stored | logout 200; copied token -> 401; revoked rows=1 | PASS |
| Authentication | Login throttling | Six wrong passwords for dev, then the right one | 5 x 401, then 429 even with the right password | wrong x6 -> [401, 401, 401, 401, 401, 429]; correct password while locked -> 429 | PASS |
| MFA | TOTP verification | finance -> finance-db without MFA, answer with current TOTP | CHALLENGE, then 200 and re-evaluated | evaluate CHALLENGE (mode live); verify 200 -> ALLOW | PASS |
| MFA | TOTP replay prevention | Reuse the code just accepted on a new challenge | 400 (time step already used) | 400 Incorrect verification code. 2 attempt(s) remaining. | PASS |
| MFA | Failed-attempt limit | Four wrong codes on one challenge | 400, 400, 429 (cancelled), then 400 | statuses [400, 400, 429, 400]; row cancelled | PASS |
| MFA | Challenge ownership | Answer finance's challenge from another finance session and from admin | 400 generic, owner's count untouched | other session 400, admin 400, owner's failed_attempts=0 | PASS |
| MFA | Challenge expiry | Move expires_at into the past, then answer | 400, row marked expired | 400; row expired | PASS |
| MFA | Persistent challenge state | Issue a challenge and read mfa_challenges | row with hashed id, bound event, 180 s TTL | row in mfa_challenges (hashed id, event 86, TTL 180s) | PASS |
| MFA | Encrypted TOTP secrets | Inspect users.mfa_secret and raw DB bytes | all enc:v1, no plaintext seed in the files | 6/6 enc:v1, plaintext seeds in DB files: 0 | PASS |
| MFA | Real vs simulated MFA | Admin simulates finance; answer with a code, then simulated_outcome | simulation mode, code 400, outcome 200, subject untouched | mode simulation; code 400; outcome 200 (simulation); live failures for finance 0 | PASS |
| Identity and access | User roles | List seeded roles | 6 identities across 6 roles | analyst, contractor, developer, finance, security_admin, service | PASS |
| Identity and access | Device ownership | finance evaluates with the analyst's laptop | 400 | 400 Device does not belong to the selected user | PASS |
| Identity and access | Device trust | Contractor: managed laptop (72) vs unmanaged laptop (38) to internal-wiki | lower trust gives more device points and risk | trust 72: device pts 4.2 risk 14.5 ALLOW; trust 38: device pts 15.3 risk 49.9 CHALLENGE | PASS |
| Identity and access | Resource sensitivity | Admin laptop to a low vs a critical resource | critical resource adds more points | public-web (low) 2.1 pts; finance-db (critical) 14.0 pts | PASS |
| Identity and access | Policy restriction | Contractor to finance-db (database policy excludes contractor) | RESTRICT or BLOCK with least-privilege reason | RESTRICT risk 59.0; least-privilege reason: True | PASS |
| Identity and access | Admin permissions | Call /api/admin/inventory as analyst and admin; open /admin as finance | 403, 200, redirect 303 | analyst 403, admin 200, finance /admin page 303 | PASS |
| Identity and access | Inventory visibility | GET /api/context/inventory as contractor and analyst | contractor self/1/3; analyst soc/6 | contractor self: 1 user, 2 devices, 3 resources; analyst soc: 6 users | PASS |
| Identity and access | Identity spoofing | Contractor sends user_id=finance in the body | 403 | 403 | PASS |
| Risk engine | Six weighted signals / risk calculation | Analyst laptop to internal-wiki, clean context | 6 signals, weights 100, risk = points + escalation | signals ['behaviour', 'device', 'identity', 'resource', 'request', 'session']; weights sum 100.0; points+escalation 6.7 vs risk 6.7 | PASS |
| Risk engine | Policy escalation | finance-db without step-up MFA | escalation points and minimum decision CHALLENGE | escalation +20.0 -> CHALLENGE (base 24.5, risk 44.5) | PASS |
| Risk engine | Hard security control | Same routine request with threat_intel=malicious | BLOCK regardless of score | BLOCK risk 14.4 | PASS |
| Risk engine | Decision ALLOW | Analyst laptop -> internal-wiki, clean context | ALLOW | ALLOW (risk 6.7) | PASS |
| Risk engine | Decision CHALLENGE | finance laptop -> finance-db, MFA not yet verified | CHALLENGE | CHALLENGE (risk 44.5) | PASS |
| Risk engine | Decision RESTRICT | Contractor unmanaged laptop -> internal-wiki, new device | RESTRICT | RESTRICT (risk 70.9) | PASS |
| Risk engine | Decision BLOCK | Developer laptop -> k8s-prod at 02:00 with 480 MB egress | BLOCK | BLOCK (risk 86.1) | PASS |
| Risk engine | PEP enforcement | POST /api/access/preview for an ALLOW and a BLOCK event | full records for ALLOW, 403 for BLOCK | ALLOW event -> 200 full; BLOCK event -> 403 | PASS |
| Anomaly detection | Isolation Forest | Inspect the loaded model | sklearn IsolationForest, 180 trees | IsolationForest, n_estimators=180, trained on 1200 synthetic samples | PASS |
| Anomaly detection | Nine behavioural features | anomaly.FEATURES and model input width | 9 features | hour, requests_last_5m, geo_distance_km, failed_attempts_24h, device_trust, bytes_out_mb, session_minutes, sensitivity, new_device | PASS |
| Anomaly detection | Contextual rules | Admin access from London (about 8,000 km) | impossible-travel rule floor applied | rule hits ['geo_distance_km>=1500', 'geo_distance_km>=3000']; score 0.92 (isolation 0.5621) | PASS |
| Anomaly detection | Anomaly threshold | Model threshold (95th percentile of baseline, clipped 0.35-0.85) | value in [0.35, 0.85] | 0.7862 | PASS |
| Anomaly detection | Feature attribution | top_factors of the BLOCK decision | features with value, baseline and z-score | Egress volume (MB) z=39.97; Failed logins (24 h) z=9.2; Requests / 5 min z=6.82 | PASS |
| Anomaly detection | Model persistence | Reload the joblib model from disk | same threshold after reload | behaviour_model.joblib exists; reloaded threshold 0.7862 | PASS |
| Monitoring | Event log and actor attribution | Read the ALLOW event as admin | actor recorded, live event | event 96: actor Aisha Rahman, simulated=False | PASS |
| Monitoring | Alerts | BLOCK decision raises an alert | alert listed for the BLOCK event | open alerts 6; BLOCK event alerted | PASS |
| Monitoring | Alert acknowledgement | Acknowledge as finance, then as analyst | 403, then 200 | finance 403, analyst 200 | PASS |
| Monitoring | Filtering | GET /api/events?decision=BLOCK and an invalid decision | only BLOCK rows; invalid 422 | 3 BLOCK events, all BLOCK; invalid filter 422 | PASS |
| Monitoring | CSV export | Browser: click Export CSV on Monitoring | CSV download with event columns | Verified with scripts/final_screenshots.py: CSV file downloaded with the expected header and 25 rows | BROWSER |
| Attack simulation | All 12 attack scenarios | POST /api/sim/scenario for each scenario as admin | 12 x 200 with a decision | impossible_travel:BLOCK; credential_stuffing:RESTRICT; brute_force:BLOCK; compromised_device:BLOCK; insider_exfiltration:CHALLENGE; privilege_escalation:BLOCK; mfa_fatigue:BLOCK; rogue_service_account:BLOCK; off_hours_drift:CHALLENGE; unmanaged_contractor:RESTRICT; lateral_movement:BLOCK; api_abuse:BLOCK | PASS |
| Attack simulation | Normal traffic | POST /api/sim/normal count=10 as analyst | 10 evaluated sessions | 200, {'ALLOW': 8, 'CHALLENGE': 2, 'RESTRICT': 0, 'BLOCK': 0} | PASS |
| Attack simulation | Attack labels | Filter events truth=attack | ground_truth true and simulated flag set | 12 attack-labelled events, all ground_truth and simulated; normal events 90 | PASS |
| Attack simulation | Simulation authorisation | Run a scenario as finance and an evaluation as contractor | 403, 403 | finance scenario 403, contractor evaluation 403 | PASS |
| Attack simulation | Audit attribution | Actor of the scenario events | the admin who ran them | actor ids on attack events {1} (admin 1) | PASS |
| Evaluation | Detection metrics | POST /api/sim/evaluation (140 normal, 3 variants) | accuracy, precision, recall, F1, FPR, FNR | accuracy=0.9261, f1=0.8471, false_negative_rate=0.0, false_positive_rate=0.0929, precision=0.7347, recall=1.0 | PASS |
| Evaluation | Decision latency | latency block of the run | avg, p50, p95, max reported | decision_avg_ms=13.62, decision_p50_ms=13.48, decision_p95_ms=14.34, decision_max_ms=19.53 | PASS |
| Evaluation | Authentication overhead / service latency | latency block of the run | both measured | auth 0.408 ms (PBKDF2 1,000 iterations in this audit), service 1.554 ms | PASS |
| Evaluation | Availability | availability block of the run | 100% when no engine error | 176/176 = 100.0% | PASS |
| Evaluation | Stored runs | GET /api/evaluation/runs/{id} | same metrics as returned | run 2 retrieved: 200 | PASS |
| Interface | All pages | GET every page as admin; / anonymously | 200 each; anonymous redirected to /login | {'/': 200, '/access': 200, '/monitoring': 200, '/simulation': 200, '/evaluation': 200, '/architecture': 200, '/admin': 200, '/api/docs': 200}; anonymous / -> 303; /login 200 | PASS |
| Interface | Security headers | Headers on an API response | CSP, frame denial, no-store | CSP script-src 'self', X-Frame-Options DENY, nosniff, no-store | PASS |
