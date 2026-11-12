# Final experimental evaluation

This document records the final measured results of the prototype. Every number below was
produced by running the project's own evaluation code (`app/evaluation.py`) and is stored in
[`docs/evidence/final_evaluation.json`](evidence/final_evaluation.json). Nothing was tuned for
this run: thresholds, weights, policies, the model and the generators are the defaults in the
repository.

> **Scope.** The behavioural baseline and all traffic are synthetic, attacks are simulated by
> changing request context inside one process, the hybrid-cloud resources are records in a
> local SQLite inventory, and every timing is a single-machine measurement. No packets are sent
> and no cloud infrastructure is involved.

## 1. How the run was produced

```bash
python scripts/final_evaluation.py docs/evidence/final_evaluation.json run1
```

The script creates a new temporary data directory, seeds the demo inventory, trains the model
exactly as the application does on first start, and calls
`evaluation.run_evaluation(normal_samples=140, variants=3, persist_run=False)`. It then re-runs
each scenario generator to record every variant's context and decision. It never reads or
writes `data/`.

| Item | Value |
| --- | --- |
| Evaluation date | 2026-11-12 01:48:54 UTC |
| Code | branch `final/submission-readiness` (Phase 2.2 code plus the WAL start-up fix) |
| Machine | Windows 11 (build 22631), AMD64 Family 25 Model 80 CPU, Python 3.13.5 |
| PBKDF2 work factor | 120,000 iterations (application default) |
| Normal sessions | 140, `simulator.run_normal(seed=2026)` |
| Attack requests | 12 scenarios × 3 variants = 36 |
| Total requests | 176 |
| Behaviour model | IsolationForest, 180 trees, 1,200 synthetic baseline sessions, contamination 0.04, seed 7 |
| Anomaly threshold | 0.7862 (95th percentile of the normalised baseline scores, clipped to 0.35–0.85) |
| Decision thresholds | Allow < 40 ≤ Challenge < 60 ≤ Restrict < 80 ≤ Block |
| Signal weights | behaviour 30, device 20, identity 12, resource 14, request 14, session 10 |
| Wall time of the evaluation | 2.94 s |

**Reproducibility.** The run was repeated three times on fresh data directories. All detection
metrics, confusion-matrix cells and decisions were identical in all three runs; only timings
varied (ranges are given in section 4).

## 2. Two different detectors

The prototype has two layers, and they are scored separately:

- **Anomaly detector (ML layer).** The IsolationForest score, normalised to 0–1, raised to a
  floor by contextual rules (for example impossible travel ≥ 1,500 km). A request is flagged
  when the score reaches the model threshold (0.7862). This layer does not decide anything on
  its own.
- **Risk engine (decision layer).** Combines the anomaly score with device, identity, resource,
  request and session signals, policy escalation and hard controls into a 0–100 risk score and
  one of Allow, Challenge, Restrict or Block.

For the risk engine, a request counts as **detected** when the decision is anything other than
Allow, and as **contained** only when it is Restrict or Block. A Challenge is a step-up
request: it is a detection, not a containment, because a user who passes MFA proceeds.

## 3. Detection results

### 3.1 Risk engine (overall decision)

|  | Predicted elevated (Challenge/Restrict/Block) | Predicted Allow |
| --- | --- | --- |
| **Actual attack (36)** | TP = 36 | FN = 0 |
| **Actual normal (140)** | FP = 13 | TN = 127 |

| Metric | Value |
| --- | --- |
| Accuracy | 0.9261 (92.6 %) |
| Precision | 0.7347 |
| Recall (detection rate) | 1.0000 |
| F1 | 0.8471 |
| False-positive rate | 0.0929 (13 of 140 normal sessions) |
| False-negative rate | 0.0000 |
| Containment rate (Restrict or Block) | 30 of 36 attacks = 83.3 % |
| Attacks answered only with Challenge | 6 of 36 = 16.7 % |

Decision counts over all 176 requests: Allow 127, Challenge 15, Restrict 10, Block 24.
Attacks: Block 24, Restrict 6, Challenge 6. Normal sessions: Allow 127, Challenge 9, Restrict 4.

### 3.2 Anomaly detector alone

|  | Flagged | Not flagged |
| --- | --- | --- |
| **Actual attack (36)** | 36 | 0 |
| **Actual normal (140)** | 15 | 125 |

Accuracy 0.9148, precision 0.7059, recall 1.0000, F1 0.8276, FPR 0.1071, FNR 0.0000.

The same numbers were obtained from the raw IsolationForest score without the rule floors: in
this corpus every attack variant already scored ≥ 0.973 on the forest alone, so no rule floor
changed a flag. The rules matter for explanations and for contexts outside this corpus, but
they did not change these metrics.

### 3.3 Where the false positives come from

All 13 risk-engine false positives were inspected:

| Decision | Count | Identity → resource | Cause |
| --- | --- | --- | --- |
| Restrict | 4 | analyst → `k8s-prod` | Least-privilege policy: "Production orchestration" admits only `security_admin` and `developer`, but the normal-traffic generator (`ROLE_CATEGORIES`) lets analysts request orchestration resources. +18 escalation points and a Restrict floor. |
| Challenge | 9 | security_admin (5), contractor (2), developer (1) on various resources | Risk 40.4–47.5, just above the Allow threshold of 40. Each had egress around 52–55 MB, about 11 requests per 5 minutes or 2 failed logins, the upper tail of the normal generator, which the anomaly score treats as unusual. |

The four Restrict results are a mismatch between the traffic generator and the policy table,
not a scoring error. Neither the generator nor the policies were changed for this evaluation,
so the numbers report the system as it is.

## 4. Performance

| Measurement | Run 1 | Range over 3 runs |
| --- | --- | --- |
| Decision latency, average | 13.57 ms | 13.47–13.57 ms |
| Decision latency, p50 | 13.52 ms | 13.33–13.52 ms |
| Decision latency, p95 | 13.92 ms | 13.74–14.10 ms |
| Decision latency, maximum | 15.93 ms | 15.93–21.68 ms |
| Authentication overhead (PBKDF2-SHA256, 120,000 iterations) | 48.36 ms | 48.36–50.99 ms |
| Protected-service latency (resource read + JSON) | 1.52 ms | 1.41–1.52 ms |
| Availability | 176 / 176 = 100 % | 100 % |

- Decision latency is time inside `risk.evaluate()` (database reads, model scoring, policy
  evaluation; evaluation traffic is not persisted).
- Authentication overhead is paid once per login, not per request.
- Availability counts requests that produced a decision without an engine exception; no faults
  were injected, so 100 % shows that no scenario crashed, not resilience under failure.
- The functional audit and test suite run with a reduced PBKDF2 work factor (1,000) for speed;
  the figures above use the real default.

## 5. The twelve attack scenarios

Ground truth is *attack* for every variant. Variant 1 uses the scenario's fixed context;
variants 2 and 3 scale request rate, failed logins and egress by a seeded random factor. Every
scenario fixes its hour, so results do not depend on the time of day of the run.

| # | Scenario (MITRE technique) | Subject · device → resource | Variant 1 context | Risk (v1/v2/v3) | Decision (all variants) | Detected | Contained |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Impossible Travel (T1078) | admin · iPhone 15 (personal) → identity-provider | London, 03:00, new device, suspicious IP, 3 sessions | 86.5 / 86.5 / 86.5 | Block | yes | yes |
| 2 | Credential Stuffing (T1110.004) | analyst · AISHA-LT-02 → internal-wiki | Singapore, 02:00, 65 req/5 min, 12 failed logins, MFA not done, new device | 78.0 / 78.0 / 78.0 | Restrict | yes | yes |
| 3 | Distributed Brute Force (T1110.001) | finance · PRIYA-LT-03 → hr-portal | Ashburn US, 02:00, 80 req/5 min, 14 failed logins, malicious IP | 86.8 / 86.8 / 86.8 | Block | yes | yes |
| 4 | Compromised Developer Endpoint (T1078 + T1021) | dev · ROHAN-LT-07 → k8s-prod | Bengaluru, 02:00, 480 MB egress, 6 failed logins, 4 sessions, suspicious IP | 86.1 / 85.8 / 85.7 | Block | yes | yes |
| 5 | Insider Data Exfiltration (T1567) | finance · PRIYA-LT-03 → analytics-lake | Singapore, 02:00, 950 MB egress, 480-min session, 5 sessions, MFA done | 57.8 / 57.8 / 57.8 | **Challenge** | yes | **no** |
| 6 | Privilege Escalation (T1078.004) | contractor · CONTRACTOR-LT-11 → k8s-prod | Chennai, 14:00, new device, clean IP | 100 / 100 / 100 | Block | yes | yes |
| 7 | MFA Fatigue (T1621) | analyst · AISHA-LT-02 → api-gateway | Chennai, 23:00, 8 failed logins, 8 sessions, MFA not done | 83.2 / 82.6 / 83.2 | Block | yes | yes |
| 8 | Rogue Service Account (T1078.004) | svc-backup · backup-runner-01 → backup-vault | Ashburn US, 02:00, 600 MB egress, malicious IP | 87.0 / 87.0 / 87.0 | Block | yes | yes |
| 9 | Off-Hours Access Drift (T1078) | analyst · AISHA-LT-02 → backup-vault | Bengaluru, 03:00, 80 MB egress, clean IP, MFA done | 48.7 / 49.3 / 49.3 | **Challenge** | yes | **no** |
| 10 | Unmanaged Contractor Device (T1200) | contractor · CONTRACTOR-LT-11 → internal-wiki | Chennai, 11:00, new unmanaged device (trust 38) | 71.0 / 70.9 / 71.1 | Restrict | yes | yes |
| 11 | Lateral Movement (T1021) | dev · ROHAN-LT-07 → finance-db | Bengaluru, 14:00, 25 req/5 min, clean IP | 89.5 / 88.2 / 89.2 | Block | yes | yes |
| 12 | API Abuse / Key Misuse (T1496) | dev · dev-vm-01 → api-gateway | Singapore, 02:00, 90 req/5 min, 200 MB egress, 6 sessions, MFA not done | 84.7 / 84.7 / 84.7 | Block | yes | yes |

Every variant's full context, anomaly score, isolation score and top reasons are in the JSON
evidence file.

**No false negatives occurred**, but two scenarios are only partially handled:

- **Insider Data Exfiltration** (risk 57.8) and **Off-Hours Access Drift** (48.7–49.3) end in
  Challenge. In both the subject has already completed MFA in the scenario context, so a
  real insider holding valid credentials and an authenticator would pass the step-up and be
  allowed. The anomaly score is at its maximum, but the weighted sum stays below the Restrict
  threshold of 60. These are the cases where the design (weights plus thresholds) is weakest.
- In the browser demonstration, recording a simulated MFA success on the exfiltration request
  re-evaluates it with `mfa_verified = true` and it remains **Challenge** (risk 58), because
  that flag was already true; this is shown in `docs/evidence/11-simulated-step-up.png`.

## 6. Interpretation

- Recall 1.0 and FNR 0 mean every simulated attack was at least challenged. With only 12
  hand-written patterns and seeded variants that differ little, this shows the patterns are
  covered, not that unseen attacks would be.
- Precision 0.73 and FPR 9.3 % are driven by two concrete causes (section 3.3): a
  generator/policy mismatch (4) and normal-tail sessions just over the Allow threshold (9).
- The anomaly detector and the risk engine flag the same 36 attacks; the engine has fewer false
  positives (13 versus 15) because device, identity and policy signals keep some anomalous but
  low-risk sessions at Allow, while policy rules add four false positives of their own.
- Decision latency of about 13.5 ms (p95 under 14.2 ms) on one machine is dominated by model
  scoring and SQLite reads. It excludes network, TLS and external identity-provider costs.

## 7. Threats to validity

The corpus is synthetic and seeded; the attack set is small and fixed; the anomaly model is
trained on the same kind of synthetic data it is evaluated against; thresholds are a single
operating point; and all timings come from one process on one laptop-class machine. See also
`docs/EVALUATION.md` section 8.
