# Evidence

Genuine outputs of the final validation run (2026-11-12). All data shown is the synthetic demo
inventory on a fresh, throw-away database; no keys, secrets or real personal data appear.

| File | Produced by | Shows |
| --- | --- | --- |
| `functional_audit.md` | `python scripts/final_audit.py` | 52 automated feature checks with expected and actual behaviour |
| `final_evaluation.json` | `python scripts/final_evaluation.py` | full evaluation metrics, every scenario variant, false positives |
| `01-login.png` | `scripts/final_screenshots.py` (headless Microsoft Edge) | sign-in page with demo accounts |
| `02-dashboard-developer-own-scope.png` | 〃 | developer dashboard limited to own identity |
| `03-access-normal-allow.png` | 〃 | demo A: developer → dev-vm-01, Allow (risk 9) |
| `04-pep-resource-preview.png` | 〃 | PEP releasing full synthetic records |
| `05-access-suspicious-mfa-challenge.png` | 〃 | demo B: finance → finance-db from Mumbai, Challenge (risk 58) |
| `06-mfa-attempt-limit.png` | 〃 | challenge cancelled after three wrong codes |
| `07-access-restrict.png` | 〃 | contractor unmanaged laptop, Restrict (risk 71) |
| `08-access-block.png` | 〃 | malicious source IP, Block |
| `09-simulation-insider-exfiltration.png` | 〃 | demo C: insider exfiltration scenario |
| `10-access-simulated-exfiltration.png` | 〃 | analyst replaying the scenario: simulation challenge panel |
| `11-simulated-step-up.png` | 〃 | simulated MFA success, labelled as simulated |
| `12-monitoring.png`, `13-monitoring-event-detail.png` | 〃 | event log and event detail with actor and mode |
| `14-evaluation.png` | 〃 | evaluation page (baseline run of that server) |
| `15-architecture.png` | 〃 | simulated private and public zones |
| `16-dashboard-soc.png`, `17-administration.png` | 〃 | SOC dashboard and administration |

The same browser run also verified the CSV export (25 rows with the expected header) and
recorded no page errors or Content-Security-Policy violations (15 checks passed).
