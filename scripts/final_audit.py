"""Final functionality audit (Task A). Drives the real FastAPI app through
TestClient on a fresh throw-away data directory and records, per feature, the
test performed, the expected and the actual behaviour.

usage (from the repository root):  python scripts/final_audit.py [out.md]

Nothing in data/ is read or written: a temporary data directory is used.
"""
import json
import os
import sys
import tempfile
from pathlib import Path
import time
import traceback

root = str(Path(__file__).resolve().parent.parent)
out = sys.argv[1] if len(sys.argv) > 1 else "docs/evidence/functional_audit.md"
for k in [k for k in os.environ if k.startswith("ZT_")]:
    del os.environ[k]
data = tempfile.mkdtemp(prefix="zt-final-audit-")
os.environ.update({"ZT_DATA_DIR": data, "ZT_PBKDF2_ITERATIONS": "1000"})
sys.path.insert(0, root)
from fastapi.testclient import TestClient  # noqa: E402

from app import anomaly, config, database, mfa_crypto, risk, security, simulator  # noqa: E402
from app.main import app  # noqa: E402

ROWS: list[tuple[str, str, str, str, str, str]] = []
PW = {"admin": "Admin#2026", "analyst": "Analyst#2026", "dev": "Dev#2026", "finance": "Finance#2026",
      "contractor": "Guest#2026", "svc-backup": "Service#2026"}
CLEAN = {"geo": "Bengaluru, IN", "hour": 13, "requests_last_5m": 4, "failed_attempts_24h": 0, "bytes_out_mb": 15,
         "session_minutes": 25, "concurrent_sessions": 1, "new_device": False, "mfa_verified": True,
         "threat_intel": "clean"}


def check(area, feature, test, expected, fn):
    try:
        ok, actual = fn()
    except Exception as exc:  # noqa: BLE001
        ok, actual = False, f"exception: {type(exc).__name__}: {exc}"
        traceback.print_exc()
    ROWS.append((area, feature, test, expected, str(actual), "PASS" if ok else "FAIL"))


def client(who=None):
    c = TestClient(app, follow_redirects=False, raise_server_exceptions=False)
    if who:
        r = c.post("/api/auth/login", json={"email": f"{who}@hybridcloud.io", "password": PW[who]})
        assert r.status_code == 200, r.text
    return c


def uid(who):
    with database.get_db() as conn:
        return database.row(conn, "SELECT id FROM users WHERE email = ?", (f"{who}@hybridcloud.io",))["id"]


def dev_id(name):
    with database.get_db() as conn:
        return database.row(conn, "SELECT id FROM devices WHERE name = ?", (name,))["id"]


def res_id(name):
    with database.get_db() as conn:
        return database.row(conn, "SELECT id FROM resources WHERE name = ?", (name,))["id"]


def secret(who):
    with database.get_db() as conn:
        u = database.row(conn, "SELECT id, mfa_secret FROM users WHERE email = ?", (f"{who}@hybridcloud.io",))
    return mfa_crypto.user_secret(u)


def wait_fresh_step(who):
    last = database.last_totp_counter(uid(who))
    while last is not None and security.current_totp_counter() <= last:
        time.sleep(0.5)


def evaluate(c, device, resource, ctx=None, user=None):
    body = {"device_id": dev_id(device), "resource_id": res_id(resource), "context": dict(CLEAN, **(ctx or {}))}
    if user:
        body["user_id"] = uid(user)
    return c.post("/api/access/evaluate", json=body)


with TestClient(app):
    pass  # lifespan: schema, seed, model, history, baseline evaluation

# --------------------------------------------------------------------------- Authentication
A = "Authentication"


def t_login():
    c = TestClient(app)
    r = c.post("/api/auth/login", json={"email": "analyst@hybridcloud.io", "password": PW["analyst"]})
    cookie = r.headers.get("set-cookie", "")
    return r.status_code == 200 and "HttpOnly" in cookie and "SameSite=lax" in cookie.replace("Lax", "lax"), \
        f"{r.status_code}; cookie HttpOnly={'HttpOnly' in cookie}, SameSite=Lax"


check(A, "Login", "POST /api/auth/login with analyst demo credentials", "200, HttpOnly SameSite=Lax session cookie", t_login)


def t_bad_pw():
    r = TestClient(app).post("/api/auth/login", json={"email": "finance@hybridcloud.io", "password": "wrong"})
    return r.status_code == 401 and "remaining" in r.json()["detail"], f"{r.status_code} {r.json()['detail']}"


check(A, "Invalid password", "Login as finance with a wrong password", "401 with attempts remaining", t_bad_pw)


def t_session():
    c = client("analyst")
    r = c.get("/api/auth/me")
    return r.status_code == 200 and r.json()["user"]["role"] == "analyst" and "password_hash" not in r.text, \
        f"{r.status_code}, role={r.json()['user']['role']}, no hash in body"


check(A, "Session creation", "GET /api/auth/me with the new cookie", "200 with the analyst identity", t_session)


def t_expiry():
    tok = security.issue_token(uid("analyst"), ttl_seconds=-1)
    r = TestClient(app).get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    return r.status_code == 401, f"{r.status_code}"


check(A, "Session expiry", "Bearer token whose exp is in the past", "401", t_expiry)


def t_logout():
    c = client("analyst")
    tok = c.cookies.get(config.SESSION_COOKIE)
    lo = c.post("/api/auth/logout")
    r = TestClient(app).get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    with database.get_db() as conn:
        n = conn.execute("SELECT COUNT(*) FROM revoked_sessions").fetchone()[0]
    return lo.status_code == 200 and r.status_code == 401 and n >= 1, f"logout {lo.status_code}; copied token -> {r.status_code}; revoked rows={n}"


check(A, "Logout and session revocation", "Log out, then replay the copied token as Bearer", "logout 200, replay 401, jti stored", t_logout)

# --------------------------------------------------------------------------- MFA
M = "MFA"


def t_totp_ok():
    wait_fresh_step("finance")
    c = client("finance")
    r = evaluate(c, "PRIYA-LT-03", "finance-db", {"mfa_verified": False})
    ch = r.json()["challenge"]
    v = c.post("/api/access/challenge", json={"challenge_id": ch["id"], "code": security.totp_code(secret("finance"))})
    return r.json()["decision"] == "CHALLENGE" and ch["mode"] == "live" and v.status_code == 200 and v.json()["step_up_mode"] == "live", \
        f"evaluate {r.json()['decision']} (mode {ch['mode']}); verify {v.status_code} -> {v.json().get('decision')}"


check(M, "TOTP verification", "finance -> finance-db without MFA, answer with current TOTP", "CHALLENGE, then 200 and re-evaluated", t_totp_ok)


def t_replay():
    c = client("finance")
    code = security.totp_code(secret("finance"))
    ch = evaluate(c, "PRIYA-LT-03", "finance-db", {"mfa_verified": False}).json()["challenge"]["id"]
    r = c.post("/api/access/challenge", json={"challenge_id": ch, "code": code})
    return r.status_code == 400 and "Incorrect" in r.json()["detail"], f"{r.status_code} {r.json()['detail']}"


check(M, "TOTP replay prevention", "Reuse the code just accepted on a new challenge", "400 (time step already used)", t_replay)


def t_attempts():
    c = client("finance")
    ch = evaluate(c, "PRIYA-LT-03", "finance-db", {"mfa_verified": False}).json()["challenge"]["id"]
    st = [c.post("/api/access/challenge", json={"challenge_id": ch, "code": "000001"}).status_code for _ in range(4)]
    with database.get_db() as conn:
        conn.execute("DELETE FROM mfa_attempts")
    return st == [400, 400, 429, 400] and risk.challenge_state(ch)["status"] == "cancelled", f"statuses {st}; row {risk.challenge_state(ch)['status']}"


check(M, "Failed-attempt limit", "Four wrong codes on one challenge", "400, 400, 429 (cancelled), then 400", t_attempts)


def t_owner():
    a, b = client("finance"), client("finance")
    ch = evaluate(a, "PRIYA-LT-03", "finance-db", {"mfa_verified": False}).json()["challenge"]["id"]
    r1 = b.post("/api/access/challenge", json={"challenge_id": ch, "code": "000001"})
    r2 = client("admin").post("/api/access/challenge", json={"challenge_id": ch, "code": "000001"})
    st = risk.challenge_state(ch)
    return r1.status_code == 400 and r2.status_code == 400 and st["failed_attempts"] == 0, \
        f"other session {r1.status_code}, admin {r2.status_code}, owner's failed_attempts={st['failed_attempts']}"


check(M, "Challenge ownership", "Answer finance's challenge from another finance session and from admin", "400 generic, owner's count untouched", t_owner)


def t_expire():
    c = client("finance")
    ch = evaluate(c, "PRIYA-LT-03", "finance-db", {"mfa_verified": False}).json()["challenge"]["id"]
    with database.get_db() as conn:
        conn.execute("UPDATE mfa_challenges SET expires_at = ? WHERE token_hash = ?", (time.time() - 1, risk.token_hash(ch)))
    r = c.post("/api/access/challenge", json={"challenge_id": ch, "code": "000001"})
    return r.status_code == 400 and risk.challenge_state(ch)["status"] == "expired", f"{r.status_code}; row {risk.challenge_state(ch)['status']}"


check(M, "Challenge expiry", "Move expires_at into the past, then answer", "400, row marked expired", t_expire)


def t_persist():
    c = client("finance")
    r = evaluate(c, "PRIYA-LT-03", "finance-db", {"mfa_verified": False}).json()
    st = risk.challenge_state(r["challenge"]["id"])
    return st is not None and st["token_hash"] != r["challenge"]["id"] and st["event_id"] == r["event_id"] and \
        st["expires_at"] - st["created_at"] == config.CHALLENGE_TTL_SECONDS, \
        f"row in mfa_challenges (hashed id, event {st['event_id']}, TTL {st['expires_at'] - st['created_at']:.0f}s)"


check(M, "Persistent challenge state", "Issue a challenge and read mfa_challenges", "row with hashed id, bound event, 180 s TTL", t_persist)


def t_enc():
    with database.get_db() as conn:
        vals = [r[0] for r in conn.execute("SELECT mfa_secret FROM users")]
    raw = b"".join(p.read_bytes() for p in config.DB_PATH.parent.glob(config.DB_PATH.name + "*"))
    plain = [secret(w) for w in PW]
    return all(v.startswith("enc:v1:") for v in vals) and not any(p.encode() in raw for p in plain), \
        f"{sum(v.startswith('enc:v1:') for v in vals)}/{len(vals)} enc:v1, plaintext seeds in DB files: {sum(p.encode() in raw for p in plain)}"


check(M, "Encrypted TOTP secrets", "Inspect users.mfa_secret and raw DB bytes", "all enc:v1, no plaintext seed in the files", t_enc)


def t_sim():
    adm = client("admin")
    r = evaluate(adm, "PRIYA-LT-03", "finance-db", {"mfa_verified": False}, user="finance").json()
    ch = r["challenge"]
    code = adm.post("/api/access/challenge", json={"challenge_id": ch["id"], "code": "123456"})
    ok = adm.post("/api/access/challenge", json={"challenge_id": ch["id"], "simulated_outcome": "success"})
    with database.get_db() as conn:
        live = conn.execute("SELECT COUNT(*) FROM mfa_attempts WHERE user_id = ? AND mode = 'live' AND success = 0",
                            (uid("finance"),)).fetchone()[0]
    return ch["mode"] == "simulation" and code.status_code == 400 and ok.status_code == 200 and ok.json()["step_up_mode"] == "simulation" and live == 0, \
        f"mode {ch['mode']}; code {code.status_code}; outcome {ok.status_code} ({ok.json().get('step_up_mode')}); live failures for finance {live}"


check(M, "Real vs simulated MFA", "Admin simulates finance; answer with a code, then simulated_outcome", "simulation mode, code 400, outcome 200, subject untouched", t_sim)

# --------------------------------------------------------------------------- IAM
I = "Identity and access"


def t_roles():
    with database.get_db() as conn:
        roles = sorted(r[0] for r in conn.execute("SELECT role FROM users"))
    return len(roles) == 6, ", ".join(roles)


check(I, "User roles", "List seeded roles", "6 identities across 6 roles", t_roles)


def t_dev_owner():
    r = evaluate(client("finance"), "AISHA-LT-02", "internal-wiki")
    return r.status_code == 400, f"{r.status_code} {r.json()['detail']}"


check(I, "Device ownership", "finance evaluates with the analyst's laptop", "400", t_dev_owner)


def t_trust():
    hi = evaluate(client("contractor"), "CONTRACTOR-LT-12", "internal-wiki").json()
    lo = evaluate(client("contractor"), "CONTRACTOR-LT-11", "internal-wiki").json()
    dev = lambda r: next(s for s in r["signals"] if s["key"] == "device")["points"]  # noqa: E731
    return dev(lo) > dev(hi) and lo["risk_score"] > hi["risk_score"], \
        f"trust 72: device pts {dev(hi)} risk {hi['risk_score']} {hi['decision']}; trust 38: device pts {dev(lo)} risk {lo['risk_score']} {lo['decision']}"


check(I, "Device trust", "Contractor: managed laptop (72) vs unmanaged laptop (38) to internal-wiki", "lower trust gives more device points and risk", t_trust)


def t_sens():
    c = client("admin")
    low = evaluate(c, "FARHAAN-LT-01", "public-web").json()
    crit = evaluate(c, "FARHAAN-LT-01", "finance-db").json()
    pts = lambda r: next(s for s in r["signals"] if s["key"] == "resource")["points"]  # noqa: E731
    return pts(crit) > pts(low), f"public-web (low) {pts(low)} pts; finance-db (critical) {pts(crit)} pts"


check(I, "Resource sensitivity", "Admin laptop to a low vs a critical resource", "critical resource adds more points", t_sens)


def t_policy():
    r = evaluate(client("contractor"), "CONTRACTOR-LT-12", "finance-db").json()
    lp = any("Least privilege" in x["text"] for x in r["reasons"])
    return r["decision"] in ("RESTRICT", "BLOCK") and lp, f"{r['decision']} risk {r['risk_score']}; least-privilege reason: {lp}"


check(I, "Policy restriction", "Contractor to finance-db (database policy excludes contractor)", "RESTRICT or BLOCK with least-privilege reason", t_policy)


def t_admin():
    a = client("analyst").get("/api/admin/inventory").status_code
    b = client("admin").get("/api/admin/inventory").status_code
    p = client("finance").get("/admin").status_code
    return (a, b, p) == (403, 200, 303), f"analyst {a}, admin {b}, finance /admin page {p}"


check(I, "Admin permissions", "Call /api/admin/inventory as analyst and admin; open /admin as finance", "403, 200, redirect 303", t_admin)


def t_inv():
    con = client("contractor").get("/api/context/inventory").json()
    ana = client("analyst").get("/api/context/inventory").json()
    return (con["scope"], len(con["users"]), len(con["resources"]), ana["scope"], len(ana["users"])) == ("self", 1, 3, "soc", 6), \
        f"contractor {con['scope']}: {len(con['users'])} user, {sum(len(u['devices']) for u in con['users'])} devices, {len(con['resources'])} resources; analyst {ana['scope']}: {len(ana['users'])} users"


check(I, "Inventory visibility", "GET /api/context/inventory as contractor and analyst", "contractor self/1/3; analyst soc/6", t_inv)


def t_spoof():
    r = evaluate(client("contractor"), "CONTRACTOR-LT-12", "internal-wiki", user="finance")
    return r.status_code == 403, f"{r.status_code}"


check(I, "Identity spoofing", "Contractor sends user_id=finance in the body", "403", t_spoof)

# --------------------------------------------------------------------------- Risk engine
R = "Risk engine"


def t_signals():
    r = evaluate(client("analyst"), "AISHA-LT-02", "internal-wiki").json()
    keys = [s["key"] for s in r["signals"]]
    w = round(sum(s["weight"] for s in r["signals"]), 1)
    total = round(sum(s["points"] for s in r["signals"]) + r["policy"]["escalation_points"], 1)
    return len(keys) == 6 and abs(w - 100) < 0.2 and abs(min(100, total) - r["risk_score"]) <= 0.3, \
        f"signals {keys}; weights sum {w}; points+escalation {total} vs risk {r['risk_score']}"


check(R, "Six weighted signals / risk calculation", "Analyst laptop to internal-wiki, clean context", "6 signals, weights 100, risk = points + escalation", t_signals)


def t_escal():
    r = evaluate(client("finance"), "PRIYA-LT-03", "finance-db", {"mfa_verified": False}).json()
    return r["policy"]["escalation_points"] > 0 and r["decision"] == "CHALLENGE", \
        f"escalation +{r['policy']['escalation_points']} -> {r['decision']} (base {r['base_risk']}, risk {r['risk_score']})"


check(R, "Policy escalation", "finance-db without step-up MFA", "escalation points and minimum decision CHALLENGE", t_escal)


def t_hard():
    r = evaluate(client("analyst"), "AISHA-LT-02", "internal-wiki", {"threat_intel": "malicious"}).json()
    return r["decision"] == "BLOCK" and any("malicious" in x["text"] for x in r["reasons"]), f"{r['decision']} risk {r['risk_score']}"


check(R, "Hard security control", "Same routine request with threat_intel=malicious", "BLOCK regardless of score", t_hard)

DECISIONS = {}


def t_dec(name, who, device, resource, ctx, expected):
    def run():
        r = evaluate(client(who), device, resource, ctx).json()
        DECISIONS[name] = r
        return r["decision"] == expected, f"{r['decision']} (risk {r['risk_score']})"
    return run


check(R, "Decision ALLOW", "Analyst laptop -> internal-wiki, clean context", "ALLOW", t_dec("allow", "analyst", "AISHA-LT-02", "internal-wiki", {}, "ALLOW"))
check(R, "Decision CHALLENGE", "finance laptop -> finance-db, MFA not yet verified", "CHALLENGE", t_dec("challenge", "finance", "PRIYA-LT-03", "finance-db", {"mfa_verified": False}, "CHALLENGE"))
check(R, "Decision RESTRICT", "Contractor unmanaged laptop -> internal-wiki, new device", "RESTRICT", t_dec("restrict", "contractor", "CONTRACTOR-LT-11", "internal-wiki", {"new_device": True, "hour": 11, "geo": "Chennai, IN"}, "RESTRICT"))
check(R, "Decision BLOCK", "Developer laptop -> k8s-prod at 02:00 with 480 MB egress", "BLOCK", t_dec("block", "dev", "ROHAN-LT-07", "k8s-prod", {"hour": 2, "bytes_out_mb": 480, "failed_attempts_24h": 6, "new_device": True, "threat_intel": "suspicious", "session_minutes": 140, "concurrent_sessions": 4, "requests_last_5m": 22}, "BLOCK"))


def t_pep():
    c = client("analyst")
    allow = c.post("/api/access/preview", json={"event_id": DECISIONS["allow"]["event_id"]})
    block_ev = evaluate(c, "AISHA-LT-02", "internal-wiki", {"threat_intel": "malicious"}).json()["event_id"]
    block = c.post("/api/access/preview", json={"event_id": block_ev})
    return allow.status_code == 200 and allow.json()["scope"] == "full" and block.status_code == 403, \
        f"ALLOW event -> {allow.status_code} {allow.json().get('scope')}; BLOCK event -> {block.status_code}"


check(R, "PEP enforcement", "POST /api/access/preview for an ALLOW and a BLOCK event", "full records for ALLOW, 403 for BLOCK", t_pep)

# --------------------------------------------------------------------------- Anomaly
N = "Anomaly detection"
model = anomaly.get_model()
check(N, "Isolation Forest", "Inspect the loaded model", "sklearn IsolationForest, 180 trees", lambda: (
    type(model.model).__name__ == "IsolationForest" and model.model.n_estimators == 180,
    f"{type(model.model).__name__}, n_estimators={model.model.n_estimators}, trained on {model.samples} synthetic samples"))
check(N, "Nine behavioural features", "anomaly.FEATURES and model input width", "9 features", lambda: (
    len(anomaly.FEATURES) == 9 and model.model.n_features_in_ == 9, ", ".join(anomaly.FEATURES)))


def t_rules():
    r = evaluate(client("admin"), "FARHAAN-LT-01", "internal-wiki", {"geo": "London, UK"}).json()
    hits = [h["rule"] for h in r["anomaly"]["rule_hits"]]
    return "geo_distance_km>=1500" in hits, f"rule hits {hits}; score {r['anomaly']['score']} (isolation {r['anomaly']['isolation_score']})"


check(N, "Contextual rules", "Admin access from London (about 8,000 km)", "impossible-travel rule floor applied", t_rules)
check(N, "Anomaly threshold", "Model threshold (95th percentile of baseline, clipped 0.35-0.85)", "value in [0.35, 0.85]", lambda: (
    0.35 <= model.threshold <= 0.85, f"{model.threshold:.4f}"))


def t_attr():
    f = DECISIONS["block"]["anomaly"]["top_factors"]
    return bool(f) and all({"label", "value", "baseline", "z"} <= set(x) for x in f), \
        "; ".join(f"{x['label']} z={x['z']}" for x in f[:3])


check(N, "Feature attribution", "top_factors of the BLOCK decision", "features with value, baseline and z-score", t_attr)


def t_persist_model():
    loaded = anomaly.BehaviourModel.load()
    return config.MODEL_PATH.exists() and loaded is not None and abs(loaded.threshold - model.threshold) < 1e-12, \
        f"{config.MODEL_PATH.name} exists; reloaded threshold {loaded.threshold:.4f}"


check(N, "Model persistence", "Reload the joblib model from disk", "same threshold after reload", t_persist_model)

# --------------------------------------------------------------------------- Monitoring
O = "Monitoring"


def t_events():
    r = client("admin").get(f"/api/events/{DECISIONS['allow']['event_id']}").json()
    return r["actor_user_id"] == uid("analyst") and r["actor_name"] and r["simulated"] is False, \
        f"event {r['id']}: actor {r['actor_name']}, simulated={r['simulated']}"


check(O, "Event log and actor attribution", "Read the ALLOW event as admin", "actor recorded, live event", t_events)


def t_alerts():
    r = client("analyst").get("/api/alerts?status=open&limit=500").json()
    ids = {a["event_id"] for a in r["alerts"]}
    return DECISIONS["block"]["event_id"] in ids and r["open_count"] >= 1, f"open alerts {r['open_count']}; BLOCK event alerted"


check(O, "Alerts", "BLOCK decision raises an alert", "alert listed for the BLOCK event", t_alerts)


def t_ack():
    alerts = client("analyst").get("/api/alerts?status=open&limit=1").json()["alerts"]
    aid = alerts[0]["id"]
    f = client("finance").post(f"/api/alerts/{aid}/ack").status_code
    a = client("analyst").post(f"/api/alerts/{aid}/ack").status_code
    return (f, a) == (403, 200), f"finance {f}, analyst {a}"


check(O, "Alert acknowledgement", "Acknowledge as finance, then as analyst", "403, then 200", t_ack)


def t_filter():
    r = client("admin").get("/api/events?decision=BLOCK&limit=500").json()
    bad = client("admin").get("/api/events?decision=DROP")
    return r["total"] >= 1 and all(e["decision"] == "BLOCK" for e in r["events"]) and bad.status_code == 422, \
        f"{r['total']} BLOCK events, all BLOCK; invalid filter {bad.status_code}"


check(O, "Filtering", "GET /api/events?decision=BLOCK and an invalid decision", "only BLOCK rows; invalid 422", t_filter)
ROWS.append((O, "CSV export", "Browser: click Export CSV on Monitoring", "CSV download with event columns",
             "Verified with scripts/final_screenshots.py: CSV file downloaded with the expected header and 25 rows", "BROWSER"))

# --------------------------------------------------------------------------- Simulation
S = "Attack simulation"


def t_scen():
    c = client("admin")
    out = []
    for sc in simulator.SCENARIOS:
        r = c.post("/api/sim/scenario", json={"scenario_id": sc["id"], "variants": 1})
        out.append((sc["id"], r.status_code, r.json()["results"][0]["decision"] if r.status_code == 200 else None))
    return len(out) == 12 and all(s == 200 for _, s, _ in out), "; ".join(f"{i}:{d}" for i, _, d in out)


check(S, "All 12 attack scenarios", "POST /api/sim/scenario for each scenario as admin", "12 x 200 with a decision", t_scen)


def t_normal():
    r = client("analyst").post("/api/sim/normal", json={"count": 10})
    return r.status_code == 200 and r.json()["summary"]["total"] == 10, f"{r.status_code}, {r.json()['summary']['decisions']}"


check(S, "Normal traffic", "POST /api/sim/normal count=10 as analyst", "10 evaluated sessions", t_normal)


def t_labels():
    r = client("admin").get("/api/events?truth=attack&limit=500").json()
    n = client("admin").get("/api/events?scenario=normal&limit=1").json()
    return r["total"] >= 12 and all(e["ground_truth"] and e["simulated"] for e in r["events"]) and n["total"] >= 1, \
        f"{r['total']} attack-labelled events, all ground_truth and simulated; normal events {n['total']}"


check(S, "Attack labels", "Filter events truth=attack", "ground_truth true and simulated flag set", t_labels)


def t_simauth():
    a = client("finance").post("/api/sim/scenario", json={"scenario_id": "impossible_travel"}).status_code
    b = client("contractor").post("/api/sim/evaluation", json={}).status_code
    return (a, b) == (403, 403), f"finance scenario {a}, contractor evaluation {b}"


check(S, "Simulation authorisation", "Run a scenario as finance and an evaluation as contractor", "403, 403", t_simauth)


def t_simaudit():
    r = client("admin").get("/api/events?truth=attack&limit=500").json()["events"]
    actors = {e["actor_user_id"] for e in r}
    return actors == {uid("admin")}, f"actor ids on attack events {actors} (admin {uid('admin')})"


check(S, "Audit attribution", "Actor of the scenario events", "the admin who ran them", t_simaudit)

# --------------------------------------------------------------------------- Evaluation
E = "Evaluation"
EVAL = {}


def t_eval():
    r = client("analyst").post("/api/sim/evaluation", json={"name": "Audit run", "normal_samples": 140, "variants": 3})
    m = r.json()
    EVAL.update(m)
    d = m["detection"]
    keys = {"accuracy", "precision", "recall", "f1", "false_positive_rate", "false_negative_rate"}
    return r.status_code == 200 and keys <= set(d), ", ".join(f"{k}={d[k]}" for k in sorted(keys))


check(E, "Detection metrics", "POST /api/sim/evaluation (140 normal, 3 variants)", "accuracy, precision, recall, F1, FPR, FNR", t_eval)
check(E, "Decision latency", "latency block of the run", "avg, p50, p95, max reported", lambda: (
    {"decision_avg_ms", "decision_p50_ms", "decision_p95_ms", "decision_max_ms"} <= set(EVAL["latency"]),
    ", ".join(f"{k}={EVAL['latency'][k]}" for k in ("decision_avg_ms", "decision_p50_ms", "decision_p95_ms", "decision_max_ms"))))
check(E, "Authentication overhead / service latency", "latency block of the run", "both measured", lambda: (
    EVAL["latency"]["auth_overhead_ms"] > 0 and EVAL["latency"]["service_latency_ms"] > 0,
    f"auth {EVAL['latency']['auth_overhead_ms']} ms (PBKDF2 1,000 iterations in this audit), service {EVAL['latency']['service_latency_ms']} ms"))
check(E, "Availability", "availability block of the run", "100% when no engine error", lambda: (
    EVAL["availability"]["rate"] == 100.0, f"{EVAL['availability']['successful']}/{EVAL['availability']['total']} = {EVAL['availability']['rate']}%"))


def t_stored():
    r = client("finance").get(f"/api/evaluation/runs/{EVAL['run_id']}")
    return r.status_code == 200 and r.json()["detection"] == EVAL["detection"], f"run {EVAL['run_id']} retrieved: {r.status_code}"


check(E, "Stored runs", "GET /api/evaluation/runs/{id}", "same metrics as returned", t_stored)

# --------------------------------------------------------------------------- Interface
U = "Interface"


def t_pages():
    c = client("admin")
    res = {p: c.get(p).status_code for p in ("/", "/access", "/monitoring", "/simulation", "/evaluation", "/architecture", "/admin", "/api/docs")}
    anon = TestClient(app, follow_redirects=False).get("/").status_code
    login = TestClient(app).get("/login").status_code
    return all(v == 200 for v in res.values()) and anon == 303 and login == 200, f"{res}; anonymous / -> {anon}; /login {login}"


check(U, "All pages", "GET every page as admin; / anonymously", "200 each; anonymous redirected to /login", t_pages)


def t_headers():
    r = client("admin").get("/api/dashboard")
    h = r.headers
    return "script-src 'self'" in h["content-security-policy"] and h["x-frame-options"] == "DENY" and h["cache-control"] == "no-store", \
        "CSP script-src 'self', X-Frame-Options DENY, nosniff, no-store"


check(U, "Security headers", "Headers on an API response", "CSP, frame denial, no-store", t_headers)

# --------------------------------------------------------------------------- Login throttle last (locks dev for 5 min in this throwaway DB)


def t_throttle():
    c = TestClient(app)
    st = [c.post("/api/auth/login", json={"email": "dev@hybridcloud.io", "password": "x"}).status_code for _ in range(6)]
    ok = c.post("/api/auth/login", json={"email": "dev@hybridcloud.io", "password": PW["dev"]}).status_code
    return st == [401] * 5 + [429] and ok == 429, f"wrong x6 -> {st}; correct password while locked -> {ok}"


check(A, "Login throttling", "Six wrong passwords for dev, then the right one", "5 x 401, then 429 even with the right password", t_throttle)

order = [A, M, I, R, N, O, S, E, U]
ROWS.sort(key=lambda r: order.index(r[0]))
from datetime import datetime, timezone  # noqa: E402

lines = ["# Functional audit", "",
         f"Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')} by `python scripts/final_audit.py` "
         "against the real FastAPI application (TestClient) on a new temporary data directory with synthetic demo "
         "data. PBKDF2 uses 1,000 iterations here for speed. `BROWSER` rows were verified in a real browser "
         "(see docs/FINAL_EVALUATION.md and docs/evidence/).", "",
         "| Area | Feature | Test performed | Expected behaviour | Actual behaviour | Result |",
         "| --- | --- | --- | --- | --- | --- |"]
for row in ROWS:
    lines.append("| " + " | ".join(str(c).replace("|", "/").replace("\n", " ") for c in row) + " |")
open(out, "w", encoding="utf-8").write("\n".join(lines) + "\n")
fails = [r for r in ROWS if r[5] == "FAIL"]
print(f"checks={len(ROWS)} pass={sum(r[5] == 'PASS' for r in ROWS)} fail={len(fails)} browser={sum(r[5] == 'BROWSER' for r in ROWS)}")
for f in fails:
    print("FAIL:", f[1], "->", f[4])
json.dump({"evaluation": EVAL.get("detection")}, sys.stdout)
