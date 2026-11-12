"""Capture genuine screenshots of the running prototype (Task I) and verify the
browser flows used in the demo guide. Headless Microsoft Edge via Playwright.

usage: python scripts/final_screenshots.py <port> <out_dir>

Playwright is not a project dependency: run this from a separate environment
(pip install playwright) with Microsoft Edge installed. Start the server first
on a new, throw-away ZT_DATA_DIR so that only synthetic demo data appears.
"""
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BASE = f"http://127.0.0.1:{int(sys.argv[1])}"
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=True)
VIEW = {"width": 1440, "height": 900}
results = []
CSP_PROBE = ("window.__csp = []; document.addEventListener('securitypolicyviolation', "
             "function (e) { window.__csp.push(e.violatedDirective); });")


def record(name, ok, detail=""):
    results.append(("PASS" if ok else "FAIL", name, detail))


def session(browser, email=None):
    ctx = browser.new_context(viewport=VIEW, accept_downloads=True)
    ctx.add_init_script(CSP_PROBE)
    page = ctx.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" and "status of 4" not in m.text else None)
    if email:
        page.goto(f"{BASE}/login")
        page.click(f'.demo-account[data-email="{email}"]')
        page.click("#login-btn")
        page.wait_for_url(f"{BASE}/", timeout=15000)
        page.wait_for_load_state("networkidle")
    return ctx, page, errors


def shot(page, name, full=True):
    page.wait_for_timeout(400)
    if not full:
        page.screenshot(path=str(OUT / name))
        return
    # Grow the viewport to the page height instead of using full_page, which
    # stitches scrolled frames and repeats the sticky sidebar mid-image.
    height = page.evaluate("Math.max(document.documentElement.scrollHeight, document.body.scrollHeight)")
    page.set_viewport_size({"width": VIEW["width"], "height": min(int(height), 6000)})
    page.wait_for_timeout(400)
    page.screenshot(path=str(OUT / name))
    page.set_viewport_size(VIEW)


def evaluate(page, *, user=None, device=None, resource, ctx):
    page.goto(f"{BASE}/access")
    page.wait_for_selector("#user-select option", state="attached")
    page.wait_for_load_state("networkidle")
    if user and page.is_enabled("#user-select"):
        page.select_option("#user-select", label=user)
        page.wait_for_timeout(200)
    if device:
        page.select_option("#device-select", index=[o.split(" ·")[0] for o in page.locator("#device-select option").all_inner_texts()].index(device))
    page.select_option("#resource-select", index=[o.split(" ·")[0] for o in page.locator("#resource-select option").all_inner_texts()].index(resource))
    fields = {"hour": "#hour-input", "requests_last_5m": "#rate-input", "failed_attempts_24h": "#failed-input",
              "bytes_out_mb": "#bytes-input", "session_minutes": "#session-input", "concurrent_sessions": "#concurrent-input"}
    for key, selector in fields.items():
        if key in ctx:
            page.fill(selector, str(ctx[key]))
    if "geo" in ctx:
        page.select_option("#geo-select", ctx["geo"])
    if "threat_intel" in ctx:
        page.select_option("#threat-select", ctx["threat_intel"])
    for key, selector in (("mfa_verified", "mfa-input"), ("new_device", "newdevice-input")):
        if key in ctx:
            page.evaluate(f"document.getElementById('{selector}').checked = {str(ctx[key]).lower()}")
    page.click("#evaluate-btn")
    page.wait_for_selector(".result-word", timeout=15000)
    page.wait_for_timeout(500)
    return page.locator(".result-word").inner_text().strip()


CLEAN = {"hour": 13, "requests_last_5m": 5, "failed_attempts_24h": 0, "bytes_out_mb": 18, "session_minutes": 25,
         "concurrent_sessions": 1, "geo": "Bengaluru, IN", "threat_intel": "clean", "mfa_verified": True, "new_device": False}

with sync_playwright() as p:
    browser = p.chromium.launch(channel="msedge", headless=True)

    ctx, page, errors = session(browser)
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    shot(page, "01-login.png")
    ctx.close()

    # Scenario A: normal developer access.
    ctx, page, errors = session(browser, "dev@hybridcloud.io")
    shot(page, "02-dashboard-developer-own-scope.png")
    word = evaluate(page, device="dev-vm-01", resource="dev-vm-01", ctx=CLEAN)
    record("Demo A: developer dev-vm-01 -> dev-vm-01, clean context", word == "Allow", word)
    shot(page, "03-access-normal-allow.png")
    page.click("#preview-btn")
    page.wait_for_selector(".preview-table", timeout=10000)
    record("Demo A: PEP releases full sample records", "full scope" in page.locator("#preview-output").inner_text().lower())
    shot(page, "04-pep-resource-preview.png")
    record("Developer session: no page errors", not errors, "; ".join(errors))
    ctx.close()

    # Scenario B: suspicious login and MFA challenge.
    ctx, page, errors = session(browser, "finance@hybridcloud.io")
    sus = dict(CLEAN, geo="Mumbai, IN", mfa_verified=False)
    word = evaluate(page, device="PRIYA-LT-03", resource="finance-db", ctx=sus)
    record("Demo B: finance -> finance-db from Mumbai without step-up MFA", word == "Challenge", word)
    record("Demo B: live challenge asks for a TOTP code", page.locator("#mfa-code").count() == 1)
    shot(page, "05-access-suspicious-mfa-challenge.png")
    if page.locator("#mfa-code").count() == 0:
        print("Demo B decision:", word, page.locator(".reason-list").first.inner_text()[:600])
        raise SystemExit(2)
    for attempt in range(3):
        page.fill("#mfa-code", f"{attempt}{attempt}{attempt}{attempt}{attempt}{attempt}")
        page.click("#verify-mfa")
        page.wait_for_timeout(900)
    hint = page.locator("#challenge-hint").inner_text()
    record("Demo B: three wrong codes cancel the challenge", page.is_disabled("#verify-mfa") and "cancelled" in hint, hint)
    shot(page, "06-mfa-attempt-limit.png", full=False)
    record("Finance session: no page errors", not errors, "; ".join(errors))
    ctx.close()

    # Restrict and block, then scenario C as a SOC analyst.
    ctx, page, errors = session(browser, "contractor@hybridcloud.io")
    word = evaluate(page, device="CONTRACTOR-LT-11", resource="internal-wiki",
                    ctx=dict(CLEAN, hour=11, geo="Chennai, IN", new_device=True))
    record("Contractor unmanaged laptop -> internal-wiki (new device)", word == "Restrict", word)
    shot(page, "07-access-restrict.png")
    ctx.close()

    ctx, page, errors = session(browser, "analyst@hybridcloud.io")
    word = evaluate(page, user="Aisha Rahman · analyst", device="AISHA-LT-02", resource="internal-wiki",
                    ctx=dict(CLEAN, threat_intel="malicious"))
    record("Analyst laptop -> internal-wiki with malicious source IP", word == "Block", word)
    shot(page, "08-access-block.png")

    page.goto(f"{BASE}/simulation")
    page.wait_for_selector('[data-run="insider_exfiltration"]', timeout=15000)
    page.click('[data-run="insider_exfiltration"]')
    page.wait_for_selector("#sim-table tbody tr", timeout=20000)
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(800)
    rows = page.locator("#sim-table tbody tr").all_inner_texts()
    record("Demo C: insider exfiltration scenario runs", bool(rows), rows[0].replace("\t", " | ")[:160] if rows else "")
    shot(page, "09-simulation-insider-exfiltration.png")

    word = evaluate(page, user="Priya Nair · finance", device="PRIYA-LT-03", resource="analytics-lake",
                    ctx=dict(CLEAN, hour=2, geo="Singapore, SG", requests_last_5m=40, failed_attempts_24h=3,
                             bytes_out_mb=950, session_minutes=480, concurrent_sessions=5, threat_intel="suspicious"))
    sim_box = page.locator("#simulation-challenge").count() == 1
    record("Demo C: analyst replays the exfiltration context for Priya", word in ("Challenge", "Restrict", "Block"), f"{word}; simulation challenge box: {sim_box}")
    shot(page, "10-access-simulated-exfiltration.png")
    if sim_box:
        page.click("#simulate-success")
        page.locator(".chip", has_text="Step-up simulated").wait_for(timeout=15000)
        record("Demo C: simulated MFA success is labelled as simulated", True, page.locator(".result-word").inner_text())
        shot(page, "11-simulated-step-up.png")

    page.goto(f"{BASE}/monitoring")
    page.wait_for_selector("#events-table tbody tr[data-event-id]", timeout=15000)
    page.wait_for_load_state("networkidle")
    shot(page, "12-monitoring.png")
    with page.expect_download(timeout=15000) as download_info:
        page.click("#export-csv")
    path = download_info.value.path()
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    record("Monitoring: CSV export downloads the loaded events",
           lines[0].startswith("id,ts,user,role,device,resource") and len(lines) > 1,
           f"{download_info.value.suggested_filename}: {len(lines) - 1} rows; header {lines[0][:60]}")
    page.click("#events-table tbody tr[data-event-id] >> nth=0")
    page.wait_for_selector(".detail-row", timeout=10000)
    shot(page, "13-monitoring-event-detail.png", full=False)

    page.goto(f"{BASE}/evaluation")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1200)
    shot(page, "14-evaluation.png")
    page.goto(f"{BASE}/architecture")
    page.wait_for_load_state("networkidle")
    shot(page, "15-architecture.png")
    page.goto(f"{BASE}/")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(800)
    shot(page, "16-dashboard-soc.png")
    record("Analyst session: no page errors or CSP violations",
           not errors and not page.evaluate("window.__csp || []"), "; ".join(errors))
    ctx.close()

    ctx, page, errors = session(browser, "admin@hybridcloud.io")
    page.goto(f"{BASE}/admin")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(800)
    shot(page, "17-administration.png")
    record("Admin session: no page errors", not errors, "; ".join(errors))
    ctx.close()
    browser.close()

for status, name, detail in results:
    print(f"[{status}] {name}  {detail}")
print(f"SUMMARY: {sum(r[0] == 'PASS' for r in results)} passed, {sum(r[0] == 'FAIL' for r in results)} failed")
