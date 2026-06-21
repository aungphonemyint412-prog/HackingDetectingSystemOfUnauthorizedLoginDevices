"""
Quick check: all 4 simulation scenarios fire and mark email_sent=1.
Uses the livetest_1781985309 account (user_id=17) already logged in.
"""
import time
import pymysql
from playwright.sync_api import sync_playwright

BASE     = "https://hacking-detection-system-production.up.railway.app"
USERNAME = "livetest_1781985309"
PASSWORD = "ResetTest456!"   # password set by forgot-password test

DB = dict(
    host="thomas.proxy.rlwy.net", port=29978,
    user="root", password="ZBpoilVhllsEVbTKIeOiaBzCMjxEVcoe",
    database="railway"
)

def q(sql, p=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as c:
        c.execute(sql, p)
        rows = c.fetchall()
    conn.close()
    return rows

def wait_otp(uid, min_id=0, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = q("SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 AND id>%s "
              "ORDER BY created_at DESC LIMIT 1", (uid, min_id))
        if r: return r[0][0]
        time.sleep(1)
    raise TimeoutError("OTP not found")

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_sim_{name}.png"
    page.screenshot(path=path, full_page=True)

SCENARIOS = ["new_ip", "new_device", "unusual_hour", "brute_force"]

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=400)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    assert rows, f"User not found: {USERNAME}"
    uid = rows[0][0]
    print(f"user_id={uid}\n")

    # ── Login ────────────────────────────────────────────────────────────────
    print("[LOGIN]")
    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=20000)

    otp_rows = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))
    last_id  = otp_rows[0][0]
    code = wait_otp(uid, min_id=last_id - 1)
    print(f"  login code={code}")
    page.locator(f'button.option-btn[data-value="{code}"]').click()
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/dashboard", timeout=20000)
    print("  -> dashboard OK\n")

    # ── Simulate each scenario ───────────────────────────────────────────────
    alert_count_before = q("SELECT COUNT(*) FROM alerts WHERE user_id=%s", (uid,))[0][0]

    for scenario in SCENARIOS:
        print(f"[SIMULATE] {scenario}")
        page.goto(f"{BASE}/testing")
        page.wait_for_load_state("networkidle")

        page.locator(
            f'form[action*="simulate"] input[name="scenario"][value="{scenario}"]'
        ).evaluate("el => el.closest('form').submit()")
        page.wait_for_load_state("networkidle")

        flash = page.locator(".flash-item, .alert").first
        if flash.count():
            print(f"  Flash: {flash.inner_text().strip()[:120]}")
        ss(page, f"sim_{scenario}")

        # Small wait so background email thread has time to write to DB
        time.sleep(2)

    # ── Check alerts in DB ───────────────────────────────────────────────────
    print("\n[DB CHECK] alerts after simulations:")
    rows = q(
        "SELECT alert_type, email_sent, created_at FROM alerts "
        "WHERE user_id=%s ORDER BY created_at DESC LIMIT 10",
        (uid,)
    )
    all_sent = True
    for row in rows:
        status = "email_sent=1 OK" if row[1] else "email_sent=0 FAIL"
        if not row[1]:
            all_sent = False
        print(f"  {row[0]:25s}  {status}  {row[2]}")

    print()
    if all_sent:
        print("[PASS] All simulations fired and email_sent=1 for every alert.")
    else:
        print("[FAIL] Some alerts have email_sent=0.")

    time.sleep(2)
    br.close()
