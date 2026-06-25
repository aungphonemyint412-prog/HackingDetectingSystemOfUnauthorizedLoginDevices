"""
Live test: 2FA two-step login flow.

When 2FA is enabled:
  password -> /verify-2fa (6-digit OTP) -> /verify-login-code (2-digit) -> dashboard

When 2FA is disabled:
  password -> /verify-login-code (2-digit) -> dashboard
"""
import time
import pymysql
from playwright.sync_api import sync_playwright
from werkzeug.security import generate_password_hash

BASE     = "https://hacking-detection-system-production.up.railway.app"
USERNAME = "livetest_1781985309"
EMAIL    = "godofwarx1234+1781985309@gmail.com"
PASSWORD = "ResetTest456!"

DB = dict(host="thomas.proxy.rlwy.net", port=29978,
          user="root", password="ZBpoilVhllsEVbTKIeOiaBzCMjxEVcoe",
          database="railway")

PASS_OK = []
FAIL_OK = []


def q(sql, p=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as c:
        c.execute(sql, p)
        rows = c.fetchall()
    conn.close()
    return rows


def exec_sql(sql, p=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as c:
        c.execute(sql, p)
    conn.commit()
    conn.close()


def wait_otp(uid, min_id=0, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = q("SELECT code, id FROM otp_codes WHERE user_id=%s AND is_used=0 AND id>%s "
              "ORDER BY created_at DESC LIMIT 1", (uid, min_id))
        if r:
            return r[0][0], r[0][1]
        time.sleep(1)
    raise TimeoutError("OTP not found in DB within 60s")


def ok(msg):
    PASS_OK.append(msg)
    print(f"  [OK] {msg}")


def fail(msg):
    FAIL_OK.append(msg)
    print(f"  [FAIL] {msg}")


def wait_notif(page, timeout=8000):
    try:
        el = page.locator("#hds-notif-layer .hds-notif").first
        el.wait_for(state="visible", timeout=timeout)
        return el.inner_text().strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════
rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
uid  = rows[0][0]
print(f"\nTest user: {USERNAME}  uid={uid}")
print("=" * 60)

exec_sql("UPDATE users SET is_locked=0, locked_until=NULL, lock_reason=NULL "
         "WHERE id=%s", (uid,))
exec_sql("UPDATE users SET password_hash=%s WHERE id=%s",
         (generate_password_hash(PASSWORD), uid))
exec_sql("DELETE FROM failed_attempts WHERE user_id=%s", (uid,))

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=True, slow_mo=200)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    # ─────────────────────────────────────────────────────────────
    # Part A: Login WITHOUT 2FA (single 2-digit step)
    # ─────────────────────────────────────────────────────────────
    print("\n[A] Login WITHOUT 2FA -> single 2-digit code step")
    exec_sql("UPDATE users SET two_fa_enabled=0 WHERE id=%s", (uid,))

    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')

    page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)
    ok("No-2FA login -> /verify-login-code directly (correct)")

    # Check: no step badge present
    has_step_badge = page.locator("text=Step 2 of 2").count() > 0
    if not has_step_badge:
        ok("No 'Step 2 of 2' badge (correct for non-2FA path)")
    else:
        fail("Unexpected 'Step 2 of 2' badge on non-2FA path")

    max_id = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))[0][0]
    code, _ = wait_otp(uid, min_id=max_id - 1)
    page.fill("#box0", code[0])
    page.fill("#box1", code[1])
    page.click("#confirmBtn")
    page.wait_for_url(f"{BASE}/dashboard", timeout=30000)
    ok("2-digit code -> dashboard (no-2FA path works)")

    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")

    # ─────────────────────────────────────────────────────────────
    # Part B: Enable 2FA via profile, then login (2-step flow)
    # ─────────────────────────────────────────────────────────────
    print("\n[B] Enable 2FA, then login -> 6-digit OTP + 2-digit code")
    exec_sql("UPDATE users SET two_fa_enabled=1 WHERE id=%s", (uid,))

    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')

    try:
        page.wait_for_url(f"{BASE}/verify-2fa", timeout=40000)
        ok("2FA login -> /verify-2fa (step 1 of 2)")
    except Exception as e:
        fail(f"2FA login did NOT reach /verify-2fa: {e} (url={page.url})")
        br.close()
        raise

    # Check step indicator on verify_2fa page
    step_text = page.locator("text=Step 1 of 2").count()
    if step_text > 0:
        ok("verify_2fa shows 'Step 1 of 2' indicator")
    else:
        fail("verify_2fa missing 'Step 1 of 2' indicator")

    # Get 6-digit OTP from DB
    max_id = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))[0][0]
    otp6, _ = wait_otp(uid, min_id=max_id - 1)
    ok(f"6-digit OTP from DB: {otp6}")

    # Enter 6-digit code
    boxes = page.locator('.otp-box')
    for i, digit in enumerate(otp6):
        boxes.nth(i).fill(digit)
    page.click('#verifyBtn')

    # Should redirect to verify_login_code for step 2
    try:
        page.wait_for_url(f"{BASE}/verify-login-code", timeout=30000)
        ok("After 6-digit 2FA -> /verify-login-code (step 2 of 2)")
    except Exception as e:
        fail(f"After 2FA did NOT reach /verify-login-code: {e} (url={page.url})")
        br.close()
        raise

    # Check step 2 indicator
    step2_text = page.locator("text=Step 2 of 2").count()
    if step2_text > 0:
        ok("verify_login_code shows 'Step 2 of 2' badge")
    else:
        fail("verify_login_code missing 'Step 2 of 2' badge")

    step1_done = page.locator("text=Step 1 done").count()
    if step1_done > 0:
        ok("verify_login_code shows 'Step 1 done' badge")
    else:
        fail("verify_login_code missing 'Step 1 done' badge")

    # Get 2-digit code from DB
    max_id = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))[0][0]
    code2d, _ = wait_otp(uid, min_id=max_id - 1)
    ok(f"2-digit login code from DB: {code2d}")

    page.fill("#box0", code2d[0])
    page.fill("#box1", code2d[1])
    page.click("#confirmBtn")
    page.wait_for_url(f"{BASE}/dashboard", timeout=30000)
    ok("2-digit code -> dashboard (2FA two-step path works!)")

    # ─────────────────────────────────────────────────────────────
    # Part C: Wrong 6-digit code shows error and returns to login
    # ─────────────────────────────────────────────────────────────
    print("\n[C] Wrong 6-digit 2FA code -> error -> back to login")
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")

    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-2fa", timeout=40000)

    # Enter wrong 6-digit code
    wrong6 = "000000"
    boxes = page.locator('.otp-box')
    for i, digit in enumerate(wrong6):
        boxes.nth(i).fill(digit)
    page.click('#verifyBtn')
    page.wait_for_load_state("networkidle")

    if "/login" in page.url or "/verify-2fa" in page.url:
        notif = wait_notif(page, timeout=6000)
        ok(f"Wrong 2FA code -> error returned ('{notif[:60]}') url={page.url.split(BASE)[1]}")
    else:
        fail(f"Wrong 2FA code -> unexpected url={page.url}")

    time.sleep(1)
    br.close()

# Cleanup
exec_sql("UPDATE users SET two_fa_enabled=0 WHERE id=%s", (uid,))
ok("Cleanup: 2FA disabled")

print(f"\n{'='*60}")
print(f"RESULTS: {len(PASS_OK)} passed, {len(FAIL_OK)} failed")
if FAIL_OK:
    print("\nFailed:")
    for f in FAIL_OK:
        print(f"  - {f}")
else:
    print("\nAll checks passed.")
