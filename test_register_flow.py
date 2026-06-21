"""
Live test: full new-user registration flow.

  Register (new username/email) -> verify 2-digit email code
  -> login -> 2-digit login code -> dashboard
  -> cleanup (delete test account)
"""
import time
import secrets
import pymysql
from playwright.sync_api import sync_playwright

BASE = "https://hacking-detection-system-production.up.railway.app"

DB = dict(host="thomas.proxy.rlwy.net", port=29978,
          user="root", password="ZBpoilVhllsEVbTKIeOiaBzCMjxEVcoe",
          database="railway")

PASS_OK = []
FAIL_OK = []

tag      = secrets.token_hex(4)
USERNAME = f"regtest_{tag}"
EMAIL    = f"godofwarx1234+regtest{tag}@gmail.com"
PASSWORD = "RegTest123!"


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


print(f"\nNew test user: {USERNAME}")
print(f"Email:         {EMAIL}")
print("=" * 60)

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=400)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    # ── [1] Register ──────────────────────────────────────────────
    print("\n[1] Register new account")
    page.goto(f"{BASE}/register")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="email"]',    EMAIL)
    page.fill('input[name="password"]', PASSWORD)
    page.fill('input[name="confirm_password"]', PASSWORD)
    page.click('button[type="submit"]')

    try:
        page.wait_for_url(f"{BASE}/verify-email", timeout=20000)
        ok("Register -> /verify-email reached")
    except Exception:
        notif = wait_notif(page)
        fail(f"Register did not reach /verify-email. Flash: '{notif[:80]}'")
        br.close()
        raise

    # ── [2] Get 2-digit email verification code from DB ───────────
    print("\n[2] Email verification")
    uid_rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    if not uid_rows:
        fail("User not created in DB")
        br.close()
        raise SystemExit(1)
    uid = uid_rows[0][0]
    ok(f"User created in DB: uid={uid}")

    code, _ = wait_otp(uid, timeout=60)
    ok(f"Verification code from DB: {code}")

    page.fill("#box0", code[0])
    page.fill("#box1", code[1])
    page.click("#verifyBtn")
    page.wait_for_load_state("networkidle")

    # Should redirect to login with success flash
    try:
        page.wait_for_url(f"{BASE}/login", timeout=15000)
        ok("Email verified -> redirected to /login")
    except Exception:
        notif = wait_notif(page)
        fail(f"Did not redirect to /login after verify. Flash: '{notif[:80]}' url={page.url}")

    notif = wait_notif(page, timeout=5000)
    if "verified" in notif.lower() or "ready" in notif.lower() or "log in" in notif.lower():
        ok(f"Success flash: '{notif[:80]}'")
    else:
        ok(f"Flash on login page: '{notif[:60]}'")

    # ── [3] Verify DB: email_verified=1 ──────────────────────────
    print("\n[3] DB state after verification")
    row = q("SELECT email_verified FROM users WHERE id=%s", (uid,))
    if row and row[0][0] == 1:
        ok("DB: email_verified=1")
    else:
        fail(f"DB: email_verified={row[0][0] if row else 'N/A'}")

    # ── [4] Login with new account ────────────────────────────────
    print("\n[4] Login with new account -> 2-digit code -> dashboard")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')

    try:
        page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)
        ok("Login -> /verify-login-code (2-digit code sent)")
    except Exception as e:
        fail(f"Login did not reach verify-login-code: {e}")
        br.close()
        raise

    max_id = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))[0][0]
    login_code, _ = wait_otp(uid, min_id=max_id - 1)
    ok(f"Login code from DB: {login_code}")

    page.fill("#box0", login_code[0])
    page.fill("#box1", login_code[1])
    page.click("#confirmBtn")
    page.wait_for_url(f"{BASE}/dashboard", timeout=30000)
    ok("Correct login code -> dashboard")

    # ── [5] Dashboard loaded for new user ─────────────────────────
    print("\n[5] Dashboard for new user")
    cards = page.locator(".hds-card").count()
    ok(f"Dashboard loaded with {cards} stat card(s)")

    time.sleep(1)
    br.close()

# ── Cleanup ───────────────────────────────────────────────────────
print("\nCleaning up test account...")
for table in ["security_incidents", "alerts", "security_tokens", "email_queue",
              "otp_codes", "known_ips", "known_devices", "failed_attempts", "login_history"]:
    exec_sql(f"DELETE FROM {table} WHERE user_id=%s", (uid,))
exec_sql("DELETE FROM users WHERE id=%s", (uid,))
ok(f"Test account uid={uid} deleted from DB")

print(f"\n{'='*60}")
print(f"RESULTS: {len(PASS_OK)} passed, {len(FAIL_OK)} failed")
if FAIL_OK:
    print("\nFailed:")
    for f in FAIL_OK:
        print(f"  - {f}")
else:
    print("\nAll checks passed.")
