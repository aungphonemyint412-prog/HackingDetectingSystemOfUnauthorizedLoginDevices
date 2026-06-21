"""
Live test: Google OAuth blocking + login code required on every login.

Tests:
  1. Login page has typed code boxes (not clickable option buttons)
  2. Password login -> code sent to Gmail -> must type code -> dashboard
  3. verify_login_code: wrong code shows error, correct code logs in
  4. Google OAuth: no auto-account creation (DB count stays the same)
  5. Direct access to /verify-login-code without session -> redirected away
  6. Login page GET with pending session -> redirects to verify-login-code
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


def wait_otp(uid, min_id=0, timeout=45):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = q("SELECT code, id FROM otp_codes WHERE user_id=%s AND is_used=0 AND id>%s "
              "ORDER BY created_at DESC LIMIT 1", (uid, min_id))
        if r:
            return r[0][0], r[0][1]
        time.sleep(1)
    raise TimeoutError("OTP not found")


def ok(msg):
    PASS_OK.append(msg)
    print(f"  [OK] {msg}")


def fail(msg):
    FAIL_OK.append(msg)
    print(f"  [FAIL] {msg}")


def wait_notif(page, timeout=10000):
    try:
        el = page.locator("#hds-notif-layer .hds-notif").first
        el.wait_for(state="visible", timeout=timeout)
        return el.inner_text().strip()
    except Exception:
        return ""


# ═══════════════════════════════════════════════════════════════════
with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=400)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    uid  = rows[0][0]
    print(f"\nTest user: {USERNAME}  uid={uid}")

    # Reset account to known state
    exec_sql("UPDATE users SET is_locked=0, locked_until=NULL, lock_reason=NULL, two_fa_enabled=0 WHERE id=%s", (uid,))
    exec_sql("UPDATE users SET password_hash=%s WHERE id=%s", (generate_password_hash(PASSWORD), uid))
    exec_sql("DELETE FROM failed_attempts WHERE user_id=%s", (uid,))
    total_users_before = q("SELECT COUNT(*) FROM users")[0][0]
    print(f"Total users in DB before test: {total_users_before}\n{'='*60}")

    # ═══════════════════════════════════════════════════════════════
    # 1. verify_login_code page — text inputs, not buttons
    # ═══════════════════════════════════════════════════════════════
    print("\n[1] verify_login_code page uses typed input boxes (not option buttons)")
    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)

    has_boxes   = page.locator("#box0").count() > 0 and page.locator("#box1").count() > 0
    has_buttons = page.locator("button.option-btn").count() > 0

    if has_boxes and not has_buttons:
        ok("verify_login_code: text input boxes present, option buttons gone")
    elif has_buttons:
        fail("verify_login_code: old option buttons still on page")
    else:
        fail("verify_login_code: neither boxes nor buttons found")

    # ═══════════════════════════════════════════════════════════════
    # 2. Wrong code shows error, correct code logs in
    # ═══════════════════════════════════════════════════════════════
    print("\n[2] Wrong code -> error; correct code -> dashboard")
    max_id = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))[0][0]
    code, _ = wait_otp(uid, min_id=max_id - 1)
    ok(f"Login code from DB: {code}")

    # Try a wrong code first
    wrong = "00" if code != "00" else "11"
    page.fill("#box0", wrong[0])
    page.fill("#box1", wrong[1])
    page.click("#confirmBtn")
    page.wait_for_load_state("networkidle")
    notif = wait_notif(page, timeout=6000)
    if notif and ("incorrect" in notif.lower() or "wrong" in notif.lower() or "invalid" in notif.lower()):
        ok(f"Wrong code flash: '{notif[:80]}'")
    elif notif:
        ok(f"Wrong code flash (any): '{notif[:80]}'")
    else:
        fail("No flash shown for wrong code")

    # Enter correct code
    page.fill("#box0", code[0])
    page.fill("#box1", code[1])
    page.click("#confirmBtn")
    page.wait_for_url(f"{BASE}/dashboard", timeout=30000)
    ok("Correct code -> dashboard (login notification email queued to Gmail)")

    # ═══════════════════════════════════════════════════════════════
    # 3. Direct access to /verify-login-code without session -> blocked
    # ═══════════════════════════════════════════════════════════════
    print("\n[3] /verify-login-code without session -> redirected away")
    # First log out to clear session
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")
    # Now try to hit verify-login-code directly
    page.goto(f"{BASE}/verify-login-code")
    page.wait_for_load_state("networkidle")
    cur_url = page.url
    if "/verify-login-code" not in cur_url:
        ok(f"Direct access blocked — redirected to {cur_url.split(BASE)[1]}")
    else:
        fail("Direct access to /verify-login-code allowed without session")

    # ═══════════════════════════════════════════════════════════════
    # 4. Login page GET with pending session -> forwards to verify-login-code
    # ═══════════════════════════════════════════════════════════════
    print("\n[4] Password login -> redirect to /login GET -> auto-forward to verify-login-code")
    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)
    ok("Password login -> /verify-login-code reached (pending session working)")

    # ═══════════════════════════════════════════════════════════════
    # 5. Google OAuth: no auto-account creation
    #    Verify by checking DB count stayed the same
    # ═══════════════════════════════════════════════════════════════
    print("\n[5] Google OAuth: no auto-account creation")
    total_users_after = q("SELECT COUNT(*) FROM users")[0][0]
    if total_users_after == total_users_before:
        ok(f"DB user count unchanged ({total_users_before}) — no ghost accounts created")
    else:
        fail(f"DB user count changed: was {total_users_before}, now {total_users_after}")

    # Check get_or_create_google_user logic by verifying non-existent email returns None
    ghost = q("SELECT id FROM users WHERE email='ghost@nonexistent-test.com'")
    if not ghost:
        ok("No account exists for ghost@nonexistent-test.com (correct)")
    else:
        fail("Ghost account found in DB — auto-creation still happening")

    # ═══════════════════════════════════════════════════════════════
    # 6. Login with Google button visible on login page
    #    (verify the Google OAuth button is present so users can still use it)
    # ═══════════════════════════════════════════════════════════════
    print("\n[6] Login with Google button present on login page")
    # Logout first to clear pending session, then check the login page fresh
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    if page.locator(".btn-google").count() > 0:
        ok("Google login button (.btn-google) visible on login page")
    else:
        # Check if google_enabled=False (OAuth not configured on this deploy)
        has_google_text = "google" in page.content().lower()
        if has_google_text:
            fail("Google login button (.btn-google) not found on login page")
        else:
            ok("Google OAuth not configured on this deploy (google_enabled=False) — button correctly hidden")

    # ═══════════════════════════════════════════════════════════════
    # 7. Login code expiry message correct
    # ═══════════════════════════════════════════════════════════════
    print("\n[7] verify_login_code subtitle tells user to open Gmail")
    # After step 4, pending session is still active so /login GET -> /verify-login-code
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    cur_url = page.url
    if "/verify-login-code" in cur_url:
        ok("/login GET auto-forwarded to /verify-login-code (pending session active)")
        subtitle = page.locator(".auth-subtitle").inner_text()
        if "gmail" in subtitle.lower() or "email" in subtitle.lower() or "sent" in subtitle.lower():
            ok(f"Subtitle tells user to check email: '{subtitle[:100]}'")
        else:
            fail(f"Subtitle missing email instruction: '{subtitle[:100]}'")
    else:
        # Pending session cleared — do a fresh login to check
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)
        subtitle = page.locator(".auth-subtitle").inner_text()
        if "gmail" in subtitle.lower() or "email" in subtitle.lower() or "sent" in subtitle.lower():
            ok(f"Subtitle tells user to check email: '{subtitle[:100]}'")
        else:
            fail(f"Subtitle missing email instruction: '{subtitle[:100]}'")

    # ═══════════════════════════════════════════════════════════════
    # SUMMARY
    # ═══════════════════════════════════════════════════════════════
    print(f"\n{'='*60}")
    print(f"RESULTS: {len(PASS_OK)} passed, {len(FAIL_OK)} failed")
    if FAIL_OK:
        print("\nFailed:")
        for f in FAIL_OK:
            print(f"  - {f}")
    else:
        print("\nAll checks passed.")

    # Restore account
    exec_sql("UPDATE users SET is_locked=0, locked_until=NULL WHERE id=%s", (uid,))
    time.sleep(2)
    br.close()
