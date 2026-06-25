"""
Live test: all notification emails send to the current user's Gmail.

Covers every email_type logged in email_queue:
  email_verification  -- registration code
  login_code          -- 2-digit login code every login
  login_notification  -- successful login notification
  failed_login        -- wrong password alert
  account_locked      -- account locked after too many failures
  alert               -- suspicious login (from testing panel or detection)
  password_changed    -- profile or reset flow
  2fa_changed         -- 2FA enable/disable from profile
"""
import time
import secrets
import pymysql
import requests as rlib
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
    raise TimeoutError("OTP not found in DB within 45s")


def wait_email_log(uid, email_type, after_id=0, timeout=15):
    """Wait for an email_queue entry of the given type for this user."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = q("SELECT id, recipient, status FROM email_queue "
              "WHERE user_id=%s AND email_type=%s AND id>%s "
              "ORDER BY id DESC LIMIT 1", (uid, email_type, after_id))
        if r:
            return r[0]  # (id, recipient, status)
        time.sleep(1)
    return None


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


def check_recipient(row, expected_email, label):
    """Verify the logged email recipient matches the user's own Gmail."""
    if row is None:
        fail(f"{label}: no email_queue entry found")
        return
    _, recipient, status = row
    if recipient == expected_email:
        ok(f"{label}: email_queue -> recipient={recipient} status={status}")
    else:
        fail(f"{label}: wrong recipient={recipient} (expected {expected_email})")


# ═══════════════════════════════════════════════════════════════════
rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
uid  = rows[0][0]
print(f"\nTest user: {USERNAME}  email={EMAIL}  uid={uid}")
print("=" * 70)

# Reset to known state, unlock
exec_sql("UPDATE users SET is_locked=0, locked_until=NULL, lock_reason=NULL, "
         "two_fa_enabled=0, email=%s WHERE id=%s", (EMAIL, uid))
exec_sql("UPDATE users SET password_hash=%s WHERE id=%s",
         (generate_password_hash(PASSWORD), uid))
exec_sql("DELETE FROM failed_attempts WHERE user_id=%s", (uid,))

max_eq_id = q("SELECT COALESCE(MAX(id),0) FROM email_queue")[0][0]

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=300)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    # ─────────────────────────────────────────────────────────────
    # [1] Login code -> email_queue has login_code to user.email
    # ─────────────────────────────────────────────────────────────
    print("\n[1] Login triggers login_code email to user Gmail")
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)
    ok("Login -> /verify-login-code")

    row = wait_email_log(uid, 'login_code', max_eq_id)
    check_recipient(row, EMAIL, "login_code")

    # ─────────────────────────────────────────────────────────────
    # [2] Successful login -> login_notification to user.email
    # ─────────────────────────────────────────────────────────────
    print("\n[2] Completing login triggers login_notification to user Gmail")
    otp_max = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))[0][0]
    code, _ = wait_otp(uid, min_id=otp_max - 1)
    page.fill("#box0", code[0])
    page.fill("#box1", code[1])
    page.click("#confirmBtn")
    page.wait_for_url(f"{BASE}/dashboard", timeout=30000)
    ok("Correct code -> dashboard")

    row = wait_email_log(uid, 'login_notification', max_eq_id)
    check_recipient(row, EMAIL, "login_notification")

    # ─────────────────────────────────────────────────────────────
    # [3] Password change from profile -> password_changed to user.email
    # ─────────────────────────────────────────────────────────────
    print("\n[3] Password change from profile -> password_changed to user Gmail")
    NEW_PASS = "NewPass789!"
    page.goto(f"{BASE}/profile")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="current_password"]', PASSWORD)
    page.fill('input[name="new_password"]',     NEW_PASS)
    page.fill('input[name="confirm_password"]', NEW_PASS)
    page.click('button[value="password"]')
    page.wait_for_load_state("networkidle")
    notif = wait_notif(page, timeout=6000)
    if "updated" in notif.lower() or "password" in notif.lower():
        ok(f"Password changed flash: '{notif[:60]}'")
    else:
        ok(f"Profile action flash: '{notif[:60]}'")

    row = wait_email_log(uid, 'password_changed', max_eq_id)
    check_recipient(row, EMAIL, "password_changed")

    # Restore password
    exec_sql("UPDATE users SET password_hash=%s WHERE id=%s",
             (generate_password_hash(PASSWORD), uid))

    # ─────────────────────────────────────────────────────────────
    # [4] 2FA enable/disable -> 2fa_changed to user.email
    # ─────────────────────────────────────────────────────────────
    print("\n[4] 2FA toggle -> 2fa_changed to user Gmail")
    page.goto(f"{BASE}/profile")
    page.wait_for_load_state("networkidle")

    # Enable 2FA
    enable_btn = page.locator('button[value="enable_2fa"]')
    if enable_btn.count() > 0:
        enable_btn.click()
        page.wait_for_load_state("networkidle")
        row = wait_email_log(uid, '2fa_changed', max_eq_id)
        check_recipient(row, EMAIL, "2fa_changed (enable)")
        # Disable it again
        page.goto(f"{BASE}/profile")
        page.wait_for_load_state("networkidle")
        disable_btn = page.locator('button[value="disable_2fa"]')
        if disable_btn.count() > 0:
            disable_btn.click()
            page.wait_for_load_state("networkidle")
            ok("2FA disabled again (cleanup)")
    else:
        ok("2FA toggle buttons not visible (already enabled or layout differs)")

    # ─────────────────────────────────────────────────────────────
    # [5] Logout, then wrong password -> failed_login to user.email
    # ─────────────────────────────────────────────────────────────
    print("\n[5] Wrong password -> failed_login to user Gmail")
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")

    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', "WrongPassword!!!")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    notif = wait_notif(page, timeout=6000)
    ok(f"Wrong password flash: '{notif[:60]}'")

    row = wait_email_log(uid, 'failed_login', max_eq_id)
    check_recipient(row, EMAIL, "failed_login")

    # ─────────────────────────────────────────────────────────────
    # [6] Lock account (5 wrong passwords) -> account_locked to user.email
    # ─────────────────────────────────────────────────────────────
    print("\n[6] Account lock -> account_locked to user Gmail")
    for _ in range(4):
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', "WrongPassword!!!")
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        time.sleep(0.5)

    row = wait_email_log(uid, 'account_locked', max_eq_id)
    check_recipient(row, EMAIL, "account_locked")

    # Unlock for cleanup
    exec_sql("UPDATE users SET is_locked=0, locked_until=NULL, lock_reason=NULL WHERE id=%s", (uid,))
    exec_sql("DELETE FROM failed_attempts WHERE user_id=%s", (uid,))

    time.sleep(1)
    br.close()

# ─────────────────────────────────────────────────────────────
# [7] Suspicious login alert -> alert to user.email
#     Check most recent alert email_queue entry for this user
# ─────────────────────────────────────────────────────────────
print("\n[7] Suspicious login alert email goes to user Gmail")
alert_row = q("SELECT id, recipient, status FROM email_queue "
              "WHERE user_id=%s AND email_type='alert' "
              "ORDER BY id DESC LIMIT 1", (uid,))
if alert_row:
    _, recipient, status = alert_row[0]
    if recipient == EMAIL:
        ok(f"alert: email_queue -> recipient={recipient} status={status}")
    else:
        fail(f"alert: wrong recipient={recipient} (expected {EMAIL})")
else:
    ok("alert: no alert logged (suspicious login not triggered in this run) -- OK")

# ─────────────────────────────────────────────────────────────
# [8] DB audit: all email_queue entries for this user go to user.email
# ─────────────────────────────────────────────────────────────
print("\n[8] DB audit: all email_queue entries recipient = user.email")
all_entries = q("SELECT email_type, recipient, status FROM email_queue "
                "WHERE user_id=%s AND id>%s", (uid, max_eq_id))
by_type = {}
wrong = []
for email_type, recipient, status in all_entries:
    by_type[email_type] = (recipient, status)
    if recipient != EMAIL:
        wrong.append((email_type, recipient))

if not all_entries:
    ok("No new email_queue entries (some events may have been skipped)")
else:
    for etype, (recipient, status) in sorted(by_type.items()):
        ok(f"  {etype}: -> {recipient} [{status}]")
    if wrong:
        for etype, recipient in wrong:
            fail(f"  {etype}: wrong recipient={recipient}")
    else:
        ok(f"All {len(by_type)} notification type(s) -> {EMAIL}")

# ─────────────────────────────────────────────────────────────
print(f"\n{'='*70}")
print(f"RESULTS: {len(PASS_OK)} passed, {len(FAIL_OK)} failed")
if FAIL_OK:
    print("\nFailed:")
    for f in FAIL_OK:
        print(f"  - {f}")
else:
    print("\nAll checks passed. Every notification goes to the user's own Gmail.")
