"""
Live test: Forgot Password flow
  1. Go to login page -> click Forgot password?
  2. Enter email -> Send Code
  3. Read 6-digit OTP from Railway MySQL
  4. Enter OTP -> Verify Code
  5. Enter new password -> Set New Password
  6. Login with the new password to confirm it worked
"""
import time
import pymysql
from playwright.sync_api import sync_playwright

BASE = "https://hacking-detection-system-production.up.railway.app"

# Use the livetest account created in the previous test run (user_id=17)
TEST_EMAIL    = "godofwarx1234+1781985309@gmail.com"
TEST_USERNAME = "livetest_1781985309"
NEW_PASSWORD  = "ResetTest456!"

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

def wait_otp(uid, timeout=45, min_id=0):
    """Poll for a fresh unused OTP written after min_id."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = q(
            "SELECT code FROM otp_codes "
            "WHERE user_id=%s AND is_used=0 AND id>%s "
            "ORDER BY created_at DESC LIMIT 1",
            (uid, min_id)
        )
        if r:
            return r[0][0]
        time.sleep(1)
    raise TimeoutError(f"No OTP found in MySQL for user_id={uid} after {timeout}s")

def ss(page, name, label=""):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_fp_{name}.png"
    page.screenshot(path=path, full_page=True)
    print(f"  [screenshot] ss_fp_{name}.png  {label}")

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=600)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    # Get user_id and highest existing OTP id (so we only read fresh ones)
    rows = q("SELECT id FROM users WHERE email=%s", (TEST_EMAIL,))
    assert rows, f"User not found in DB for email={TEST_EMAIL}"
    uid = rows[0][0]
    otp_rows = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))
    last_otp_id = otp_rows[0][0]
    print(f"  user_id={uid}  last_otp_id={last_otp_id}")

    # ── Step 1: Land on login page ───────────────────────────────────────────
    print("\n[1] Login page")
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    ss(page, "01_login", "login page")
    assert page.locator("#sec-login").is_visible(), "sec-login not visible"
    print("  sec-login visible OK")

    # ── Step 2: Open forgot-email section ───────────────────────────────────
    print("\n[2] Click Forgot password?")
    page.click("text=Forgot password?")
    page.wait_for_selector("#sec-forgot-email:not(.hidden)", timeout=3000)
    ss(page, "02_forgot_email", "sec-forgot-email shown")
    assert page.locator("#sec-forgot-email").is_visible()
    print("  sec-forgot-email visible OK")

    # ── Step 3: Enter email and submit ───────────────────────────────────────
    print(f"\n[3] Enter email: {TEST_EMAIL}")
    page.fill("#fp-email", TEST_EMAIL)
    ss(page, "03_email_filled", "email filled in")
    page.click("#btn-send")

    # Wait for OTP section to appear (means API returned success)
    page.wait_for_selector("#sec-forgot-otp:not(.hidden)", timeout=15000)
    ss(page, "04_otp_section", "sec-forgot-otp shown after Send Code")
    assert page.locator("#sec-forgot-otp").is_visible()
    print("  sec-forgot-otp visible OK — code was sent")

    # ── Step 4: Read OTP from Railway MySQL ──────────────────────────────────
    print("\n[4] Reading 6-digit OTP from Railway MySQL...")
    otp = wait_otp(uid, timeout=45, min_id=last_otp_id)
    print(f"  OTP={otp}")
    assert len(otp) == 6, f"Expected 6-digit OTP, got: {otp!r}"

    # ── Step 5: Enter OTP and verify ─────────────────────────────────────────
    print("\n[5] Enter OTP and verify")
    page.fill("#fp-otp", otp)
    ss(page, "05_otp_filled", f"OTP {otp} entered")
    page.click("#btn-verify")

    # Wait for new-password section
    page.wait_for_selector("#sec-forgot-reset:not(.hidden)", timeout=10000)
    ss(page, "06_reset_section", "sec-forgot-reset shown — OTP verified")
    assert page.locator("#sec-forgot-reset").is_visible()
    print("  OTP verified OK — sec-forgot-reset visible")

    # ── Step 6: Set new password ──────────────────────────────────────────────
    print(f"\n[6] Set new password: {NEW_PASSWORD}")
    page.fill("#fp-newpwd", NEW_PASSWORD)
    page.fill("#fp-confirmpwd", NEW_PASSWORD)
    ss(page, "07_new_password", "new password entered")

    # Click reset — the custom #g-alert will show "Password updated!" in the DOM
    page.click("#btn-reset")

    # Wait for the DOM alert to appear with success message
    page.wait_for_selector("#g-alert.show.ok", timeout=10000)
    alert_text = page.locator("#g-alert").inner_text()
    print(f"  Alert: {alert_text}")
    assert "password" in alert_text.lower() or "updated" in alert_text.lower(), \
        f"Unexpected alert text: {alert_text!r}"

    # Should return to sec-login
    time.sleep(0.5)
    ss(page, "08_back_to_login", "returned to login section after reset")
    assert page.locator("#sec-login").is_visible(), "Expected sec-login after password reset"
    print("  Back to sec-login OK")

    # ── Step 7: Login with new password ──────────────────────────────────────
    print(f"\n[7] Login with new password: {TEST_USERNAME} / {NEW_PASSWORD}")
    page.fill('input[name="username"]', TEST_USERNAME)
    page.fill('input[name="password"]', NEW_PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=20000)
    ss(page, "09_login_code", "verify-login-code page")
    print("  -> /verify-login-code OK — new password accepted")

    # Read fresh login code and enter it
    time.sleep(3)
    login_code = wait_otp(uid, timeout=45)
    print(f"  Login code={login_code}")
    page.locator(f'button.option-btn[data-value="{login_code}"]').click()
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/dashboard", timeout=20000)
    ss(page, "10_dashboard", "dashboard — full reset flow confirmed")
    print("  -> dashboard OK")

    time.sleep(2)
    br.close()
    print("\n[PASS] Forgot password flow works end-to-end!")
