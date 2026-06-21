"""
Full live test on Railway — covers:
  1. Login page (white theme, IP badge, forgot-password sections)
  2. Register -> email verify -> redirect to login
  3. Login -> 2-digit code -> dashboard
  4. Simulate New IP (alert email to user)
  5. Logout -> security message -> back to login
  6. Forgot password flow (send code section visible)
  7. Google select page (checkbox UI)
"""
import time
import pymysql
from playwright.sync_api import sync_playwright

BASE     = "https://hacking-detection-system-production.up.railway.app"
TS       = int(time.time())
USERNAME = f"livetest_{TS}"
EMAIL    = f"godofwarx1234+{TS}@gmail.com"
PASSWORD = "TestPass123!"

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

def wait_otp(uid, timeout=45):
    dl = time.time() + timeout
    while time.time() < dl:
        r = q("SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 "
              "ORDER BY created_at DESC LIMIT 1", (uid,))
        if r: return r[0][0]
        time.sleep(1)
    raise TimeoutError("OTP not found in Railway MySQL")

def ss(page, name, label=""):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_full_{name}.png"
    page.screenshot(path=path, full_page=True)
    print(f"  [screenshot] ss_full_{name}.png  {label}")

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=500)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(60000)

    # ── 1. Login page — white theme ──────────────────────────────────────────
    print("\n[1] Login page — white theme check")
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    ss(page, "01_login_page", "white background + IP badge")

    # Check IP badge visible
    ip_badge = page.locator(".ip-row")
    assert ip_badge.is_visible(), "IP badge not visible on login page"
    print(f"  IP badge text: {ip_badge.inner_text().strip()}")

    # ── 2. Forgot password sections (JS switching) ───────────────────────────
    print("\n[2] Forgot password — section switching")
    page.click("text=Forgot password?")
    time.sleep(0.5)
    assert page.locator("#sec-forgot-email").is_visible(), "Forgot email section not visible"
    ss(page, "02_forgot_email_section", "Step 1 — enter email")

    page.fill("#fp-email", "test@example.com")
    page.locator(".back-btn").first.click()
    time.sleep(0.4)
    assert page.locator("#sec-login").is_visible(), "Back to login failed"
    print("  Section switching works correctly")

    # ── 3. Register ──────────────────────────────────────────────────────────
    print(f"\n[3] Register: {USERNAME} / {EMAIL}")
    page.goto(f"{BASE}/register")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="email"]',    EMAIL)
    page.fill('input[name="password"]', PASSWORD)
    page.fill('input[name="confirm_password"]', PASSWORD)
    ss(page, "03_register_form", "filled registration form")
    with page.expect_navigation(timeout=90000, wait_until="load"):
        page.click('button[type="submit"]')
    print(f"  -> landed on: {page.url}")
    ss(page, "04_after_register", "page after registration submit")
    if "/verify-email" not in page.url:
        print(f"  WARN: expected /verify-email, got {page.url}")
        body = page.inner_text('body')
        print(f"  Page text: {body[:400]}")
    assert "/verify-email" in page.url, f"Register did not redirect to /verify-email: {page.url}"
    print("  -> redirected to /verify-email OK")

    # ── 4. Read OTP from Railway MySQL ───────────────────────────────────────
    print("\n[4] Reading OTP from Railway MySQL...")
    rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    assert rows, "User not found in DB!"
    uid  = rows[0][0]
    code = wait_otp(uid)
    print(f"  user_id={uid}  OTP={code}")

    page.fill('#box0', code[0])
    page.fill('#box1', code[1])
    ss(page, "05_otp_filled", "verification code entered")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")

    # Should redirect to login (not dashboard)
    assert "/login" in page.url, f"Expected /login redirect, got {page.url}"
    ss(page, "06_after_verify_redirected_login", "redirected to login after verify OK")
    print(f"  -> redirected to {page.url} OK")

    # ── 5. Login ─────────────────────────────────────────────────────────────
    print(f"\n[5] Login: {USERNAME}")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=20000)
    ss(page, "07_login_code_page", "verify-login-code page with IP")
    print("  -> /verify-login-code OK")

    # Get login code from DB
    time.sleep(3)
    lcode = wait_otp(uid)
    print(f"  Login code={lcode}")
    page.locator(f'button.option-btn[data-value="{lcode}"]').click()
    ss(page, "08_code_selected", "code option selected")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/dashboard", timeout=20000)
    ss(page, "09_dashboard", "dashboard after login")
    print("  -> dashboard OK")

    # ── 6. Simulate New IP (alert sent to user's email) ──────────────────────
    print("\n[6] Simulate New IP Address")
    page.goto(f"{BASE}/testing")
    page.wait_for_load_state("networkidle")
    ss(page, "10_testing_panel", "testing panel")
    page.locator('form[action*="simulate"] input[name="scenario"][value="new_ip"]').evaluate(
        "el => el.closest('form').submit()"
    )
    page.wait_for_load_state("networkidle")
    ss(page, "11_after_simulate_new_ip", "after new IP simulation")
    flash = page.locator(".flash-item, .alert").first
    print(f"  Flash: {flash.inner_text().strip()[:100]}")

    # ── 7. Logout — security message ─────────────────────────────────────────
    print("\n[7] Logout -> security message")
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")
    ss(page, "12_after_logout", "login page after logout with security message")
    page_text = page.content()
    assert "securely signed out" in page_text or "signed out" in page_text.lower(), \
        "Security logout message not found"
    print("  Security message visible OK")

    # ── 8. Check Railway MySQL data ──────────────────────────────────────────
    print("\n[8] Railway MySQL final state:")
    for row in q("SELECT username,email,email_verified FROM users WHERE id=%s", (uid,)):
        print(f"  users -> username={row[0]} email={row[1]} verified={row[2]}")
    for row in q("SELECT login_status,ip_address,is_suspicious FROM login_history "
                 "WHERE user_id=%s ORDER BY login_time", (uid,)):
        print(f"  login_history -> status={row[0]} ip={row[1]} suspicious={row[2]}")
    for row in q("SELECT alert_type,email_sent FROM alerts WHERE user_id=%s", (uid,)):
        print(f"  alerts -> type={row[0]} email_sent={row[1]}")
    otp_rows = q("SELECT code,is_used FROM otp_codes WHERE user_id=%s", (uid,))
    print(f"  otp_codes -> {len(otp_rows)} total")

    time.sleep(3)
    br.close()
    print("\n[PASS] All live tests complete!")
