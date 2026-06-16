"""
Register on the live Railway app using aungphonemyint412@gmail.com
so the 2-digit codes arrive in the real Gmail inbox.
OTP is also read from Railway MySQL so the test can complete automatically.
"""
import time, pymysql
from playwright.sync_api import sync_playwright

BASE     = "https://hacking-detection-system-production.up.railway.app"
USERNAME = f"aunguser_{int(time.time())}"
EMAIL    = "aungphonemyint412@gmail.com"
PASSWORD = "TestPass123!"

DB = dict(
    host="thomas.proxy.rlwy.net",
    port=29978,
    user="root",
    password="ZBpoilVhllsEVbTKIeOiaBzCMjxEVcoe",
    database="railway"
)

def q(sql, p=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as c:
        c.execute(sql, p); rows = c.fetchall()
    conn.close(); return rows

def otp(uid, timeout=30):
    dl = time.time() + timeout
    while time.time() < dl:
        r = q("SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 ORDER BY created_at DESC LIMIT 1", (uid,))
        if r: return r[0][0]
        time.sleep(1)
    raise TimeoutError("No OTP")

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_real_{name}.png"
    page.screenshot(path=path)
    print(f"  [screenshot] ss_real_{name}.png")

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=600)
    page = br.new_page()
    page.set_default_timeout(20000)

    # 1. Register with aungphonemyint412@gmail.com
    print(f"\n[1] Register on live app: {USERNAME} / {EMAIL}")
    page.goto(f"{BASE}/register")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="email"]',    EMAIL)
    page.fill('input[name="password"]', PASSWORD)
    page.fill('input[name="confirm_password"]', PASSWORD)
    ss(page, "01_register")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-email", timeout=15000)
    ss(page, "02_verify_email")
    print(f"  Email verification code sent to {EMAIL}")
    print("  --> Check your Gmail inbox for the 2-digit code!")

    # 2. Read code from Railway MySQL and enter it
    rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    uid  = rows[0][0]
    code = otp(uid)
    print(f"  Code from MySQL: {code}")

    page.fill('#box0', code[0])
    page.fill('#box1', code[1])
    ss(page, "03_code_entered")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    if "/link-gmail" in page.url:
        skip = page.locator('a:has-text("Skip")')
        if skip.count():
            skip.first.click()
            page.wait_for_load_state("networkidle")
    ss(page, "04_verified")
    print("  Email verified!")

    # 3. Logout then login
    print("\n[2] Logout")
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")

    print(f"\n[3] Login as {USERNAME}")
    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=15000)
    ss(page, "05_login_options")
    print(f"  Login code sent to {EMAIL}")
    print("  --> Check your Gmail inbox for the 2-digit code!")

    time.sleep(2)
    lcode = otp(uid)
    print(f"  Code from MySQL: {lcode}")
    page.locator(f'button.option-btn[data-value="{lcode}"]').click()
    ss(page, "06_selected")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/dashboard", timeout=15000)
    ss(page, "07_dashboard")
    print(f"\n  Logged in! Landed on: {page.url}")

    time.sleep(4)
    br.close()
    print("\n[PASS] Real email test complete!")
    print(f"  Check {EMAIL} for 2 emails:")
    print("    1. [HDS] Email Verification Code")
    print("    2. [HDS] Login Verification Code")
