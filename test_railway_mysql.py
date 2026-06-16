"""Quick smoke test on the live Railway deployment."""
import time
import pymysql
from playwright.sync_api import sync_playwright

BASE     = "https://hacking-detection-system-production.up.railway.app"
USERNAME = f"railwayuser_{int(time.time())}"
EMAIL    = "godofwarx1234@gmail.com"
PASSWORD = "TestPass123!"

# Railway MySQL public URL
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
        c.execute(sql, p)
        rows = c.fetchall()
    conn.close()
    return rows

def otp(uid, timeout=30):
    dl = time.time() + timeout
    while time.time() < dl:
        r = q("SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 ORDER BY created_at DESC LIMIT 1", (uid,))
        if r: return r[0][0]
        time.sleep(1)
    raise TimeoutError("No OTP found in Railway MySQL")

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_railway_{name}.png"
    page.screenshot(path=path)
    print(f"  [screenshot] ss_railway_{name}.png")

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=600)
    page = br.new_page()
    page.set_default_timeout(20000)

    print(f"\n[1] Register {USERNAME} on live Railway app")
    page.goto(f"{BASE}/register")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="email"]',    EMAIL)
    page.fill('input[name="password"]', PASSWORD)
    page.fill('input[name="confirm_password"]', PASSWORD)
    ss(page, "01_register")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-email", timeout=15000)
    ss(page, "02_verify_email")
    print("  Redirected to /verify-email")

    print("\n[2] Reading OTP from Railway MySQL...")
    rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    assert rows, "User NOT found in Railway MySQL!"
    uid  = rows[0][0]
    code = otp(uid)
    print(f"  User id={uid}  OTP={code}")

    page.fill('#box0', code[0])
    page.fill('#box1', code[1])
    ss(page, "03_otp_filled")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    if "/link-gmail" in page.url:
        skip = page.locator('a:has-text("Skip")')
        if skip.count():
            skip.first.click()
            page.wait_for_load_state("networkidle")
    ss(page, "04_after_verify")

    print("\n[3] Logout")
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")

    print(f"\n[4] Login {USERNAME}")
    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=15000)
    ss(page, "05_login_options")

    time.sleep(2)
    lcode = otp(uid)
    print(f"  Login OTP={lcode}")
    page.locator(f'button.option-btn[data-value="{lcode}"]').click()
    ss(page, "06_selected")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/dashboard", timeout=15000)
    ss(page, "07_dashboard")

    print("\n[5] Railway MySQL data:")
    for row in q("SELECT id,username,email,email_verified FROM users WHERE id=%s", (uid,)):
        print(f"  users -> id={row[0]} username={row[1]} email={row[2]} verified={row[3]}")
    for row in q("SELECT login_status,ip_address FROM login_history WHERE user_id=%s", (uid,)):
        print(f"  login_history -> status={row[0]} ip={row[1]}")
    for row in q("SELECT code,is_used FROM otp_codes WHERE user_id=%s", (uid,)):
        print(f"  otp_codes -> code={row[0]} used={row[1]}")

    time.sleep(3)
    br.close()
    print("\n[PASS] Live Railway + MySQL test complete!")
