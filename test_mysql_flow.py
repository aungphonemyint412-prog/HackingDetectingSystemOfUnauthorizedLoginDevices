"""
Register a user, log in, then verify the account exists in MySQL.
"""
import time
import pymysql
from playwright.sync_api import sync_playwright

BASE     = "http://127.0.0.1:5000"
USERNAME = f"mysqluser_{int(time.time())}"
EMAIL    = "godofwarx1234@gmail.com"
PASSWORD = "TestPass123!"

DB = dict(host="127.0.0.1", user="root", password="", database="hds_db")


def mysql_query(sql, params=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as cur:
        cur.execute(sql, params)
        rows = cur.fetchall()
    conn.close()
    return rows


def get_latest_otp_mysql(user_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = mysql_query(
            "SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 "
            "ORDER BY created_at DESC LIMIT 1", (user_id,)
        )
        if rows:
            return rows[0][0]
        time.sleep(0.5)
    raise TimeoutError("No OTP found in MySQL")


def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_mysql_{name}.png"
    page.screenshot(path=path)
    print(f"  [screenshot] {path}")


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=500)
        page    = browser.new_page()
        page.set_default_timeout(15000)

        # 1. Register
        print(f"\n[1] Register as {USERNAME}")
        page.goto(f"{BASE}/register")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="email"]',    EMAIL)
        page.fill('input[name="password"]', PASSWORD)
        page.fill('input[name="confirm_password"]', PASSWORD)
        ss(page, "01_register")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-email", timeout=10000)
        ss(page, "02_verify_email")
        print("  Redirected to /verify-email")

        # 2. Read OTP from MySQL
        users = mysql_query("SELECT id FROM users WHERE username=%s", (USERNAME,))
        assert users, "User not found in MySQL after registration!"
        user_id = users[0][0]
        print(f"  User in MySQL — id={user_id}")

        code = get_latest_otp_mysql(user_id)
        print(f"  Email OTP from MySQL: {code}")

        page.fill('#box0', code[0])
        page.fill('#box1', code[1])
        ss(page, "03_otp_filled")
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        ss(page, "04_after_verify")

        # Skip Gmail link
        if "/link-gmail" in page.url:
            skip = page.locator('a:has-text("Skip"), a:has-text("skip")')
            if skip.count():
                skip.first.click()
                page.wait_for_load_state("networkidle")

        # 3. Logout and login
        print("\n[2] Logout")
        page.goto(f"{BASE}/logout")
        page.wait_for_load_state("networkidle")

        print(f"\n[3] Login as {USERNAME}")
        page.goto(f"{BASE}/login")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', PASSWORD)
        ss(page, "05_login")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-login-code", timeout=10000)
        ss(page, "06_login_options")
        print("  Showing 3-option login code page")

        # 4. Read login OTP from MySQL and click correct button
        time.sleep(1)
        login_code = get_latest_otp_mysql(user_id)
        print(f"  Login OTP from MySQL: {login_code}")

        page.locator(f'button.option-btn[data-value="{login_code}"]').click()
        ss(page, "07_option_selected")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/dashboard", timeout=10000)
        ss(page, "08_dashboard")
        print(f"  Landed on: {page.url}")

        # 5. Verify data in MySQL
        print("\n[4] Verifying MySQL data...")
        user_row = mysql_query(
            "SELECT id, username, email, email_verified, created_at FROM users WHERE id=%s",
            (user_id,)
        )[0]
        print(f"  users row:  id={user_row[0]}  username={user_row[1]}  email={user_row[2]}  verified={user_row[3]}  created={user_row[4]}")

        logins = mysql_query(
            "SELECT login_status, ip_address, login_time FROM login_history WHERE user_id=%s",
            (user_id,)
        )
        print(f"  login_history rows: {len(logins)}")
        for r in logins:
            print(f"    status={r[0]}  ip={r[1]}  time={r[2]}")

        otps = mysql_query("SELECT code, is_used, expires_at FROM otp_codes WHERE user_id=%s", (user_id,))
        print(f"  otp_codes rows: {len(otps)}")
        for r in otps:
            print(f"    code={r[0]}  used={r[1]}  expires={r[2]}")

        time.sleep(3)
        browser.close()
        print("\n[PASS] MySQL integration test complete!")


if __name__ == "__main__":
    run()
