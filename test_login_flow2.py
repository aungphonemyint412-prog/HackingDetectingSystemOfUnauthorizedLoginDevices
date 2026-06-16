"""
Test the 3-option login verification UI.
Registers a user, verifies email, logs out, logs in, then reads the OTP from
DB to find and click the correct option button.
"""
import time, sqlite3
from playwright.sync_api import sync_playwright

BASE     = "http://127.0.0.1:5000"
DB_PATH  = r"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\instance\hacking_detection.db"
USERNAME = f"testuser2_{int(time.time())}"
EMAIL    = "godofwarx1234@gmail.com"
PASSWORD = "TestPass123!"


def get_user_id(username):
    conn = sqlite3.connect(DB_PATH)
    row  = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    return row[0] if row else None


def get_latest_otp(user_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        conn = sqlite3.connect(DB_PATH)
        row  = conn.execute(
            "SELECT code FROM otp_codes WHERE user_id=? AND is_used=0 "
            "ORDER BY created_at DESC LIMIT 1", (user_id,)
        ).fetchone()
        conn.close()
        if row:
            return row[0]
        time.sleep(0.5)
    raise TimeoutError("No OTP found")


def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_flow2_{name}.png"
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
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-email", timeout=10000)
        ss(page, "01_verify_email")

        # 2. Verify email (type-in boxes still used here)
        user_id = get_user_id(USERNAME)
        code    = get_latest_otp(user_id)
        print(f"  Email OTP: {code}")
        page.fill('#box0', code[0])
        page.fill('#box1', code[1])
        page.click('button[type="submit"]')
        page.wait_for_load_state("networkidle")
        ss(page, "02_after_email_verify")

        # Skip Gmail link if shown
        if "/link-gmail" in page.url or "/link_gmail" in page.url:
            skip = page.locator('a:has-text("Skip"), a:has-text("skip")')
            if skip.count():
                skip.first.click()
                page.wait_for_load_state("networkidle")

        # 3. Logout
        print("\n[2] Logout")
        page.goto(f"{BASE}/logout")
        page.wait_for_load_state("networkidle")

        # 4. Login
        print(f"\n[3] Login as {USERNAME}")
        page.goto(f"{BASE}/login")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-login-code", timeout=10000)
        ss(page, "03_login_code_options")
        print("  Redirected to /verify-login-code with 3 options")

        # 5. Read the correct code from DB and click it
        time.sleep(1)
        login_code = get_latest_otp(user_id)
        print(f"  Correct login code (from email): {login_code}")

        # Find the button with the correct code and click it
        btn = page.locator(f'button.option-btn[data-value="{login_code}"]')
        btn.click()
        ss(page, "04_option_selected")
        print(f"  Selected option: {login_code}")

        # 6. Click Confirm
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/dashboard", timeout=10000)
        ss(page, "05_dashboard")
        print(f"\n  Landed on: {page.url}")
        print("\n[PASS] 3-option login code flow works correctly!")

        time.sleep(3)
        browser.close()


if __name__ == "__main__":
    run()
