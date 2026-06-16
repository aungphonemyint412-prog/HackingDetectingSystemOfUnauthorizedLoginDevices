"""
Full browser test: register -> verify email -> login -> verify login code -> dashboard
OTP codes are read directly from the local SQLite database (they're stored before being emailed).
"""
import time
import sqlite3
import sys

from playwright.sync_api import sync_playwright

BASE    = "http://127.0.0.1:5000"
DB_PATH = r"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\instance\hacking_detection.db"

USERNAME = f"testuser_{int(time.time())}"
EMAIL    = "godofwarx1234@gmail.com"
PASSWORD = "TestPass123!"


def get_latest_otp(user_id: int, timeout: int = 20) -> str:
    """Poll the otp_codes table until a fresh unused code appears."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        conn = sqlite3.connect(DB_PATH)
        row  = conn.execute(
            "SELECT code FROM otp_codes "
            "WHERE user_id=? AND is_used=0 "
            "ORDER BY created_at DESC LIMIT 1",
            (user_id,)
        ).fetchone()
        conn.close()
        if row:
            return row[0]
        time.sleep(0.5)
    raise TimeoutError(f"No OTP found for user_id={user_id} within {timeout}s")


def get_user_id(username: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    row  = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    if not row:
        raise ValueError(f"User '{username}' not found in DB")
    return row[0]


def screenshot(page, name: str):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_flow_{name}.png"
    page.screenshot(path=path)
    print(f"  [screenshot] {path}")


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=400)
        page    = browser.new_page()
        page.set_default_timeout(15000)

        # ── 1. LANDING PAGE ─────────────────────────────────────────────────
        print("\n[1] Landing page")
        page.goto(BASE)
        screenshot(page, "01_landing")

        # ── 2. REGISTER ──────────────────────────────────────────────────────
        print(f"\n[2] Register as {USERNAME}")
        page.goto(f"{BASE}/register")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="email"]',    EMAIL)
        page.fill('input[name="password"]', PASSWORD)
        page.fill('input[name="confirm_password"]', PASSWORD)
        screenshot(page, "02_register_filled")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-email", timeout=10000)
        screenshot(page, "03_verify_email_page")
        print("  -- redirected to /verify-email")

        # ── 3. VERIFY EMAIL ──────────────────────────────────────────────────
        print("\n[3] Reading email-verification OTP from DB")
        user_id   = get_user_id(USERNAME)
        otp_email = get_latest_otp(user_id)
        print(f"  OTP code: {otp_email}")

        page.fill('#box0', otp_email[0])
        page.fill('#box1', otp_email[1])
        screenshot(page, "04_verify_email_filled")
        page.click('button[type="submit"]')

        # After successful verification -> /link-gmail or /dashboard
        page.wait_for_load_state("networkidle")
        screenshot(page, "05_after_email_verify")
        print(f"  -- landed on: {page.url}")

        # If redirected to link-gmail, skip it
        if "/link-gmail" in page.url or "/link_gmail" in page.url:
            print("  -- on link-gmail page, clicking Skip")
            skip = page.locator('a:has-text("Skip"), a:has-text("skip")')
            if skip.count():
                skip.first.click()
                page.wait_for_load_state("networkidle")
            screenshot(page, "06_after_skip_gmail")
            print(f"  -- now on: {page.url}")

        # ── 4. LOG OUT so we can test fresh login ────────────────────────────
        print("\n[4] Logging out")
        page.goto(f"{BASE}/logout")
        page.wait_for_load_state("networkidle")
        screenshot(page, "07_after_logout")
        print(f"  -- now on: {page.url}")

        # ── 5. LOGIN ─────────────────────────────────────────────────────────
        print(f"\n[5] Login as {USERNAME}")
        page.goto(f"{BASE}/login")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', PASSWORD)
        screenshot(page, "08_login_filled")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/verify-login-code", timeout=10000)
        screenshot(page, "09_verify_login_code_page")
        print("  -- redirected to /verify-login-code")

        # ── 6. VERIFY LOGIN CODE ─────────────────────────────────────────────
        print("\n[6] Reading login OTP from DB")
        # Wait a moment for the new OTP to be written
        time.sleep(1)
        otp_login = get_latest_otp(user_id)
        print(f"  OTP code: {otp_login}")

        page.fill('#box0', otp_login[0])
        page.fill('#box1', otp_login[1])
        screenshot(page, "10_verify_login_filled")
        page.click('button[type="submit"]')
        page.wait_for_url(f"{BASE}/dashboard", timeout=10000)
        screenshot(page, "11_dashboard")
        print(f"  -- landed on: {page.url}")

        # ── 7. VERIFY DASHBOARD ──────────────────────────────────────────────
        print("\n[7] Dashboard check")
        heading = page.locator('h1, h2').first.inner_text()
        print(f"  Heading: {heading}")
        screenshot(page, "12_dashboard_final")

        browser.close()
        print("\n[PASS] Full login flow completed successfully.")


if __name__ == "__main__":
    run()
