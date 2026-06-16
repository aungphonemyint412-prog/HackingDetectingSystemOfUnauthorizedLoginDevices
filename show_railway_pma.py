"""Show Railway MySQL data in phpMyAdmin using SQL tab."""
import time
from playwright.sync_api import sync_playwright

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_rpma_{name}.png"
    page.screenshot(path=path, full_page=False)
    print(f"  [screenshot] ss_rpma_{name}.png")

def run_sql(page, sql, name):
    # Click SQL tab
    page.locator('#topmenu a', has_text="SQL").first.click()
    time.sleep(1)
    # Clear and type query
    page.locator('#sqlquery').fill(sql)
    page.locator('#button_submit_query').click()
    time.sleep(3)
    ss(page, name)

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=400)
    page = br.new_page()
    page.set_default_timeout(30000)

    # Connect to Railway MySQL
    print("[1] Opening Railway MySQL in phpMyAdmin...")
    page.goto("http://localhost/phpmyadmin/index.php?server=2", wait_until="domcontentloaded")
    time.sleep(5)
    ss(page, "01_connected")

    # Go to railway database via Databases tab
    print("[2] Opening railway database...")
    page.locator('#topmenu a, a.nav-link', has_text="Databases").first.click()
    time.sleep(3)
    page.locator('a', has_text="railway").first.click()
    time.sleep(4)
    ss(page, "02_railway_db")

    # Query users
    print("[3] Querying users...")
    run_sql(page, "SELECT id, username, email, email_verified, created_at FROM users;", "03_users")

    # Query login_history
    print("[4] Querying login_history...")
    run_sql(page, "SELECT id, user_id, ip_address, login_status, login_time, is_suspicious FROM login_history;", "04_login_history")

    # Query otp_codes
    print("[5] Querying otp_codes...")
    run_sql(page, "SELECT id, user_id, code, is_used, expires_at, created_at FROM otp_codes;", "05_otp_codes")

    time.sleep(3)
    br.close()
    print("Done.")
