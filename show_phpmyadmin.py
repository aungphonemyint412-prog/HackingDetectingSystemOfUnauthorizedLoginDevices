"""Open phpMyAdmin and show the hacking_detection_system tables."""
import time
from playwright.sync_api import sync_playwright

PMA = "http://localhost/phpmyadmin"
DB  = "hacking_detection_system"

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_pma_{name}.png"
    page.screenshot(path=path, full_page=True)
    print(f"  [screenshot] ss_pma_{name}.png")

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=400)
    page = br.new_page()
    page.set_default_timeout(15000)

    # 1. Open phpMyAdmin
    print("[1] Opening phpMyAdmin...")
    page.goto(PMA)
    page.wait_for_load_state("networkidle")
    ss(page, "01_login")

    # Login if needed
    if page.locator('input[name="pma_username"], #input_username').count():
        page.fill('input[name="pma_username"], #input_username', "root")
        page.fill('input[name="pma_password"], #input_password', "")
        page.click('input[type="submit"], #input_go')
        page.wait_for_load_state("networkidle")
        time.sleep(2)

    ss(page, "02_home")

    # 2. Click the database
    print(f"[2] Opening {DB}...")
    db_link = page.locator(f'a:has-text("{DB}")').first
    db_link.click()
    page.wait_for_load_state("networkidle")
    time.sleep(2)
    ss(page, "03_database_tables")

    # 3. Browse users table
    print("[3] Browsing users table...")
    page.locator('a:has-text("users")').first.click()
    page.wait_for_load_state("networkidle")
    time.sleep(1)
    ss(page, "04_users_table")

    # 4. Browse login_history
    print("[4] Browsing login_history table...")
    page.go_back()
    page.wait_for_load_state("networkidle")
    page.locator('a:has-text("login_history")').first.click()
    page.wait_for_load_state("networkidle")
    time.sleep(1)
    ss(page, "05_login_history")

    # 5. Browse otp_codes
    print("[5] Browsing otp_codes table...")
    page.go_back()
    page.wait_for_load_state("networkidle")
    page.locator('a:has-text("otp_codes")').first.click()
    page.wait_for_load_state("networkidle")
    time.sleep(1)
    ss(page, "06_otp_codes")

    time.sleep(3)
    br.close()
    print("\nDone.")
