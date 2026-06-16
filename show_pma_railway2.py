"""Show Railway MySQL data in phpMyAdmin via direct URL navigation."""
import time
from playwright.sync_api import sync_playwright

PMA = "http://localhost/phpmyadmin"
SERVER = 2
DB = "railway"

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_pma2_{name}.png"
    page.screenshot(path=path, full_page=False)
    print(f"  [screenshot] ss_pma2_{name}.png")

def goto(page, table=None, action="browse"):
    if table:
        url = f"{PMA}/index.php?server={SERVER}&db={DB}&table={table}&action={action}"
    else:
        url = f"{PMA}/index.php?server={SERVER}&db={DB}"
    page.goto(url, wait_until="domcontentloaded", timeout=90000)
    time.sleep(5)

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=300)
    page = br.new_page(viewport={"width": 1400, "height": 900})
    page.set_default_timeout(90000)

    print("[1] phpMyAdmin — Railway MySQL database overview...")
    goto(page)
    ss(page, "01_db_overview")

    print("[2] users table...")
    goto(page, "users")
    ss(page, "02_users")

    print("[3] login_history table...")
    goto(page, "login_history")
    ss(page, "03_login_history")

    print("[4] otp_codes table...")
    goto(page, "otp_codes")
    ss(page, "04_otp_codes")

    print("[5] alerts table...")
    goto(page, "alerts")
    ss(page, "05_alerts")

    time.sleep(2)
    br.close()
    print("Done.")
