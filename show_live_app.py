"""Open the live Railway app and screenshot key pages."""
import time
from playwright.sync_api import sync_playwright

BASE = "https://hacking-detection-system-production.up.railway.app"

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_live_{name}.png"
    page.screenshot(path=path, full_page=False)
    print(f"  [screenshot] ss_live_{name}.png")

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=400)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    print("[1] Landing page...")
    page.goto(BASE)
    page.wait_for_load_state("networkidle")
    ss(page, "01_landing")

    print("[2] Register page...")
    page.goto(f"{BASE}/register")
    page.wait_for_load_state("networkidle")
    ss(page, "02_register")

    print("[3] Login page...")
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")
    ss(page, "03_login")

    print("[4] Logging in as aunguser...")
    page.fill('input[name="username"]', "aunguser_1781625834")
    page.fill('input[name="password"]', "TestPass123!")
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=12000)
    ss(page, "04_verify_code")

    # Pick any visible option (wrong one — just to show the page)
    # then go back
    print("[5] Back to login...")
    page.goto(f"{BASE}/login")
    page.wait_for_load_state("networkidle")

    time.sleep(2)
    br.close()
    print("Done.")
