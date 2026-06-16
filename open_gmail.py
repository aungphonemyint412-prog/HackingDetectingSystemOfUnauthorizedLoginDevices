"""Open Gmail using the user's existing Chrome profile (already logged in)."""
import time, shutil, os
from playwright.sync_api import sync_playwright

SRC_PROFILE = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data\Profile 2")
TEMP_DIR    = r"C:\Temp\chrome_hds_profile"

# Copy profile once so Chrome lock doesn't block us
if not os.path.exists(os.path.join(TEMP_DIR, "Default")):
    print("Copying Chrome profile (first time, ~30s)...")
    os.makedirs(TEMP_DIR, exist_ok=True)
    shutil.copytree(SRC_PROFILE, os.path.join(TEMP_DIR, "Default"))
    print("Done.")

def ss(page, name):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_gmail_{name}.png"
    page.screenshot(path=path, full_page=False)
    print(f"  [screenshot] ss_gmail_{name}.png")

with sync_playwright() as p:
    ctx  = p.chromium.launch_persistent_context(
        user_data_dir=TEMP_DIR,
        executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        headless=False,
        slow_mo=400,
        viewport={"width": 1280, "height": 800},
    )
    page = ctx.pages[0] if ctx.pages else ctx.new_page()

    # Search for HDS emails
    print("[1] Opening Gmail search for [HDS]...")
    page.goto("https://mail.google.com/mail/u/0/#search/%5BHDS%5D+aungphonemyint412")
    page.wait_for_load_state("networkidle", timeout=30000)
    time.sleep(3)
    ss(page, "inbox_search")

    # Click first HDS email (verification code)
    rows = page.locator('tr.zA')
    print(f"  Found {rows.count()} email rows")
    if rows.count() > 0:
        rows.nth(0).click()
        page.wait_for_load_state("networkidle")
        time.sleep(2)
        ss(page, "email_01_verify")
        print("  Opened first email")
        page.go_back()
        page.wait_for_load_state("networkidle")
        time.sleep(1)

    if rows.count() > 1:
        rows.nth(1).click()
        page.wait_for_load_state("networkidle")
        time.sleep(2)
        ss(page, "email_02_login")
        print("  Opened second email")

    time.sleep(4)
    ctx.close()
    print("Done.")
