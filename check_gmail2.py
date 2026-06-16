"""Open Gmail using existing Chrome profile (already logged in) and screenshot HDS emails."""
import time, shutil, os
from playwright.sync_api import sync_playwright

CHROME_USER_DATA = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\User Data")
# Copy Default profile to a temp dir so Chrome doesn't need to close
TEMP_PROFILE = r"C:\Temp\chrome_pw_profile"

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch_persistent_context(
            user_data_dir=TEMP_PROFILE,
            executable_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            headless=False,
            slow_mo=400,
            args=["--profile-directory=Default"],
        )
        page = browser.pages[0] if browser.pages else browser.new_page()

        print("[1] Opening Gmail inbox...")
        page.goto("https://mail.google.com/mail/u/0/#inbox")
        page.wait_for_load_state("networkidle", timeout=30000)
        time.sleep(3)
        page.screenshot(path=r"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_gmail_01_inbox.png")
        print("  [screenshot] ss_gmail_01_inbox.png")

        # Look for HDS emails
        hds_row = page.locator('tr:has-text("[HDS]")').first
        if hds_row.count():
            hds_row.click()
            page.wait_for_load_state("networkidle")
            time.sleep(2)
            page.screenshot(path=r"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_gmail_02_hds_email.png")
            print("  [screenshot] ss_gmail_02_hds_email.png")
            print("  Found HDS email!")
        else:
            print("  No [HDS] email found in inbox.")

        time.sleep(5)
        browser.close()

if __name__ == "__main__":
    # Ensure temp profile dir exists and copy Chrome's Default profile into it
    os.makedirs(TEMP_PROFILE, exist_ok=True)
    default_src = os.path.join(CHROME_USER_DATA, "Default")
    default_dst = os.path.join(TEMP_PROFILE, "Default")
    if not os.path.exists(default_dst):
        print("Copying Chrome profile (first run, may take a moment)...")
        shutil.copytree(default_src, default_dst)
    run()
