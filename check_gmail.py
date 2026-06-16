"""Open Gmail inbox so the user can see the HDS verification code emails."""
from playwright.sync_api import sync_playwright
import time

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=300)
        ctx  = browser.new_context()
        page = ctx.new_page()

        print("[1] Opening Gmail inbox...")
        page.goto("https://mail.google.com/mail/u/0/#inbox")
        page.wait_for_load_state("networkidle", timeout=30000)

        # Take a screenshot so we can see what landed
        time.sleep(3)
        page.screenshot(path=r"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_gmail_01_inbox.png")
        print("  [screenshot] ss_gmail_01_inbox.png")

        # Click the first HDS email
        hds_row = page.locator('tr:has-text("[HDS]")').first
        if hds_row.count():
            hds_row.click()
            page.wait_for_load_state("networkidle")
            time.sleep(2)
            page.screenshot(path=r"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_gmail_02_email.png")
            print("  [screenshot] ss_gmail_02_email.png")
        else:
            print("  No [HDS] email found yet — may still be in transit.")

        input("\nPress Enter to close the browser...")
        browser.close()

if __name__ == "__main__":
    run()
