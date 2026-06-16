"""
Test the new-device login approval flow.
Registers a fresh user, logs in from an 'unknown' device,
checks the approval page appears, then enters the correct code.
"""
from playwright.sync_api import sync_playwright
import time, re

BASE  = 'http://localhost:5000'
TS    = int(time.time())
USER  = f'approvaltest{TS}'
EMAIL = f'godofwarx1234+approval{TS}@gmail.com'  # alias - delivers to godofwarx1234@gmail.com
PASS  = 'ApprovalTest123!'

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=600)
        ctx  = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = ctx.new_page()

        # 1. Register
        print(f'[1] Registering {USER}')
        page.goto(f'{BASE}/register')
        page.fill('#username', USER)
        page.fill('#email', EMAIL)
        page.fill('#password', PASS)
        page.fill('#confirm_password', PASS)
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        if '/link-gmail' in page.url:
            page.locator('form[action*="skip-gmail-link"] button').click()
            page.wait_for_load_state('networkidle')
        print(f'    URL: {page.url}')

        # 2. Login — new device → should trigger approval
        print('[2] Logging in (new device -- approval expected)')
        page.goto(f'{BASE}/login')
        page.fill('#username', USER)
        page.fill('#password', PASS)
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_approval_01_triggered.png')
        print(f'    URL: {page.url}')

        if '/verify-login-approval' in page.url:
            print('    PASS — approval page shown')
            print(f'    Check {EMAIL} for the 2-digit code')
            print('    Enter the code manually in the browser window that opened...')

            # Wait up to 60s for user to enter the code
            try:
                page.wait_for_url(f'{BASE}/dashboard', timeout=60000)
                page.screenshot(path='ss_approval_02_dashboard.png')
                print('    PASS — logged in after approval')
            except Exception:
                page.screenshot(path='ss_approval_02_timeout.png')
                print('    Timed out waiting for manual code entry')
        else:
            print(f'    UNEXPECTED URL: {page.url}')

        browser.close()
        print('\nDone.')

if __name__ == '__main__':
    run()
