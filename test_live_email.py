from playwright.sync_api import sync_playwright
import time

BASE = 'https://hacking-detection-system-production.up.railway.app'
USER = f'emailtest{int(time.time())}'
EMAIL = f'{USER}@example.com'
PASS  = 'LiveTest123!'

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=600)
        ctx  = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = ctx.new_page()

        # Register a fresh account
        print('[1] Registering new account')
        page.goto(f'{BASE}/register')
        page.fill('#username', USER)
        page.fill('#email', EMAIL)
        page.fill('#password', PASS)
        page.fill('#confirm_password', PASS)
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle', timeout=15000)
        page.screenshot(path='ss_live_email_01_register.png')
        print(f'    URL: {page.url}')

        # Skip Gmail link if shown
        if '/link-gmail' in page.url:
            page.screenshot(path='ss_live_email_01c_linkgmail.png')
            skip_btn = page.locator('form[action*="skip-gmail-link"] button, a:has-text("Skip"), button:has-text("Skip")')
            print(f'    Skip buttons found: {skip_btn.count()}')
            if skip_btn.count() > 0:
                with page.expect_navigation(timeout=30000):
                    skip_btn.first.click()
            page.wait_for_load_state('networkidle', timeout=10000)
            page.screenshot(path='ss_live_email_01d_after_skip.png')
            print(f'    URL after skip: {page.url}')

        # Login
        print('[2] Logging in')
        page.goto(f'{BASE}/login')
        page.fill('#username', USER)
        page.fill('#password', PASS)
        with page.expect_navigation(timeout=60000):
            page.click('button[type=submit]', timeout=60000)
        page.wait_for_load_state('networkidle', timeout=30000)
        page.screenshot(path='ss_live_email_01b_after_login.png')
        print(f'    URL after login: {page.url}')
        # Handle 2FA verify if triggered
        if '/verify-2fa' in page.url:
            print('    2FA page detected — entering OTP')
            otp_input = page.locator('input[name=otp], input[name=code], input[type=text]').first
            otp_input.fill('000000')
            page.click('button[type=submit]')
            page.wait_for_load_state('networkidle', timeout=10000)
        print(f'    Final URL: {page.url}')

        # Go to testing panel and send test email
        print('[3] Opening Testing panel')
        page.goto(f'{BASE}/testing')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_live_email_02_testing.png')

        print('[4] Triggering test email simulation')
        page.evaluate("""
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/testing/simulate';
            const input = document.createElement('input');
            input.name = 'scenario';
            input.value = 'test_email';
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        """)
        page.wait_for_load_state('networkidle', timeout=20000)
        page.screenshot(path='ss_live_email_03_result.png')

        flash = page.locator('.alert, [class*="alert"]')
        for i in range(flash.count()):
            text = flash.nth(i).inner_text().strip()
            if text:
                print(f'    {text}')

        # Also trigger a suspicious login simulation to fire a real alert email
        print('[5] Triggering suspicious login simulation (New IP)')
        page.evaluate("""
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/testing/simulate';
            const input = document.createElement('input');
            input.name = 'scenario';
            input.value = 'new_ip';
            form.appendChild(input);
            document.body.appendChild(form);
            form.submit();
        """)
        page.wait_for_load_state('networkidle', timeout=20000)
        page.screenshot(path='ss_live_email_04_sim_result.png')

        flash2 = page.locator('.alert, [class*="alert"]')
        for i in range(flash2.count()):
            text = flash2.nth(i).inner_text().strip()
            if text:
                print(f'    {text}')

        browser.close()
        print(f'\nDone. Check aungphonemyint412@gmail.com for alert emails.')

if __name__ == '__main__':
    run()
