from playwright.sync_api import sync_playwright
import time

BASE  = 'https://hacking-detection-system-production.up.railway.app'
USER  = f'aungphone{int(time.time())}'
EMAIL = 'godofwarx1234@gmail.com'
PASS  = 'LiveTest123!'

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=600)
        ctx  = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = ctx.new_page()

        # Register with real email
        print(f'[1] Registering as {USER} with {EMAIL}')
        page.goto(f'{BASE}/register')
        page.fill('#username', USER)
        page.fill('#email', EMAIL)
        page.fill('#password', PASS)
        page.fill('#confirm_password', PASS)
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle', timeout=15000)
        page.screenshot(path='ss_real_01_register.png')
        print(f'    URL: {page.url}')

        # Skip Gmail link
        if '/link-gmail' in page.url:
            skip = page.locator('form[action*="skip-gmail-link"] button, a:has-text("Skip"), button:has-text("Skip")')
            if skip.count() > 0:
                with page.expect_navigation(timeout=20000):
                    skip.first.click()
            page.wait_for_load_state('networkidle', timeout=10000)

        # Login
        print('[2] Logging in')
        page.goto(f'{BASE}/login')
        page.fill('#username', USER)
        page.fill('#password', PASS)
        with page.expect_navigation(timeout=60000):
            page.click('button[type=submit]', timeout=60000)
        page.wait_for_load_state('networkidle', timeout=30000)
        page.screenshot(path='ss_real_02_dashboard.png')
        print(f'    URL: {page.url}')

        # Trigger suspicious login simulation
        print('[3] Triggering New IP suspicious login simulation')
        page.goto(f'{BASE}/testing')
        page.wait_for_load_state('networkidle')
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
        page.screenshot(path='ss_real_03_sim_result.png')

        flash = page.locator('.alert, [class*="alert"]')
        for i in range(flash.count()):
            text = flash.nth(i).inner_text().strip()
            if text:
                print(f'    {text}')

        browser.close()
        print(f'\nDone. Check {EMAIL} for the alert email.')

if __name__ == '__main__':
    run()
