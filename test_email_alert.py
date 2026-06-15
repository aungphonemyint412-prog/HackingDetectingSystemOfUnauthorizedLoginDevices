from playwright.sync_api import sync_playwright

BASE = 'http://localhost:5000'

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=600)
        ctx  = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = ctx.new_page()

        print('[1] Logging in as demouser')
        page.goto(f'{BASE}/login')
        page.fill('#username', 'demouser')
        page.fill('#password', 'Password123')
        page.click('button[type=submit]')
        page.wait_for_url(f'{BASE}/dashboard', timeout=10000)

        print('[2] Opening Testing panel')
        page.goto(f'{BASE}/testing')
        page.wait_for_load_state('networkidle')

        print('[3] Sending test email')
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
        page.screenshot(path='ss_email_test.png')

        flash = page.locator('.alert, [class*="alert"]')
        for i in range(flash.count()):
            text = flash.nth(i).inner_text().strip()
            if text:
                print(f'    {text}')

        browser.close()
        print('\nDone.')

if __name__ == '__main__':
    run()
