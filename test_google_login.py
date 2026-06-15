from playwright.sync_api import sync_playwright

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=600)
        ctx  = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = ctx.new_page()

        print('[1] Loading login page')
        page.goto('http://localhost:5000/login')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_google_01_login.png')

        print('[2] Clicking Sign in with Google (login page)')
        page.locator('a[href*="google"], a:has-text("Google"), button:has-text("Google")').first.click()
        page.wait_for_load_state('networkidle', timeout=8000)
        page.screenshot(path='ss_google_02_select.png')
        print(f'    URL: {page.url}')

        print('[3] Clicking Sign in with Google (google-select page)')
        btn2 = page.locator('a:has-text("Sign in with Google"), button:has-text("Sign in with Google")')
        if btn2.count() > 0:
            btn2.first.click()
            try:
                page.wait_for_load_state('networkidle', timeout=12000)
            except Exception:
                pass
            page.screenshot(path='ss_google_03_oauth.png')
            print(f'    URL: {page.url}')
            print('    Screenshot: ss_google_03_oauth.png')
        else:
            print('    No second button found')

        browser.close()
        print('\nDone.')

if __name__ == '__main__':
    run()
