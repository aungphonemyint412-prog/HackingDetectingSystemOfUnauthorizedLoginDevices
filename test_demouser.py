from playwright.sync_api import sync_playwright

BASE = 'http://localhost:5000'
USER = 'demouser'
PASS = 'Password123'

def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=500)
        ctx  = browser.new_context(viewport={'width': 1280, 'height': 800})
        page = ctx.new_page()

        # 1. Landing page
        print('[1] Landing page')
        page.goto(BASE)
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_01_landing.png')
        print(f'    URL: {page.url}')

        # 2. Login
        print('[2] Login with demouser')
        page.goto(f'{BASE}/login')
        page.fill('#username', USER)
        page.fill('#password', PASS)
        page.screenshot(path='ss_demo_02_login_filled.png')
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle', timeout=10000)
        page.screenshot(path='ss_demo_03_after_login.png')
        print(f'    URL: {page.url}')

        # 3. Dashboard
        print('[3] Dashboard')
        page.goto(f'{BASE}/dashboard')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_04_dashboard.png')
        print(f'    URL: {page.url}')

        # 4. Login history
        print('[4] Login history')
        page.goto(f'{BASE}/login-history')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_05_login_history.png')
        print(f'    URL: {page.url}')

        # 5. Alerts
        print('[5] Alerts')
        page.goto(f'{BASE}/alerts')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_06_alerts.png')
        print(f'    URL: {page.url}')

        # 6. Profile
        print('[6] Profile')
        page.goto(f'{BASE}/profile')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_07_profile.png')
        print(f'    URL: {page.url}')

        # 7. Testing panel
        print('[7] Testing / simulation panel')
        page.goto(f'{BASE}/testing')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_08_testing.png')
        print(f'    URL: {page.url}')

        # 8. Logout
        print('[8] Logout')
        page.goto(f'{BASE}/logout')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_demo_09_logout.png')
        print(f'    URL: {page.url}')

        browser.close()
        print('\nAll done.')

if __name__ == '__main__':
    run()
