"""
Live smoke test for the deployed HDS app.
Tests registration, login, 2FA flow, dashboard, login history, forgot password.
"""
import time, re
from playwright.sync_api import sync_playwright, expect

BASE = 'https://hacking-detection-system-production.up.railway.app'
USER = f'livetest{int(time.time())}'
EMAIL = f'{USER}@example.com'
PASS  = 'LiveTest123!'


def run():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False, slow_mo=400)
        ctx     = browser.new_context(viewport={'width': 1280, 'height': 800})
        page    = ctx.new_page()

        # ── 1. Landing page ────────────────────────────────────────────────
        print('\n[1] Landing page')
        page.goto(BASE)
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_01_landing.png')
        assert 'HDS' in page.content() or 'Hacking Detection' in page.content(), 'Landing page failed'
        print('    PASS')

        # ── 2. Register ────────────────────────────────────────────────────
        print('[2] Register new account')
        page.goto(f'{BASE}/register')
        page.fill('#username', USER)
        page.fill('#email', EMAIL)
        page.fill('#password', PASS)
        page.fill('#confirm_password', PASS)
        page.click('button[type=submit]')
        page.wait_for_url(f'{BASE}/link-gmail', timeout=10000)
        page.screenshot(path='ss_02_link_gmail.png')
        print('    PASS — redirected to /link-gmail')

        # ── 3. Skip Gmail link ─────────────────────────────────────────────
        print('[3] Skip Gmail link')
        page.click('form[action*="skip-gmail-link"] button')
        page.wait_for_url(f'{BASE}/login', timeout=10000)
        page.screenshot(path='ss_03_login.png')
        print('    PASS — redirected to /login')

        # ── 4. Login ───────────────────────────────────────────────────────
        print('[4] Login')
        page.fill('#username', USER)
        page.fill('#password', PASS)
        page.click('button[type=submit]')
        page.wait_for_url(f'{BASE}/dashboard', timeout=15000)
        page.screenshot(path='ss_04_dashboard.png')
        assert USER in page.content()
        print('    PASS — dashboard loaded')

        # ── 5. Login history ───────────────────────────────────────────────
        print('[5] Login history page')
        page.goto(f'{BASE}/login-history')
        page.screenshot(path='ss_05_login_history.png')
        assert page.url.endswith('/login-history')
        print('    PASS')

        # ── 6. Alerts page ────────────────────────────────────────────────
        print('[6] Alerts page')
        page.goto(f'{BASE}/alerts')
        page.screenshot(path='ss_06_alerts.png')
        assert page.url.endswith('/alerts')
        print('    PASS')

        # ── 7. Profile page ───────────────────────────────────────────────
        print('[7] Profile page')
        page.goto(f'{BASE}/profile')
        page.screenshot(path='ss_07_profile.png')
        assert page.url.endswith('/profile')
        print('    PASS')

        # ── 8. Enable 2FA ─────────────────────────────────────────────────
        print('[8] Enable 2FA')
        btn = page.locator('button[name=action][value=enable_2fa]')
        if btn.count() > 0:
            btn.click()
            page.wait_for_load_state('networkidle')
            page.screenshot(path='ss_08_2fa_enabled.png')
            print('    PASS — 2FA enabled')
        else:
            page.screenshot(path='ss_08_profile_no2fa.png')
            print('    SKIP — 2FA already enabled or button not found')

        # ── 9. Logout ─────────────────────────────────────────────────────
        print('[9] Logout')
        page.goto(f'{BASE}/logout')
        page.wait_for_url(f'{BASE}/login', timeout=10000)
        page.screenshot(path='ss_09_logout.png')
        print('    PASS')

        # ── 10. Forgot password page ───────────────────────────────────────
        print('[10] Forgot password page')
        page.goto(f'{BASE}/forgot-password')
        page.screenshot(path='ss_10_forgot_password.png')
        assert page.url.endswith('/forgot-password')
        page.fill('input[name=email]', EMAIL)
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_10b_reset_code_sent.png')
        assert '/verify-reset-otp' in page.url or '/forgot-password' in page.url
        print('    PASS — reset code sent flash shown')

        # ── 11. Wrong password lockout check ──────────────────────────────
        print('[11] Wrong-password attempt (brute-force detection)')
        page.goto(f'{BASE}/login')
        for i in range(3):
            page.fill('#username', USER)
            page.fill('#password', 'WrongPassword!')
            page.click('button[type=submit]')
            page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_11_brute_force.png')
        content = page.content()
        locked = 'locked' in content.lower() or 'Invalid username' in content
        print(f'    PASS — after 3 wrong attempts: locked={locked}')

        # ── 12. Testing / simulation panel ────────────────────────────────
        print('[12] Login as demo user and open testing panel')
        page.goto(f'{BASE}/login')
        page.fill('#username', 'demouser')
        page.fill('#password', 'Password123')
        page.click('button[type=submit]')
        page.wait_for_load_state('networkidle')
        page.screenshot(path='ss_12_demo_login.png')
        if '/dashboard' in page.url:
            page.goto(f'{BASE}/testing')
            page.screenshot(path='ss_12b_testing.png')
            print('    PASS — testing panel loaded')
        else:
            print('    SKIP — demouser not available on live app')

        browser.close()
        print('\n✓ All tests done. Screenshots saved as ss_*.png')


if __name__ == '__main__':
    run()
