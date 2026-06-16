import pymysql, time
from playwright.sync_api import sync_playwright

BASE     = 'http://127.0.0.1:5000'
USERNAME = f'hdsuser_{int(time.time())}'
EMAIL    = 'godofwarx1234@gmail.com'
PASSWORD = 'TestPass123!'
DB       = dict(host='127.0.0.1', user='root', password='', database='hacking_detection_system')

def q(sql, p=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as c:
        c.execute(sql, p)
        rows = c.fetchall()
    conn.close()
    return rows

def otp(uid, timeout=20):
    dl = time.time() + timeout
    while time.time() < dl:
        r = q('SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 ORDER BY created_at DESC LIMIT 1', (uid,))
        if r: return r[0][0]
        time.sleep(0.5)
    raise TimeoutError('No OTP found')

def ss(page, name):
    path = rf'C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_hds_{name}.png'
    page.screenshot(path=path)
    print(f'  [screenshot] ss_hds_{name}.png')

with sync_playwright() as p:
    br   = p.chromium.launch(headless=False, slow_mo=500)
    page = br.new_page()
    page.set_default_timeout(15000)

    # 1. Register
    print(f'\n[1] Register {USERNAME}')
    page.goto(f'{BASE}/register')
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="email"]',    EMAIL)
    page.fill('input[name="password"]', PASSWORD)
    page.fill('input[name="confirm_password"]', PASSWORD)
    ss(page, '01_register')
    page.click('button[type="submit"]')
    page.wait_for_url(f'{BASE}/verify-email', timeout=10000)
    ss(page, '02_verify_email')

    uid  = q('SELECT id FROM users WHERE username=%s', (USERNAME,))[0][0]
    code = otp(uid)
    print(f'  User id={uid}  email OTP={code}')
    page.fill('#box0', code[0])
    page.fill('#box1', code[1])
    ss(page, '03_otp_filled')
    page.click('button[type="submit"]')
    page.wait_for_load_state('networkidle')
    if '/link-gmail' in page.url:
        skip = page.locator('a:has-text("Skip")')
        if skip.count():
            skip.first.click()
            page.wait_for_load_state('networkidle')
    ss(page, '04_after_verify')

    # 2. Logout
    print('\n[2] Logout')
    page.goto(f'{BASE}/logout')
    page.wait_for_load_state('networkidle')

    # 3. Login
    print(f'\n[3] Login {USERNAME}')
    page.goto(f'{BASE}/login')
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    ss(page, '05_login')
    page.click('button[type="submit"]')
    page.wait_for_url(f'{BASE}/verify-login-code', timeout=10000)
    ss(page, '06_options')

    time.sleep(1)
    lcode = otp(uid)
    print(f'  Login OTP={lcode}')
    page.locator(f'button.option-btn[data-value="{lcode}"]').click()
    ss(page, '07_selected')
    page.click('button[type="submit"]')
    page.wait_for_url(f'{BASE}/dashboard', timeout=10000)
    ss(page, '08_dashboard')

    # 4. Show MySQL data
    print('\n[4] Data in hacking_detection_system:')
    for row in q('SELECT id,username,email,email_verified,created_at FROM users WHERE id=%s', (uid,)):
        print(f'  users       -> id={row[0]}  username={row[1]}  email={row[2]}  verified={row[3]}  created={row[4]}')
    for row in q('SELECT login_status,ip_address,login_time FROM login_history WHERE user_id=%s', (uid,)):
        print(f'  login_history -> status={row[0]}  ip={row[1]}  time={row[2]}')
    for row in q('SELECT code,is_used FROM otp_codes WHERE user_id=%s', (uid,)):
        print(f'  otp_codes   -> code={row[0]}  used={row[1]}')

    time.sleep(3)
    br.close()
    print('\n[PASS] hacking_detection_system MySQL test complete!')
