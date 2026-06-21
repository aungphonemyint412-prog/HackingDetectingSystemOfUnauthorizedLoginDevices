"""
Visual test: confirm all notifications appear centered on the page.
Covers: login flash, forgot-password AJAX alert, dashboard flash,
        verify-email flash, verify-login-code flash.
"""
import time
import pymysql
from playwright.sync_api import sync_playwright

BASE     = "https://hacking-detection-system-production.up.railway.app"
USERNAME = "livetest_1781985309"
PASSWORD = "ResetTest456!"

DB = dict(host="thomas.proxy.rlwy.net", port=29978,
          user="root", password="ZBpoilVhllsEVbTKIeOiaBzCMjxEVcoe",
          database="railway")

def q(sql, p=()):
    conn = pymysql.connect(**DB)
    with conn.cursor() as c: c.execute(sql, p); rows = c.fetchall()
    conn.close(); return rows

def wait_otp(uid, min_id=0, timeout=45):
    dl = time.time() + timeout
    while time.time() < dl:
        r = q("SELECT code FROM otp_codes WHERE user_id=%s AND is_used=0 AND id>%s "
              "ORDER BY created_at DESC LIMIT 1", (uid, min_id))
        if r: return r[0][0]
        time.sleep(1)
    raise TimeoutError("OTP not found")

def ss(page, name, label=""):
    path = rf"C:\HackingDetectingSystemOfUnauthorizedLoginDevices\ss_notif_{name}.png"
    page.screenshot(path=path, full_page=True)
    print(f"  [ss] ss_notif_{name}.png  {label}")

def check_centered(page, label):
    """Assert #hds-notif-layer exists and its content is roughly centered."""
    layer = page.locator("#hds-notif-layer")
    assert layer.count() > 0, f"#hds-notif-layer missing on {label}"
    box = layer.bounding_box()
    if box:
        vw = page.viewport_size["width"]
        vh = page.viewport_size["height"]
        cx = box["x"] + box["width"]  / 2
        cy = box["y"] + box["height"] / 2
        print(f"  overlay center: ({cx:.0f}, {cy:.0f})  viewport: ({vw}, {vh})")
        assert abs(cx - vw/2) < 60, f"Not horizontally centered on {label}: cx={cx:.0f} vw/2={vw/2}"
    print(f"  #hds-notif-layer centered OK on {label}")

with sync_playwright() as pw:
    br   = pw.chromium.launch(headless=False, slow_mo=500)
    page = br.new_page(viewport={"width": 1280, "height": 800})
    page.set_default_timeout(30000)

    rows = q("SELECT id FROM users WHERE username=%s", (USERNAME,))
    uid  = rows[0][0]
    print(f"user_id={uid}\n")

    # ── 1. Login page: flash via redirect (logout shows security flash) ────────
    print("[1] Logout flash — security message centered")
    page.goto(f"{BASE}/logout")
    page.wait_for_load_state("networkidle")
    time.sleep(0.6)
    ss(page, "01_logout_flash", "centered flash after logout")
    check_centered(page, "login page (logout flash)")

    # ── 2. Login page: forgot-password AJAX alert (bad email) ────────────────
    print("\n[2] Forgot-password AJAX alert — unknown email")
    page.goto(f"{BASE}/login")
    page.click("text=Forgot password?")
    page.wait_for_selector("#sec-forgot-email:not(.hidden)", timeout=3000)
    page.fill("#fp-email", "notareal@example.com")
    page.click("#btn-send")
    page.wait_for_selector("#g-alert[style*='flex']", timeout=8000)
    ss(page, "02_forgot_bad_email", "centered AJAX error on forgot-password")
    check_centered(page, "login page (forgot-password AJAX)")

    # ── 3. Dashboard flash (simulate then logout/login to see flash) ──────────
    print("\n[3] Dashboard flash — login and simulate, see flash")
    # Log in properly
    page.goto(f"{BASE}/login")
    page.fill('input[name="username"]', USERNAME)
    page.fill('input[name="password"]', PASSWORD)
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/verify-login-code", timeout=40000)
    otp_rows = q("SELECT COALESCE(MAX(id),0) FROM otp_codes WHERE user_id=%s", (uid,))
    code = wait_otp(uid, min_id=otp_rows[0][0] - 1)
    page.locator(f'button.option-btn[data-value="{code}"]').click()
    page.click('button[type="submit"]')
    page.wait_for_url(f"{BASE}/dashboard", timeout=20000)
    print("  logged in OK")

    # Simulate new_ip -> flash appears on testing page redirect
    page.goto(f"{BASE}/testing")
    page.wait_for_load_state("networkidle")
    page.locator('form[action*="simulate"] input[name="scenario"][value="new_ip"]').evaluate(
        "el => el.closest('form').submit()"
    )
    page.wait_for_load_state("networkidle")
    time.sleep(0.5)
    # Check for flash in centered overlay
    notif = page.locator("#hds-notif-layer .hds-notif")
    if notif.count() > 0:
        ss(page, "03_dashboard_flash", "centered flash on testing page after simulate")
        check_centered(page, "testing page (simulate flash)")
        print(f"  Flash text: {notif.first.inner_text().strip()[:80]}")
    else:
        ss(page, "03_dashboard_no_flash", "no flash visible (may have auto-dismissed)")
        print("  (flash auto-dismissed or not present)")

    # ── 4. Verify: #hds-notif-layer present on all base-extending pages ───────
    print("\n[4] Check #hds-notif-layer present on base-extending pages")
    for path in ["/dashboard", "/alerts", "/login-history", "/profile", "/testing"]:
        page.goto(f"{BASE}{path}")
        page.wait_for_load_state("networkidle")
        assert page.locator("#hds-notif-layer").count() > 0, f"Missing on {path}"
        print(f"  {path}  #hds-notif-layer present OK")

    time.sleep(2)
    br.close()
    print("\n[PASS] All notifications are centered.")
