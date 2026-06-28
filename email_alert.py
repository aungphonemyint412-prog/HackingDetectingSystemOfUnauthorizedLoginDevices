"""
Gmail SMTP alert system.
Sends HTML + plain-text emails for security events.
"""
import smtplib
import time
import os
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


# ── Severity ──────────────────────────────────────────────────────────────

def get_severity(risk_score: int) -> str:
    if risk_score == 0:   return 'Informational'
    if risk_score <= 25:  return 'Low'
    if risk_score <= 50:  return 'Medium'
    if risk_score <= 75:  return 'High'
    return 'Critical'


_SEVERITY_COLORS = {
    'Informational': '#0284c7',
    'Low':           '#16a34a',
    'Medium':        '#ca8a04',
    'High':          '#ea580c',
    'Critical':      '#dc2626',
}


# ── Shared helpers ─────────────────────────────────────────────────────────

def _credentials() -> tuple[str, str]:
    return os.environ.get('MAIL_USERNAME', ''), os.environ.get('MAIL_PASSWORD', '')


def _get_email_api_key(key_name: str) -> str:
    """Read API key from env var first, then DB (Railway v2 env var bug workaround)."""
    key = os.environ.get(key_name, '')
    if key:
        return key
    try:
        import pymysql
        db_url = os.environ.get('DATABASE_URL', '')
        if not db_url:
            return ''
        import re as _re
        m = _re.match(r'mysql(?:\+pymysql)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)', db_url)
        if not m:
            return ''
        conn = pymysql.connect(host=m.group(3), port=int(m.group(4)),
                               user=m.group(1), password=m.group(2),
                               database=m.group(5), connect_timeout=5)
        with conn.cursor() as c:
            c.execute("SELECT val FROM app_config WHERE key_name=%s LIMIT 1", (key_name,))
            row = c.fetchone()
        conn.close()
        return row[0] if row else ''
    except Exception as exc:
        print(f'[email_alert] DB key lookup ({key_name}) failed: {exc}')
        return ''


def _send_via_brevo(msg: MIMEMultipart) -> bool:
    """Send using Brevo (Sendinblue) HTTP API — no domain verification needed."""
    import requests as _req
    api_key = _get_email_api_key('BREVO_API_KEY')
    if not api_key:
        return None  # not configured, fall through
    sender_email, _ = _credentials()
    plain_text = html_text = ''
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == 'text/plain':
            plain_text = part.get_payload(decode=True).decode('utf-8', errors='replace')
        elif ct == 'text/html':
            html_text  = part.get_payload(decode=True).decode('utf-8', errors='replace')
    try:
        r = _req.post(
            'https://api.brevo.com/v3/smtp/email',
            headers={'api-key': api_key, 'Content-Type': 'application/json'},
            json={
                'sender':      {'email': sender_email or 'noreply@hds.dev', 'name': 'HDS Security'},
                'to':          [{'email': msg['To']}],
                'subject':     msg['Subject'],
                'htmlContent': html_text or f'<pre>{plain_text}</pre>',
                'textContent': plain_text,
            },
            timeout=15,
        )
        if r.status_code in (200, 201):
            return True
        if r.status_code == 403:
            print(f'[email_alert] Brevo not activated – falling back to SMTP')
            return None  # fall through to SMTP fallback
        print(f'[email_alert] Brevo API error {r.status_code}: {r.text[:300]}')
        return None  # always fall through on error so SMTP can try
    except Exception as exc:
        print(f'[email_alert] Brevo API exception: {exc}')
        return None  # fall through to SMTP fallback


def _send_via_gmail_api(msg: MIMEMultipart) -> bool:
    """Send via Gmail REST API over HTTPS — works on Railway where SMTP is blocked."""
    import base64
    import requests as _req
    refresh_token = _get_email_api_key('GMAIL_REFRESH_TOKEN')
    if not refresh_token:
        return None
    client_id     = os.environ.get('GOOGLE_CLIENT_ID', '')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    if not client_id or not client_secret:
        return None
    try:
        tok = _req.post('https://oauth2.googleapis.com/token', data={
            'client_id':     client_id,
            'client_secret': client_secret,
            'refresh_token': refresh_token,
            'grant_type':    'refresh_token',
        }, timeout=10)
        if tok.status_code != 200:
            print(f'[email_alert] Gmail token refresh failed: {tok.text[:200]}')
            return None
        access_token = tok.json().get('access_token', '')
        if not access_token:
            return None
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode('utf-8')
        resp = _req.post(
            'https://gmail.googleapis.com/gmail/v1/users/me/messages/send',
            headers={'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'},
            json={'raw': raw},
            timeout=15,
        )
        if resp.status_code in (200, 201):
            return True
        print(f'[email_alert] Gmail API send failed {resp.status_code}: {resp.text[:200]}')
        return None
    except Exception as exc:
        print(f'[email_alert] Gmail API exception: {exc}')
        return None


def _smtp_send_blocking(msg: MIMEMultipart, retries: int = 3) -> bool:
    # 1. Try Brevo (HTTP API, works on Railway)
    brevo_result = _send_via_brevo(msg)
    if brevo_result is not None:
        return brevo_result

    # 2. Try Gmail API (HTTPS, works on Railway even when SMTP is blocked)
    gmail_result = _send_via_gmail_api(msg)
    if gmail_result is not None:
        return gmail_result

    # 3. Fall back to SMTP (local dev only)
    sender, app_pwd = _credentials()
    if not sender or not app_pwd:
        return False
    for attempt in range(retries):
        for port, use_ssl in [(465, True), (587, False)]:
            try:
                if use_ssl:
                    with smtplib.SMTP_SSL('smtp.gmail.com', port, timeout=15) as srv:
                        srv.login(sender, app_pwd)
                        srv.sendmail(sender, msg['To'], msg.as_string())
                else:
                    with smtplib.SMTP('smtp.gmail.com', port, timeout=15) as srv:
                        srv.ehlo(); srv.starttls()
                        srv.login(sender, app_pwd)
                        srv.sendmail(sender, msg['To'], msg.as_string())
                return True
            except Exception as exc:
                print(f'[email_alert] SMTP port {port} attempt {attempt+1} failed: {exc}')
        if attempt < retries - 1:
            time.sleep(1)
    return False


def _smtp_send(msg: MIMEMultipart, retries: int = 3) -> bool:
    """Fire-and-forget: sends in a background thread without blocking the response."""
    t = threading.Thread(target=_smtp_send_blocking, args=(msg, retries), daemon=False)
    t.start()
    return True


def _base_msg(subject: str, recipient: str) -> MIMEMultipart:
    sender, _ = _credentials()
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From']    = f'HDS Security <{sender}>'
    msg['To']      = recipient
    return msg


def _detail_rows_html(rows: list[tuple[str, str]]) -> str:
    html = ''
    for i, (label, value) in enumerate(rows):
        bg = 'background:#f1f5f9;' if i % 2 == 0 else ''
        html += (
            f'<tr style="{bg}">'
            f'<td style="border:1px solid #e2e8f0;color:#64748b;width:40%;'
            f'font-size:13px;font-weight:600;padding:10px;">{label}</td>'
            f'<td style="border:1px solid #e2e8f0;color:#1e293b;'
            f'font-size:13px;padding:10px;">{value}</td>'
            f'</tr>'
        )
    return html


def _wrap_html(header_color: str, header_title: str, header_sub: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f4f6fb;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 20px;">
        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#fff;border-radius:8px;
                      box-shadow:0 2px 8px rgba(0,0,0,.12);overflow:hidden;">
          <tr>
            <td style="background:{header_color};padding:28px 32px;text-align:center;">
              <h1 style="margin:0;color:#fff;font-size:22px;">{header_title}</h1>
              <p style="margin:6px 0 0;color:rgba(255,255,255,.8);font-size:14px;">{header_sub}</p>
            </td>
          </tr>
          <tr><td style="padding:32px;">{body}</td></tr>
          <tr>
            <td style="background:#f8fafc;border-top:1px solid #e2e8f0;
                       padding:16px 32px;text-align:center;">
              <p style="margin:0;color:#94a3b8;font-size:12px;">
                Automated message from <strong>Hacking Detection System (HDS)</strong>.
                Do not reply.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


# ── Alert email ────────────────────────────────────────────────────────────

def send_alert_email(
    recipient: str,
    username: str,
    ip_address: str,
    ua_info: dict,
    reasons: list[str],
    login_time: datetime,
    location: str = '',
    risk_score: int = 0,
    recommendations: list | None = None,
    confirm_url: str = '',
    deny_url: str = '',
) -> bool:
    if recommendations is None:
        recommendations = ['If this was NOT you, change your password immediately.']

    severity      = get_severity(risk_score)
    badge_color   = _SEVERITY_COLORS[severity]
    reasons_html  = ''.join(f'<li>{r}</li>' for r in reasons)
    recs_html     = ''.join(f'<li>{r}</li>' for r in recommendations)
    reasons_plain = '\n'.join(f'  • {r}' for r in reasons)

    detail_rows = [
        ('DATE & TIME',     login_time.strftime('%Y-%m-%d %H:%M:%S UTC')),
        ('IP ADDRESS',      ip_address),
        ('LOCATION',        location or 'Unknown'),
        ('DEVICE',          ua_info.get('device_type', 'Unknown')),
        ('BROWSER',         ua_info.get('browser',     'Unknown')),
        ('OPERATING SYSTEM', ua_info.get('os',         'Unknown')),
    ]

    was_this_you = ''
    if confirm_url and deny_url:
        was_this_you = f"""
        <div style="background:#f0f9ff;border:1px solid #bae6fd;
                    border-radius:8px;padding:20px;margin:20px 0;text-align:center;">
          <p style="margin:0 0 14px;color:#0369a1;font-weight:700;font-size:15px;">
            Was this you?
          </p>
          <p style="margin:0 0 16px;color:#0c4a6e;font-size:13px;">
            Confirm or deny this login to keep your account secure.
          </p>
          <a href="{confirm_url}"
             style="display:inline-block;background:#16a34a;color:#fff;
                    text-decoration:none;padding:10px 24px;border-radius:6px;
                    font-weight:700;font-size:14px;margin:0 6px;">
            &#10003; Yes, this was me
          </a>
          <a href="{deny_url}"
             style="display:inline-block;background:#dc2626;color:#fff;
                    text-decoration:none;padding:10px 24px;border-radius:6px;
                    font-weight:700;font-size:14px;margin:0 6px;">
            &#10007; No, secure my account
          </a>
        </div>"""

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 16px;">
        Suspicious login activity was detected on your account.
      </p>

      <div style="margin:0 0 20px;">
        <span style="background:{badge_color};color:#fff;border-radius:20px;
                     padding:4px 14px;font-size:13px;font-weight:700;margin-right:8px;">
          {severity}
        </span>
        <span style="background:#f1f5f9;color:#334155;border-radius:20px;
                     padding:4px 14px;font-size:13px;font-weight:700;">
          Risk Score: {risk_score}/100
        </span>
      </div>

      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html(detail_rows)}
      </table>

      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:16px;margin-bottom:16px;">
        <p style="margin:0 0 10px;color:#dc2626;font-weight:700;font-size:14px;">
          Suspicious activity detected:
        </p>
        <ul style="margin:0;padding-left:20px;color:#7f1d1d;font-size:13px;">
          {reasons_html}
        </ul>
      </div>

      <div style="background:#f0fdf4;border:1px solid #bbf7d0;
                  border-radius:6px;padding:16px;margin-bottom:16px;">
        <p style="margin:0 0 8px;color:#15803d;font-weight:700;font-size:14px;">
          Security recommendations:
        </p>
        <ul style="margin:0;padding-left:20px;color:#166534;font-size:13px;">
          {recs_html}
        </ul>
      </div>

      {was_this_you}
    """

    plain = f"""Security Alert – Suspicious Login Detected

Dear {username},

Risk Score: {risk_score}/100

  Date/Time : {login_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
  IP Address: {ip_address}
  Location  : {location or 'Unknown'}
  Device    : {ua_info.get('device_type', 'Unknown')}
  Browser   : {ua_info.get('browser', 'Unknown')}
  OS        : {ua_info.get('os', 'Unknown')}

Suspicious Reasons:
{reasons_plain}

{'Confirm login: ' + confirm_url if confirm_url else ''}
{'Deny & secure account: ' + deny_url if deny_url else ''}

-- Hacking Detection System (automated alert)
"""

    html = _wrap_html(badge_color, '&#9888;&#65039; Security Alert', f'{severity} — Suspicious Login Detected', body)
    msg  = _base_msg(f'[HDS] [{severity}] Security Alert: Suspicious Login Detected', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── OTP email ──────────────────────────────────────────────────────────────

def send_otp_email(recipient: str, username: str, otp_code: str,
                   expires_minutes: int = 5,
                   ip_address: str = '',
                   location: str = '',
                   ua_info=None,
                   purpose: str = 'login') -> bool:
    """Send a 6-digit OTP code (login 2FA or password reset) via Gmail."""
    is_reset     = purpose == 'reset'
    header_title = 'Password Reset Code'       if is_reset else 'Login Verification'
    header_sub   = 'Reset your HDS password'   if is_reset else 'Two-Factor Authentication Code'
    subject_line = f'[HDS] Your password reset code: {otp_code}' if is_reset \
                   else f'[HDS] Your login verification code: {otp_code}'
    action_label = 'password reset' if is_reset else 'login'

    location_section_html = ''
    location_block_plain  = ''

    if ip_address:
        rows = [('IP ADDRESS', ip_address), ('LOCATION', location or 'Unknown')]
        if ua_info:
            rows += [
                ('DEVICE',  ua_info.get('device_type', 'Unknown')),
                ('BROWSER', ua_info.get('browser',      'Unknown')),
                ('OS',      ua_info.get('os',           'Unknown')),
            ]
        location_section_html = (
            '<p style="margin:0 0 8px;color:#475569;font-size:13px;font-weight:600;">'
            'Login attempt details:</p>'
            '<table width="100%" cellpadding="0" cellspacing="0"'
            ' style="border-collapse:collapse;margin-bottom:24px;">'
            f'{_detail_rows_html(rows)}</table>'
        )
        location_block_plain = (
            f'\nLogin attempt details:\n'
            f'  IP Address : {ip_address}\n'
            f'  Location   : {location or "Unknown"}\n'
        )
        if ua_info:
            location_block_plain += (
                f'  Device     : {ua_info.get("device_type", "Unknown")}\n'
                f'  Browser    : {ua_info.get("browser", "Unknown")}\n'
                f'  OS         : {ua_info.get("os", "Unknown")}\n'
            )

    if is_reset:
        warning_html  = ('<strong>&#9888; Never share this code.</strong> '
                         'If you did not request a password reset, ignore this email.')
        warning_plain = 'If you did not request a password reset, ignore this email.'
    else:
        warning_html  = ('<strong>&#9888; Never share this code.</strong> '
                         'If you did not attempt to log in, change your password immediately.')
        warning_plain = 'If you did not attempt to log in, change your password immediately.'

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 28px;">
        Use the verification code below to complete your {action_label}.
        This code expires in <strong>{expires_minutes} minutes</strong>.
      </p>
      <div style="text-align:center;margin:0 0 28px;">
        <div style="display:inline-block;background:#f1f5f9;
                    border:2px dashed #2563eb;border-radius:12px;padding:20px 40px;">
          <span style="font-size:2.4rem;font-weight:900;letter-spacing:12px;
                       color:#1e293b;font-family:'Courier New',monospace;">
            {otp_code}
          </span>
        </div>
      </div>
      {location_section_html}
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:14px;margin-bottom:20px;">
        <p style="margin:0;color:#dc2626;font-size:13px;">{warning_html}</p>
      </div>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;
                  border-radius:6px;padding:14px;">
        <p style="margin:0;color:#15803d;font-size:13px;">
          This code is valid for <strong>{expires_minutes} minutes</strong> and can only be used once.
        </p>
      </div>
    """

    plain = f"""{'Password Reset Code' if is_reset else 'Login Verification Code'} – HDS

Dear {username},

Your one-time {action_label} code is:

    {otp_code}
{location_block_plain}
This code expires in {expires_minutes} minutes and can only be used once.

{warning_plain}

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#2563eb', f'&#128274; {header_title}', header_sub, body)
    msg  = _base_msg(subject_line, recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send_blocking(msg)


# ── Login notification email ───────────────────────────────────────────────

def send_login_notification_email(
    recipient: str,
    username: str,
    ip: str,
    location: str,
    ua_info: dict,
    login_time: datetime,
) -> bool:
    """Quiet notification sent on every successful non-suspicious login."""
    detail_rows = [
        ('DATE & TIME',     login_time.strftime('%Y-%m-%d %H:%M:%S UTC')),
        ('IP ADDRESS',      ip),
        ('LOCATION',        location or 'Unknown'),
        ('DEVICE',          ua_info.get('device_type', 'Unknown')),
        ('BROWSER',         ua_info.get('browser',     'Unknown')),
        ('OPERATING SYSTEM', ua_info.get('os',         'Unknown')),
    ]

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">
        A successful login to your account was recorded.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html(detail_rows)}
      </table>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:14px;">
        <p style="margin:0;color:#dc2626;font-size:13px;">
          If this was <strong>not you</strong>, use <em>Forgot Password</em> on the login
          page to immediately secure your account.
        </p>
      </div>
    """

    plain = f"""New Login Notification – HDS

Dear {username},

A successful login was recorded on your account.

  Date/Time : {login_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
  IP Address: {ip}
  Location  : {location or 'Unknown'}
  Device    : {ua_info.get('device_type', 'Unknown')}
  Browser   : {ua_info.get('browser', 'Unknown')}
  OS        : {ua_info.get('os', 'Unknown')}

If this was NOT you, use Forgot Password on the login page to secure your account.

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#0284c7', '&#128274; New Sign-In', 'Login notification for your account', body)
    msg  = _base_msg('[HDS] New sign-in to your account', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── Password changed email ─────────────────────────────────────────────────

def send_password_changed_email(
    recipient: str,
    username: str,
    ip: str,
    location: str,
    changed_at: datetime,
) -> bool:
    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">
        Your account password was changed successfully.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html([
            ('DATE & TIME', changed_at.strftime('%Y-%m-%d %H:%M:%S UTC')),
            ('IP ADDRESS',  ip),
            ('LOCATION',    location or 'Unknown'),
        ])}
      </table>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:14px;">
        <p style="margin:0;color:#dc2626;font-size:13px;">
          If you did <strong>not</strong> make this change, your account may be compromised.
          Use <em>Forgot Password</em> immediately and contact support.
        </p>
      </div>
    """

    plain = f"""Password Changed – HDS

Dear {username},

Your account password was changed at {changed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
from IP {ip} ({location or 'Unknown'}).

If you did NOT make this change, use Forgot Password immediately.

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#d97706', '&#128273; Password Changed', 'Your password was updated', body)
    msg  = _base_msg('[HDS] Your password was changed', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── Email address changed email ────────────────────────────────────────────

def send_email_changed_email(
    recipient: str,
    username: str,
    old_email: str,
    new_email: str,
    ip: str,
    location: str,
    changed_at: datetime,
) -> bool:
    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">
        The email address on your account was changed.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html([
            ('DATE & TIME', changed_at.strftime('%Y-%m-%d %H:%M:%S UTC')),
            ('FROM',        old_email),
            ('TO',          new_email),
            ('IP ADDRESS',  ip),
            ('LOCATION',    location or 'Unknown'),
        ])}
      </table>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:14px;">
        <p style="margin:0;color:#dc2626;font-size:13px;">
          If you did <strong>not</strong> make this change, contact support immediately.
        </p>
      </div>
    """

    plain = f"""Email Address Changed – HDS

Dear {username},

Your account email was changed at {changed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}.
  From: {old_email}
  To  : {new_email}
  IP  : {ip} ({location or 'Unknown'})

If you did NOT make this change, contact support immediately.

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#d97706', '&#9993;&#65039; Email Address Changed', 'Account email was updated', body)
    msg  = _base_msg('[HDS] Your email address was changed', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── 2FA status changed email ───────────────────────────────────────────────

def send_2fa_changed_email(
    recipient: str,
    username: str,
    enabled: bool,
    ip: str,
    location: str,
    changed_at: datetime,
) -> bool:
    action      = 'enabled' if enabled else 'disabled'
    color       = '#16a34a' if enabled else '#d97706'
    icon        = '&#128275;' if enabled else '&#128274;'
    description = 'Two-Factor Authentication is now active on your account.' if enabled \
                  else 'Two-Factor Authentication has been turned off.'

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">{description}</p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html([
            ('DATE & TIME', changed_at.strftime('%Y-%m-%d %H:%M:%S UTC')),
            ('IP ADDRESS',  ip),
            ('LOCATION',    location or 'Unknown'),
            ('STATUS',      f'2FA {action.upper()}'),
        ])}
      </table>
      {'<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:14px;"><p style="margin:0;color:#15803d;font-size:13px;">2FA adds an extra layer of protection. Every login now requires a one-time code sent to your email.</p></div>' if enabled else
       '<div style="background:#fff5f5;border:1px solid #fecaca;border-radius:6px;padding:14px;"><p style="margin:0;color:#dc2626;font-size:13px;">If you did <strong>not</strong> disable 2FA, change your password and re-enable it immediately.</p></div>'}
    """

    plain = f"""Two-Factor Authentication {action.title()} – HDS

Dear {username},

2FA was {action} on your account at {changed_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
from IP {ip} ({location or 'Unknown'}).

{'If you did NOT make this change, secure your account immediately.' if not enabled else ''}

-- Hacking Detection System (automated message)
"""

    html = _wrap_html(color, f'{icon} 2FA {action.title()}', f'Two-Factor Authentication {action}', body)
    msg  = _base_msg(f'[HDS] Two-Factor Authentication {action}', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── Account locked email ───────────────────────────────────────────────────

def send_account_locked_email(
    recipient: str,
    username: str,
    reason: str,
    locked_until: datetime | None = None,
) -> bool:
    unlock_note = (
        f'<p style="margin:6px 0 0;color:#fca5a5;font-size:13px;">'
        f'Auto-unlocks at {locked_until.strftime("%H:%M UTC")} if this was a temporary lockout.</p>'
    ) if locked_until else ''

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">
        Your account has been locked due to suspicious activity.
      </p>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:16px;margin-bottom:20px;">
        <p style="margin:0 0 6px;color:#dc2626;font-weight:700;font-size:14px;">
          Reason: {reason}
        </p>
        {unlock_note}
      </div>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;
                  border-radius:6px;padding:14px;">
        <p style="margin:0 0 8px;color:#15803d;font-weight:700;font-size:14px;">
          To unlock your account:
        </p>
        <ul style="margin:0;padding-left:20px;color:#166534;font-size:13px;">
          <li>Use <strong>Forgot Password</strong> on the login page to reset your password and unlock.</li>
          <li>Change your password to something strong and unique.</li>
          <li>Enable Two-Factor Authentication for extra protection.</li>
        </ul>
      </div>
    """

    until_str = f' (auto-unlocks at {locked_until.strftime("%H:%M UTC")})' if locked_until else ''
    plain = f"""Account Locked – HDS

Dear {username},

Your account has been locked{until_str}.

Reason: {reason}

To unlock: use Forgot Password on the login page to reset your password.

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#dc2626', '&#128274; Account Locked', 'Your account access has been restricted', body)
    msg  = _base_msg('[HDS] Your account has been locked', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── Failed login notification ──────────────────────────────────────────────

def send_failed_login_email(
    recipient: str,
    username: str,
    ip: str,
    location: str,
    ua_info: dict,
    attempt_time: datetime,
) -> bool:
    """Notify user of a single failed login attempt (rate-limited by caller)."""
    detail_rows = [
        ('DATE & TIME',     attempt_time.strftime('%Y-%m-%d %H:%M:%S UTC')),
        ('IP ADDRESS',      ip),
        ('LOCATION',        location or 'Unknown'),
        ('DEVICE',          ua_info.get('device_type', 'Unknown')),
        ('BROWSER',         ua_info.get('browser',     'Unknown')),
        ('OPERATING SYSTEM', ua_info.get('os',         'Unknown')),
    ]

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">
        A failed login attempt was recorded on your account.
        If this was you entering the wrong password, no action is needed.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html(detail_rows)}
      </table>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:14px;">
        <p style="margin:0;color:#dc2626;font-size:13px;">
          If you did <strong>not</strong> attempt to log in, someone may be trying to
          access your account. Use <em>Forgot Password</em> to secure it immediately.
        </p>
      </div>
    """

    plain = f"""Failed Login Attempt – HDS

Dear {username},

A failed login attempt was recorded at {attempt_time.strftime('%Y-%m-%d %H:%M:%S UTC')}.

  IP Address: {ip}
  Location  : {location or 'Unknown'}
  Device    : {ua_info.get('device_type', 'Unknown')}
  Browser   : {ua_info.get('browser', 'Unknown')}
  OS        : {ua_info.get('os', 'Unknown')}

If this was NOT you, use Forgot Password on the login page immediately.

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#d97706', '&#9888; Failed Login Attempt', 'Someone tried to access your account', body)
    msg  = _base_msg('[HDS] Failed login attempt on your account', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── 2FA recovery email ─────────────────────────────────────────────────────

def send_2fa_recovery_email(
    recipient: str,
    username: str,
    ip: str,
    location: str,
    recovered_at: datetime,
) -> bool:
    """Sent when a password reset is completed and 2FA is still active on the account."""
    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">Dear <strong>{username}</strong>,</p>
      <p style="color:#475569;margin:0 0 20px;">
        Your account password was reset via the <em>Forgot Password</em> flow.
        Your Two-Factor Authentication (2FA) is still active.
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html([
            ('DATE & TIME', recovered_at.strftime('%Y-%m-%d %H:%M:%S UTC')),
            ('IP ADDRESS',  ip),
            ('LOCATION',    location or 'Unknown'),
            ('2FA STATUS',  'Still ENABLED — required on next login'),
        ])}
      </table>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:14px;">
        <p style="margin:0;color:#dc2626;font-size:13px;">
          If you did <strong>not</strong> request a password reset, your account may be
          compromised. Log in immediately and review your security settings.
        </p>
      </div>
    """

    plain = f"""2FA Recovery Notice – HDS

Dear {username},

Your password was reset at {recovered_at.strftime('%Y-%m-%d %H:%M:%S UTC')}
from IP {ip} ({location or 'Unknown'}).

Your 2FA is still active — your next login will require an email verification code.

If you did NOT request this reset, log in and review your security settings immediately.

-- Hacking Detection System (automated message)
"""

    html = _wrap_html('#7c3aed', '&#128275; 2FA Recovery Notice', 'Account recovered — 2FA still active', body)
    msg  = _base_msg('[HDS] Password reset completed — 2FA still active', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send(msg)


# ── SOC admin alert ────────────────────────────────────────────────────────

def send_soc_admin_email(
    admin_emails: list[str],
    incident_ref: str,
    incident_type: str,
    severity: str,
    details: str,
    source_ip: str,
    username: str,
    risk_score: int,
    occurred_at: datetime,
) -> bool:
    """Fire a SOC-level alert to admin addresses for High/Critical incidents."""
    if not admin_emails:
        return False

    color = _SEVERITY_COLORS.get(severity, '#dc2626')

    body = f"""
      <p style="margin:0 0 16px;color:#1e293b;">
        <strong>SOC Alert — Action may be required.</strong>
      </p>
      <table width="100%" cellpadding="0" cellspacing="0"
             style="border-collapse:collapse;margin-bottom:20px;">
        {_detail_rows_html([
            ('INCIDENT REF',  incident_ref),
            ('TYPE',          incident_type.replace('_', ' ').title()),
            ('SEVERITY',      severity.upper()),
            ('RISK SCORE',    f'{risk_score}/100'),
            ('AFFECTED USER', username),
            ('SOURCE IP',     source_ip),
            ('DATE & TIME',   occurred_at.strftime('%Y-%m-%d %H:%M:%S UTC')),
            ('STATUS',        'OPEN — Awaiting review'),
        ])}
      </table>
      <div style="background:#fff5f5;border:1px solid #fecaca;
                  border-radius:6px;padding:16px;margin-bottom:16px;">
        <p style="margin:0 0 8px;color:#dc2626;font-weight:700;font-size:14px;">
          Incident Details:
        </p>
        <p style="margin:0;color:#7f1d1d;font-size:13px;">{details}</p>
      </div>
      <div style="background:#f0fdf4;border:1px solid #bbf7d0;
                  border-radius:6px;padding:14px;">
        <p style="margin:0 0 8px;color:#15803d;font-weight:700;font-size:14px;">
          Recommended Response:
        </p>
        <ul style="margin:0;padding-left:20px;color:#166534;font-size:13px;">
          <li>Review the affected user's login history and active sessions.</li>
          <li>Verify whether the account is currently locked.</li>
          <li>Escalate to Critical if further suspicious activity is detected.</li>
          <li>Update incident status once investigated.</li>
        </ul>
      </div>
    """

    plain = f"""[SOC ALERT] {severity.upper()} — {incident_type.replace('_', ' ').title()} – HDS

Incident Ref : {incident_ref}
Severity     : {severity.upper()}
Risk Score   : {risk_score}/100
Affected User: {username}
Source IP    : {source_ip}
Date/Time    : {occurred_at.strftime('%Y-%m-%d %H:%M:%S UTC')}

Details: {details}

Action: Review login history for {username} and verify account lockout status.

-- Hacking Detection System SOC (automated alert)
"""

    sent_any = False
    for admin in admin_emails:
        html = _wrap_html(color, f'&#128679; SOC Alert — {severity}', f'Incident {incident_ref}', body)
        msg  = _base_msg(f'[HDS-SOC] [{severity.upper()}] {incident_type.replace("_"," ").title()} — {incident_ref}', admin)
        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html,  'html'))
        if _smtp_send(msg):
            sent_any = True
    return sent_any


# ── Registration email verification ───────────────────────────────────────

def send_email_verification_code(recipient: str, username: str, code: str) -> bool:
    plain = f"""
HDS — Verify Your Email Address
================================

Hello {username},

Your email verification code is:

  {code}

Enter this 2-digit code on the verification page to complete your registration.
The code expires in 10 minutes.

If you did not register for HDS, ignore this email.

-- Hacking Detection System (automated message)
"""

    body = f"""
<p style="font-size:15px;color:#374151;">
  Hello <strong>{username}</strong>,
</p>
<p style="font-size:15px;color:#374151;">
  Enter the code below to verify your email address and complete registration.
</p>

<div style="text-align:center;margin:32px 0;">
  <div style="display:inline-block;background:#16a34a;color:#fff;
              border-radius:16px;padding:20px 48px;">
    <div style="font-size:13px;letter-spacing:2px;text-transform:uppercase;
                opacity:.8;margin-bottom:6px;">Verification Code</div>
    <div style="font-size:56px;font-weight:900;letter-spacing:12px;
                line-height:1;">{code}</div>
    <div style="font-size:12px;opacity:.7;margin-top:8px;">Expires in 10 minutes</div>
  </div>
</div>

<p style="font-size:13px;color:#6b7280;margin-top:24px;">
  If you did not create an account, you can safely ignore this email.
</p>
"""

    html = _wrap_html('#16a34a', '&#9989; Verify Your Email',
                      'Complete your HDS registration', body)
    msg  = _base_msg('[HDS] Email Verification Code', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send_blocking(msg)


# ── Login 2-digit verification ─────────────────────────────────────────────

def send_login_code_email(recipient: str, username: str, code: str, ip: str = '') -> bool:
    plain = f"""
HDS — Login Verification Code
==============================

Hello {username},

Your login verification code is:

  {code}

Enter this 2-digit code to complete your login.
The code expires in 5 minutes.

  IP Address : {ip or 'Unknown'}

If you did not attempt to log in, change your password immediately.

-- Hacking Detection System (automated message)
"""

    body = f"""
<p style="font-size:15px;color:#374151;">
  Hello <strong>{username}</strong>,
</p>
<p style="font-size:15px;color:#374151;">
  Enter the code below to complete your login.
</p>

<div style="text-align:center;margin:32px 0;">
  <div style="display:inline-block;background:#2563eb;color:#fff;
              border-radius:16px;padding:20px 48px;">
    <div style="font-size:13px;letter-spacing:2px;text-transform:uppercase;
                opacity:.8;margin-bottom:6px;">Login Code</div>
    <div style="font-size:56px;font-weight:900;letter-spacing:12px;
                line-height:1;">{code}</div>
    <div style="font-size:12px;opacity:.7;margin-top:8px;">Expires in 5 minutes</div>
  </div>
</div>

{_detail_rows_html([('IP Address', ip or 'Unknown')])}

<p style="font-size:13px;color:#6b7280;margin-top:24px;">
  If you did not attempt to log in,
  <a href="#" style="color:#dc2626;">change your password immediately</a>.
</p>
"""

    html = _wrap_html('#2563eb', '&#128272; Login Verification Code',
                      'Enter this code to complete your login', body)
    msg  = _base_msg('[HDS] Login Verification Code', recipient)
    msg.attach(MIMEText(plain, 'plain'))
    msg.attach(MIMEText(html,  'html'))
    return _smtp_send_blocking(msg)
