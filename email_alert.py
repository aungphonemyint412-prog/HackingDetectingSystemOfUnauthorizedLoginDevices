"""
Gmail SMTP alert system.
Sends HTML + plain-text emails when suspicious activity is detected.
"""
import smtplib
import os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime


def send_alert_email(
    recipient: str,
    username: str,
    ip_address: str,
    ua_info: dict,
    reasons: list[str],
    login_time: datetime,
) -> bool:
    """
    Send a suspicious-login alert to *recipient*.
    Returns True on success, False on failure.
    """
    sender  = os.environ.get('MAIL_USERNAME', '')
    app_pwd = os.environ.get('MAIL_PASSWORD', '')

    if not sender or not app_pwd:
        return False

    reasons_html  = ''.join(f'<li>{r}</li>' for r in reasons)
    reasons_plain = '\n'.join(f'  • {r}' for r in reasons)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f4f6fb;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 20px;">
        <table width="600" cellpadding="0" cellspacing="0"
               style="background:#fff;border-radius:8px;
                      box-shadow:0 2px 8px rgba(0,0,0,.12);overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="background:#dc3545;padding:28px 32px;text-align:center;">
              <h1 style="margin:0;color:#fff;font-size:22px;">
                &#9888;&#65039; Security Alert
              </h1>
              <p style="margin:6px 0 0;color:#ffcdd2;font-size:14px;">
                Suspicious Login Detected
              </p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:32px;">
              <p style="margin:0 0 16px;color:#1e293b;">
                Dear <strong>{username}</strong>,
              </p>
              <p style="color:#475569;margin:0 0 24px;">
                We detected unusual login activity on your account.
                Please review the details below.
              </p>

              <!-- Login Details -->
              <table width="100%" cellpadding="10" cellspacing="0"
                     style="border-collapse:collapse;margin-bottom:24px;">
                <tr style="background:#f1f5f9;">
                  <td style="border:1px solid #e2e8f0;color:#64748b;width:40%;font-size:13px;font-weight:600;">
                    DATE &amp; TIME
                  </td>
                  <td style="border:1px solid #e2e8f0;color:#1e293b;font-size:13px;">
                    {login_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
                  </td>
                </tr>
                <tr>
                  <td style="border:1px solid #e2e8f0;color:#64748b;font-size:13px;font-weight:600;">
                    IP ADDRESS
                  </td>
                  <td style="border:1px solid #e2e8f0;color:#1e293b;font-size:13px;">
                    {ip_address}
                  </td>
                </tr>
                <tr style="background:#f1f5f9;">
                  <td style="border:1px solid #e2e8f0;color:#64748b;font-size:13px;font-weight:600;">
                    DEVICE
                  </td>
                  <td style="border:1px solid #e2e8f0;color:#1e293b;font-size:13px;">
                    {ua_info.get('device_type','Unknown')}
                  </td>
                </tr>
                <tr>
                  <td style="border:1px solid #e2e8f0;color:#64748b;font-size:13px;font-weight:600;">
                    BROWSER
                  </td>
                  <td style="border:1px solid #e2e8f0;color:#1e293b;font-size:13px;">
                    {ua_info.get('browser','Unknown')}
                  </td>
                </tr>
                <tr style="background:#f1f5f9;">
                  <td style="border:1px solid #e2e8f0;color:#64748b;font-size:13px;font-weight:600;">
                    OPERATING SYSTEM
                  </td>
                  <td style="border:1px solid #e2e8f0;color:#1e293b;font-size:13px;">
                    {ua_info.get('os','Unknown')}
                  </td>
                </tr>
              </table>

              <!-- Reasons -->
              <div style="background:#fff5f5;border:1px solid #fecaca;
                          border-radius:6px;padding:16px;margin-bottom:24px;">
                <p style="margin:0 0 10px;color:#dc2626;font-weight:700;font-size:14px;">
                  Suspicious Activity Detected:
                </p>
                <ul style="margin:0;padding-left:20px;color:#7f1d1d;font-size:13px;">
                  {reasons_html}
                </ul>
              </div>

              <!-- Action -->
              <div style="background:#f0fdf4;border:1px solid #bbf7d0;
                          border-radius:6px;padding:16px;">
                <p style="margin:0 0 8px;color:#15803d;font-weight:700;font-size:14px;">
                  Recommended Action:
                </p>
                <ul style="margin:0;padding-left:20px;color:#166534;font-size:13px;">
                  <li>If this was <strong>you</strong>, no action is needed.</li>
                  <li>If this was <strong>NOT you</strong>, change your password immediately.</li>
                  <li>Review your full login history in the security dashboard.</li>
                </ul>
              </div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;border-top:1px solid #e2e8f0;
                       padding:16px 32px;text-align:center;">
              <p style="margin:0;color:#94a3b8;font-size:12px;">
                This is an automated message from the
                <strong>Hacking Detection System (HDS)</strong>.<br>
                Do not reply to this email.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    plain = f"""Security Alert – Suspicious Login Detected

Dear {username},

A suspicious login was detected on your account:

  Date/Time : {login_time.strftime('%Y-%m-%d %H:%M:%S UTC')}
  IP Address: {ip_address}
  Device    : {ua_info.get('device_type', 'Unknown')}
  Browser   : {ua_info.get('browser', 'Unknown')}
  OS        : {ua_info.get('os', 'Unknown')}

Suspicious Reasons:
{reasons_plain}

If this was NOT you, please change your password immediately and
review your login history in the security dashboard.

-- Hacking Detection System (automated alert)
"""

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '⚠️ Security Alert: Suspicious Login Detected'
        msg['From']    = f'HDS Security <{sender}>'
        msg['To']      = recipient

        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html,  'html'))

        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(sender, app_pwd)
            srv.sendmail(sender, recipient, msg.as_string())

        return True

    except Exception as exc:
        print(f'[email_alert] Failed to send: {exc}')
        return False


def send_otp_email(recipient: str, username: str, otp_code: str,
                   expires_minutes: int = 5,
                   ip_address: str = '',
                   location: str = '',
                   ua_info=None,
                   purpose: str = 'login') -> bool:
    """Send a 6-digit OTP code (login 2FA or password reset) via Gmail.

    Pass ip_address + location + ua_info to include a login-details table
    in the email body (shown for 2FA logins so the user can verify the location).
    purpose='reset' switches the subject, header, and warning text for password resets.
    """
    sender  = os.environ.get('MAIL_USERNAME', '')
    app_pwd = os.environ.get('MAIL_PASSWORD', '')

    if not sender or not app_pwd:
        return False

    is_reset     = purpose == 'reset'
    header_title = 'Password Reset Code'       if is_reset else 'Login Verification'
    header_sub   = 'Reset your HDS password'   if is_reset else 'Two-Factor Authentication Code'
    subject_line = f'[HDS] Your password reset code: {otp_code}' if is_reset \
                   else f'[HDS] Your login verification code: {otp_code}'
    action_label = 'password reset'            if is_reset else 'login'

    # ── Optional location/device details table ─────────────────────────────
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

        rows_html = ''
        for i, (label, value) in enumerate(rows):
            bg = 'background:#f1f5f9;' if i % 2 == 0 else ''
            rows_html += (
                f'<tr style="{bg}">'
                f'<td style="border:1px solid #e2e8f0;color:#64748b;width:40%;'
                f'font-size:13px;font-weight:600;padding:10px;">{label}</td>'
                f'<td style="border:1px solid #e2e8f0;color:#1e293b;'
                f'font-size:13px;padding:10px;">{value}</td>'
                f'</tr>'
            )

        location_section_html = (
            '<p style="margin:0 0 8px;color:#475569;font-size:13px;font-weight:600;">'
            'Login attempt details:</p>'
            '<table width="100%" cellpadding="0" cellspacing="0"'
            ' style="border-collapse:collapse;margin-bottom:24px;">'
            f'{rows_html}</table>'
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

    # ── Warning text ───────────────────────────────────────────────────────
    if is_reset:
        warning_html  = ('<strong>&#9888; Never share this code.</strong> '
                         'If you did not request a password reset, ignore this email '
                         'and your password will remain unchanged.')
        warning_plain = 'If you did not request a password reset, ignore this email.'
    else:
        warning_html  = ('<strong>&#9888; Never share this code.</strong> '
                         'HDS will never ask for this code via phone or email. '
                         'If you did not attempt to log in, change your password immediately.')
        warning_plain = 'If you did not attempt to log in, change your password immediately.'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:Arial,sans-serif;background:#f4f6fb;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:40px 20px;">
        <table width="520" cellpadding="0" cellspacing="0"
               style="background:#fff;border-radius:8px;
                      box-shadow:0 2px 8px rgba(0,0,0,.12);overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="background:#2563eb;padding:28px 32px;text-align:center;">
              <h1 style="margin:0;color:#fff;font-size:22px;">
                &#128274; {header_title}
              </h1>
              <p style="margin:6px 0 0;color:#bfdbfe;font-size:14px;">
                {header_sub}
              </p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:32px;">
              <p style="margin:0 0 16px;color:#1e293b;">
                Dear <strong>{username}</strong>,
              </p>
              <p style="color:#475569;margin:0 0 28px;">
                Use the verification code below to complete your {action_label}.
                This code expires in <strong>{expires_minutes} minutes</strong>.
              </p>

              <!-- OTP box -->
              <div style="text-align:center;margin:0 0 28px;">
                <div style="display:inline-block;background:#f1f5f9;
                            border:2px dashed #2563eb;border-radius:12px;
                            padding:20px 40px;">
                  <span style="font-size:2.4rem;font-weight:900;
                               letter-spacing:12px;color:#1e293b;
                               font-family:'Courier New',monospace;">
                    {otp_code}
                  </span>
                </div>
              </div>

              {location_section_html}

              <div style="background:#fff5f5;border:1px solid #fecaca;
                          border-radius:6px;padding:14px;margin-bottom:20px;">
                <p style="margin:0;color:#dc2626;font-size:13px;">
                  {warning_html}
                </p>
              </div>

              <div style="background:#f0fdf4;border:1px solid #bbf7d0;
                          border-radius:6px;padding:14px;">
                <p style="margin:0;color:#15803d;font-size:13px;">
                  This code is valid for <strong>{expires_minutes} minutes</strong>
                  and can only be used once.
                </p>
              </div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:#f8fafc;border-top:1px solid #e2e8f0;
                       padding:14px 32px;text-align:center;">
              <p style="margin:0;color:#94a3b8;font-size:12px;">
                Automated message from
                <strong>Hacking Detection System (HDS)</strong>.
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

    plain = f"""{'Password Reset Code' if is_reset else 'Login Verification Code'} – HDS

Dear {username},

Your one-time {action_label} code is:

    {otp_code}
{location_block_plain}
This code expires in {expires_minutes} minutes and can only be used once.

{warning_plain}

-- Hacking Detection System (automated message)
"""

    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject_line
        msg['From']    = f'HDS Security <{sender}>'
        msg['To']      = recipient

        msg.attach(MIMEText(plain, 'plain'))
        msg.attach(MIMEText(html,  'html'))

        with smtplib.SMTP('smtp.gmail.com', 587, timeout=10) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(sender, app_pwd)
            srv.sendmail(sender, recipient, msg.as_string())

        return True

    except Exception as exc:
        print(f'[email_alert] OTP send failed: {exc}')
        return False
