"""
Hacking Detection System of Unauthorized Login to the Device
Flask Application – Main entry point
"""
import os
import re
import secrets
import threading
from datetime import datetime, timedelta

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, session as flask_session,
)
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user,
)
from sqlalchemy import func

import requests as http_requests
import user_agents as ua_lib

from config import Config
from models import (
    db, User, LoginHistory, Alert, OTPCode,
    KnownIP, KnownDevice, FailedAttempt, SecurityToken,
    EmailQueue, SecurityIncident, device_fingerprint,
)
from detection import SuspiciousLoginDetector
from email_alert import (
    get_severity,
    send_alert_email, send_otp_email,
    send_login_notification_email,
    send_failed_login_email,
    send_password_changed_email,
    send_email_changed_email,
    send_2fa_changed_email,
    send_2fa_recovery_email,
    send_account_locked_email,
    send_soc_admin_email,
    send_email_verification_code,
    send_login_code_email,
)

# ── Allow HTTP for OAuth in dev (remove in production) ─────────────────────
os.environ.setdefault('OAUTHLIB_INSECURE_TRANSPORT', '1')

# ── App factory ────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'

# ── Google OAuth (Flask-Dance) ─────────────────────────────────────────────
_google_client_id     = app.config.get('GOOGLE_OAUTH_CLIENT_ID', '')
_google_client_secret = app.config.get('GOOGLE_OAUTH_CLIENT_SECRET', '')

_google_enabled = bool(_google_client_id and _google_client_secret
                       and _google_client_id != 'your_google_client_id_here')

if _google_enabled:
    from flask_dance.contrib.google import make_google_blueprint
    from flask_dance.consumer import oauth_authorized
    google_bp = make_google_blueprint(
        client_id=_google_client_id,
        client_secret=_google_client_secret,
        scope=[
            'openid',
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/userinfo.profile',
        ],
        redirect_url='/dashboard',
    )
    google_bp.authorization_url_params = {"prompt": "select_account"}

    @google_bp.before_request
    def _apply_login_hint():
        hint = flask_session.pop('google_login_hint', None)
        if hint:
            google_bp.authorization_url_params['login_hint'] = hint
        else:
            google_bp.authorization_url_params.pop('login_hint', None)

    app.register_blueprint(google_bp, url_prefix='/login')

    @oauth_authorized.connect_via(google_bp)
    def google_logged_in(blueprint, token):
        if not token:
            flash('Google login failed — no token received.', 'danger')
            return False

        resp = blueprint.session.get('/oauth2/v2/userinfo')
        if not resp.ok:
            flash('Failed to fetch Google account info.', 'danger')
            return False

        info = resp.json()

        # ── Gmail link flow (called right after new registration) ──────────
        link_user_id = flask_session.pop('pending_gmail_link_user_id', None)
        if link_user_id:
            link_user = User.query.get(link_user_id)
            if not link_user:
                flash('Account not found. Please register again.', 'danger')
                return False
            google_id = info.get('id', '')
            clash = User.query.filter_by(google_id=google_id).first()
            if clash and clash.id != link_user.id:
                flash('This Google account is already linked to another HDS account.', 'danger')
                return False
            link_user.google_id   = google_id
            link_user.profile_pic = info.get('picture', '')
            db.session.commit()

            ip     = get_client_ip()
            ua_raw = request.headers.get('User-Agent', '')
            ua     = parse_user_agent(ua_raw)
            record = _record_login(link_user, 'success', ua, ip, ua_raw)
            db.session.flush()
            _run_detection_and_commit(link_user, record, ip, ua)
            update_known_ip(link_user.id, ip)
            update_known_device(link_user.id, ua_raw, ua)
            link_user.last_login = datetime.utcnow()
            db.session.commit()

            login_user(link_user, remember=False)
            flash(f'Gmail linked! Welcome to HDS, {link_user.username}!', 'success')
            link_geo = get_geo_data(ip)
            threading.Thread(
                target=send_login_notification_email,
                args=(link_user.email, link_user.username, ip,
                      link_geo.get('location', ''), ua, datetime.utcnow()),
                daemon=False,
            ).start()
            return False

        # ── Normal Google sign-in flow ──────────────────────────────────────
        expected_email = flask_session.pop('google_expected_email', None)
        if expected_email and info.get('email', '').lower() != expected_email.lower():
            flash(
                f'Account mismatch. You selected {expected_email} but authenticated '
                f'as {info.get("email")}. Please try again.',
                'danger',
            )
            return False

        user = get_or_create_google_user(info)
        if not user:
            flash('Google login failed — could not retrieve email from Google.', 'danger')
            return False

        ip     = get_client_ip()
        ua_raw = request.headers.get('User-Agent', '')

        # Every login must verify via Gmail code — same as password login
        code = str(secrets.randbelow(90) + 10)  # 10–99
        otp  = OTPCode(
            user_id    = user.id,
            code       = code,
            expires_at = datetime.utcnow() + timedelta(minutes=5),
            ip_address = ip,
        )
        db.session.add(otp)
        db.session.commit()
        flask_session['pending_login_code_user_id'] = user.id
        flask_session['pending_login_code_otp_id']  = otp.id
        threading.Thread(
            target=send_login_code_email,
            args=(user.email, user.username, code, ip),
            daemon=False,
        ).start()
        flash(
            f'A 2-digit login code has been sent to {mask_email(user.email)}. '
            'Enter it to complete your login.',
            'info',
        )
        return False  # don't store the OAuth token in the session
else:
    pass


@login_manager.user_loader
def load_user(user_id: str):
    user = User.query.get(int(user_id))
    if user and user.is_locked:
        return None  # Instantly kills any active session for locked accounts
    return user


@app.before_request
def make_session_permanent():
    flask_session.permanent = True


# ── Context processor ─────────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    count = 0
    try:
        if current_user.is_authenticated:
            count = Alert.query.filter_by(
                user_id=current_user.id, is_read=False
            ).count()
    except Exception:
        pass
    return {'unread_alert_count': count, 'google_enabled': _google_enabled}


# ══════════════════════════════════════════════════════════════════════════
# UTILITY HELPERS
# ══════════════════════════════════════════════════════════════════════════

def get_client_ip() -> str:
    xff = request.headers.get('X-Forwarded-For')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def parse_user_agent(ua_string: str) -> dict:
    parsed = ua_lib.parse(ua_string)
    device = 'Mobile' if parsed.is_mobile else 'Tablet' if parsed.is_tablet else 'PC'
    return {
        'browser':     f'{parsed.browser.family} {parsed.browser.version_string}'.strip(),
        'os':          f'{parsed.os.family} {parsed.os.version_string}'.strip(),
        'device_type': device,
        'is_bot':      parsed.is_bot,
    }


def mask_email(email: str) -> str:
    try:
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked = local[0] + '*'
        else:
            masked = local[0] + '*' * (len(local) - 2) + local[-1]
        return f'{masked}@{domain}'
    except Exception:
        return email


def get_geo_data(ip: str) -> dict:
    """Return dict with location, lat, lon, is_vpn from ip-api.com (free, no key)."""
    blank = {'location': 'Unknown', 'lat': None, 'lon': None, 'is_vpn': False}
    if ip in ('127.0.0.1', '::1', 'localhost', '0.0.0.0'):
        return {**blank, 'location': 'Local (localhost)'}
    try:
        resp = http_requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,city,regionName,country,lat,lon,proxy',
            timeout=3,
        )
        data = resp.json()
        if data.get('status') == 'success':
            parts    = [data.get('city', ''), data.get('regionName', ''), data.get('country', '')]
            location = ', '.join(p for p in parts if p) or 'Unknown'
            return {
                'location': location,
                'lat':      data.get('lat'),
                'lon':      data.get('lon'),
                'is_vpn':   bool(data.get('proxy', False)),
            }
    except Exception:
        pass
    return blank


def get_location(ip: str) -> str:
    return get_geo_data(ip)['location']


def generate_otp() -> str:
    return f'{secrets.randbelow(1000000):06d}'


def update_known_ip(user_id: int, ip_address: str) -> None:
    known = KnownIP.query.filter_by(user_id=user_id, ip_address=ip_address).first()
    if known:
        known.last_seen   = datetime.utcnow()
        known.login_count += 1
    else:
        db.session.add(KnownIP(user_id=user_id, ip_address=ip_address))
    db.session.commit()


def update_known_device(user_id: int, ua_raw: str, ua_info: dict) -> None:
    fp = device_fingerprint(ua_raw)
    known = KnownDevice.query.filter_by(user_id=user_id, device_fingerprint=fp).first()
    if known:
        known.last_seen   = datetime.utcnow()
        known.device_type = ua_info['device_type']
        known.browser     = ua_info['browser']
        known.os          = ua_info['os']
    else:
        db.session.add(KnownDevice(
            user_id=user_id, device_fingerprint=fp,
            device_type=ua_info['device_type'],
            browser=ua_info['browser'], os=ua_info['os'],
        ))
    db.session.commit()


def _record_login(user: User, status: str, ua_info: dict, ip: str,
                  ua_raw: str, two_fa_required: bool = False,
                  geo: dict | None = None) -> LoginHistory:
    if geo is None:
        geo = get_geo_data(ip)
    record = LoginHistory(
        user_id         = user.id,
        ip_address      = ip,
        device_type     = ua_info['device_type'],
        browser         = ua_info['browser'],
        os              = ua_info['os'],
        user_agent      = ua_raw,
        location        = geo['location'],
        lat             = geo.get('lat'),
        lon             = geo.get('lon'),
        is_vpn          = geo.get('is_vpn', False),
        login_time      = datetime.utcnow(),
        login_status    = status,
        two_fa_required = two_fa_required,
    )
    db.session.add(record)
    return record


def _can_send_email(user_id: int, email_type: str) -> bool:
    """Return True if this email type hasn't hit its rate limit for this user."""
    limits = app.config.get('EMAIL_RATE_LIMITS', {})
    if email_type not in limits:
        return True  # no rate limit defined — always allow
    max_count, window_min = limits[email_type]
    since = datetime.utcnow() - timedelta(minutes=window_min)
    count = EmailQueue.query.filter(
        EmailQueue.user_id    == user_id,
        EmailQueue.email_type == email_type,
        EmailQueue.created_at >= since,
        EmailQueue.status     != 'skipped',
    ).count()
    return count < max_count


def _log_email(user_id, recipient: str, email_type: str,
               subject: str, sent: bool, error: str = '') -> None:
    """Record every email attempt in EmailQueue for audit + rate limiting."""
    entry = EmailQueue(
        user_id    = user_id,
        recipient  = recipient,
        email_type = email_type,
        subject    = subject,
        status     = 'sent' if sent else 'failed',
        sent_at    = datetime.utcnow() if sent else None,
        error_msg  = error or None,
    )
    db.session.add(entry)


def _log_skipped_email(user_id, recipient: str, email_type: str, subject: str) -> None:
    db.session.add(EmailQueue(
        user_id=user_id, recipient=recipient, email_type=email_type,
        subject=subject, status='skipped',
    ))


def _create_incident(user_id, incident_type: str, severity: str,
                     details: str, source_ip: str, risk_score: int = 0):
    """Create a SecurityIncident record and return it."""
    today = datetime.utcnow().strftime('%Y%m%d')
    count = SecurityIncident.query.filter(
        SecurityIncident.incident_ref.like(f'INC-{today}-%')
    ).count()
    ref = f'INC-{today}-{count + 1:04d}'
    inc = SecurityIncident(
        incident_ref  = ref,
        user_id       = user_id,
        incident_type = incident_type,
        severity      = severity,
        details       = details,
        source_ip     = source_ip,
        risk_score    = risk_score,
    )
    db.session.add(inc)
    db.session.flush()
    return inc


def _detect_credential_stuffing(ip: str, window_min: int = 10, min_accounts: int = 3) -> bool:
    """Return True if the same IP failed logins against multiple distinct accounts recently."""
    since = datetime.utcnow() - timedelta(minutes=window_min)
    distinct = (
        db.session.query(func.count(func.distinct(FailedAttempt.user_id)))
        .filter(FailedAttempt.ip_address == ip)
        .filter(FailedAttempt.attempt_time >= since)
        .scalar() or 0
    )
    return distinct >= min_accounts


def calculate_risk_score(reasons: list[str]) -> int:
    score = 0
    for r in reasons:
        rl = r.lower()
        if 'vpn' in rl or 'proxy' in rl or 'tor' in rl:
            score += 25
        elif 'impossible travel' in rl:
            score += 30
        elif 'new ip' in rl:
            score += 15
        elif 'new device' in rl:
            score += 15
        elif 'new browser' in rl:
            score += 10
        elif 'new operating system' in rl:
            score += 10
        elif 'unusual hour' in rl:
            score += 10
        elif 'multiple logins' in rl or 'rapid' in rl:
            score += 15
    return min(score, 100)


def get_security_recommendations(reasons: list[str], has_2fa: bool) -> list[str]:
    rl   = ' '.join(r.lower() for r in reasons)
    recs = []
    if not has_2fa:
        recs.append('Enable Two-Factor Authentication for extra account protection.')
    if 'new ip' in rl or 'new device' in rl:
        recs.append('Unrecognised device or location — change your password if this was not you.')
    if 'vpn' in rl or 'proxy' in rl:
        recs.append('Login came from a VPN or proxy — verify this was you.')
    if 'impossible travel' in rl:
        recs.append('Impossible travel detected — your credentials may have been stolen.')
    if 'unusual hour' in rl:
        recs.append('Login at an unusual hour — be extra vigilant.')
    if 'multiple logins' in rl or 'rapid' in rl:
        recs.append('Multiple logins in a short period — verify your account is secure.')
    if not recs:
        recs.append('Review your login history for any unrecognised activity.')
    return recs


def _lock_account(user: User, reason: str, duration_minutes: int = 0) -> None:
    """Lock account. duration_minutes=0 = indefinite (requires password reset to unlock)."""
    user.is_locked   = True
    user.lock_reason = reason
    user.locked_until = (
        datetime.utcnow() + timedelta(minutes=duration_minutes)
        if duration_minutes else None
    )
    db.session.flush()


def _fire_alert(user: User, record: LoginHistory, reasons: list,
                ip: str, ua_info: dict, alert_type: str = 'suspicious_login'):
    risk_score = calculate_risk_score(reasons)
    severity   = get_severity(risk_score)
    recs       = get_security_recommendations(reasons, user.two_fa_enabled)

    if record:
        record.risk_score = risk_score

    alert = Alert(
        user_id          = user.id,
        login_history_id = record.id if record else None,
        alert_type       = alert_type,
        message          = '; '.join(reasons),
        created_at       = datetime.utcnow(),
    )
    db.session.add(alert)

    # ── Create security incident ───────────────────────────────────────────
    inc = _create_incident(
        user_id       = user.id,
        incident_type = alert_type,
        severity      = severity.lower(),
        details       = '; '.join(reasons),
        source_ip     = ip,
        risk_score    = risk_score,
    )

    db.session.flush()

    confirm_url = deny_url = ''
    if record and record.id:
        confirm_tok = SecurityToken(
            user_id          = user.id,
            token            = secrets.token_urlsafe(32),
            token_type       = 'confirm_login',
            login_history_id = record.id,
            expires_at       = datetime.utcnow() + timedelta(hours=48),
        )
        deny_tok = SecurityToken(
            user_id          = user.id,
            token            = secrets.token_urlsafe(32),
            token_type       = 'deny_login',
            login_history_id = record.id,
            expires_at       = datetime.utcnow() + timedelta(hours=48),
        )
        db.session.add(confirm_tok)
        db.session.add(deny_tok)
        db.session.flush()
        try:
            confirm_url = url_for('security_confirm', token=confirm_tok.token, _external=True)
            deny_url    = url_for('security_deny',    token=deny_tok.token,    _external=True)
        except Exception:
            pass

    if not app.config.get('TESTING', False):
        try:
            location = (record.location or '') if record else ''
            sent = send_alert_email(
                user.email, user.username, ip, ua_info, reasons, datetime.utcnow(),
                location=location, risk_score=risk_score, recommendations=recs,
                confirm_url=confirm_url, deny_url=deny_url,
            )
            alert.email_sent = sent
            _log_email(user.id, user.email, 'alert',
                       f'[{severity}] Security Alert', sent)
        except Exception:
            pass

        # ── SOC admin notification for High / Critical ─────────────────────
        if severity in ('High', 'Critical'):
            admin_emails = app.config.get('ADMIN_EMAILS', [])
            if admin_emails:
                try:
                    send_soc_admin_email(
                        admin_emails, inc.incident_ref, alert_type,
                        severity, '; '.join(reasons), ip, user.username,
                        risk_score, datetime.utcnow(),
                    )
                except Exception:
                    pass


def _run_detection_and_commit(user: User, record: LoginHistory,
                               ip: str, ua_info: dict) -> bool:
    detector = SuspiciousLoginDetector(user, record, db.session)
    is_suspicious, reasons = detector.analyze()
    if is_suspicious:
        record.is_suspicious      = True
        record.suspicious_reasons = '; '.join(reasons)
        _fire_alert(user, record, reasons, ip, ua_info)
    db.session.commit()
    return is_suspicious


def get_or_create_google_user(info: dict) -> 'User | None':
    """Find or create an HDS account for this Google identity."""
    email     = info.get('email', '')
    google_id = info.get('id', '')
    pic       = info.get('picture', '')

    if not email:
        return None

    # Match by google_id first, then fall back to email
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User.query.filter_by(email=email).first()

    if not user:
        # Auto-register: derive a unique username from the email prefix
        base = re.sub(r'[^a-z0-9_]', '', email.split('@')[0].lower()) or 'user'
        username = base
        suffix = 1
        while User.query.filter_by(username=username).first():
            username = f'{base}{suffix}'
            suffix  += 1

        user = User(
            username       = username,
            email          = email,
            google_id      = google_id,
            profile_pic    = pic,
            email_verified = True,
        )
        user.set_password(secrets.token_hex(32))
        db.session.add(user)
        db.session.commit()
        return user

    # Keep google_id and profile_pic in sync
    if not user.google_id or user.profile_pic != pic:
        user.google_id   = google_id
        user.profile_pic = pic
        db.session.commit()

    return user


# ══════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


# ── Google account picker ─────────────────────────────────────────────────
@app.route('/google-select')
def google_select():
    if not _google_enabled:
        return redirect(url_for('login'))
    google_users = User.query.filter(User.google_id.isnot(None)).order_by(User.username).all()
    return render_template('google_select.html', google_users=google_users)


@app.route('/google-login-as', methods=['POST'])
def google_login_as():
    hint = request.form.get('email', '').strip()
    if hint:
        flask_session['google_login_hint']     = hint
        flask_session['google_expected_email'] = hint
    return redirect(url_for('google.login'))


# ── Gmail link (post-registration choice) ─────────────────────────────────
@app.route('/link-gmail')
def link_gmail():
    user_id = flask_session.get('pending_gmail_link_user_id')
    if not user_id:
        return redirect(url_for('login'))
    user = User.query.get(user_id)
    if not user:
        flask_session.pop('pending_gmail_link_user_id', None)
        return redirect(url_for('login'))
    return render_template('link_gmail.html', username=user.username, email=user.email)


@app.route('/start-gmail-link', methods=['POST'])
def start_gmail_link():
    if not _google_enabled:
        flask_session.pop('pending_gmail_link_user_id', None)
        flash('Google OAuth is not configured on this server.', 'warning')
        return redirect(url_for('login'))
    return redirect(url_for('google.login'))


@app.route('/skip-gmail-link', methods=['POST'])
def skip_gmail_link():
    flask_session.pop('pending_gmail_link_user_id', None)
    flash('Account created successfully! You can now log in.', 'success')
    return redirect(url_for('login'))


# ── Register ──────────────────────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if '@' not in email:
            errors.append('A valid email address is required.')
        if len(password) < 8:
            errors.append('Password must be at least 8 characters.')
        if password != confirm:
            errors.append('Passwords do not match.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email address already registered.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html', username=username, email=email)

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        # Send 2-digit email verification code (skip in test mode)
        if not app.config.get('TESTING', False):
            code = str(secrets.randbelow(90) + 10)  # 10–99
            otp  = OTPCode(
                user_id    = user.id,
                code       = code,
                expires_at = datetime.utcnow() + timedelta(minutes=10),
            )
            db.session.add(otp)
            db.session.commit()
            flask_session['pending_email_verify_user_id'] = user.id
            flask_session['pending_email_verify_otp_id']  = otp.id
            threading.Thread(
                target=send_email_verification_code,
                args=(user.email, user.username, code),
                daemon=False,
            ).start()
            flash(
                f'A 2-digit verification code has been sent to {user.email}. '
                'Enter it to complete your registration.',
                'info',
            )
            return redirect(url_for('verify_email'))

        flash('Account created! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ── Login ─────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    # Google OAuth sets pending_login_code session; forward user to verify step
    if request.method == 'GET' and flask_session.get('pending_login_code_user_id'):
        return redirect(url_for('verify_login_code'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        ip     = get_client_ip()
        ua_raw = request.headers.get('User-Agent', '')
        ua     = parse_user_agent(ua_raw)

        user = User.query.filter_by(username=username).first()

        # ── Account lockout check ──────────────────────────────────────────
        if user and user.is_locked:
            if user.locked_until and datetime.utcnow() >= user.locked_until:
                user.is_locked    = False
                user.locked_until = None
                user.lock_reason  = None
                db.session.commit()
            else:
                if user.locked_until:
                    flash(
                        f'Account locked until {user.locked_until.strftime("%H:%M UTC")}. '
                        'Use "Forgot password?" to unlock immediately.',
                        'danger',
                    )
                else:
                    flash(
                        'Account locked due to suspicious activity. '
                        'Use "Forgot password?" to unlock.',
                        'danger',
                    )
                return render_template('login.html', client_ip=get_client_ip())

        if user and user.check_password(password):
            # ── Mandatory 2-digit login code (always, unless in test mode) ─
            if not app.config.get('TESTING', False):
                code = str(secrets.randbelow(90) + 10)  # 10–99
                otp  = OTPCode(
                    user_id          = user.id,
                    code             = code,
                    expires_at       = datetime.utcnow() + timedelta(minutes=5),
                    ip_address       = ip,
                )
                db.session.add(otp)
                db.session.commit()
                flask_session['pending_login_code_user_id'] = user.id
                flask_session['pending_login_code_otp_id']  = otp.id
                threading.Thread(
                    target=send_login_code_email,
                    args=(user.email, user.username, code, ip),
                    daemon=False,
                ).start()
                flash(
                    f'A 2-digit login code has been sent to {mask_email(user.email)}. '
                    'Enter it to complete your login.',
                    'info',
                )
                return redirect(url_for('verify_login_code'))
            # ── TESTING mode only: skip email, log in directly ──────────────
            geo    = get_geo_data(ip)
            record = _record_login(user, 'success', ua, ip, ua_raw, geo=geo)
            db.session.flush()
            _run_detection_and_commit(user, record, ip, ua)
            update_known_ip(user.id, ip)
            update_known_device(user.id, ua_raw, ua)
            user.last_login = datetime.utcnow()
            db.session.commit()
            login_user(user, remember=False)
            return redirect(url_for('dashboard'))

        else:
            if user:
                # Record failed attempt
                db.session.add(FailedAttempt(user_id=user.id, ip_address=ip))
                record = _record_login(user, 'failed', ua, ip, ua_raw)
                db.session.flush()

                window     = app.config['FAILED_ATTEMPT_WINDOW']
                max_fail   = app.config['MAX_FAILED_ATTEMPTS']
                since      = datetime.utcnow() - timedelta(minutes=window)
                fail_count = (
                    LoginHistory.query
                    .filter_by(user_id=user.id, login_status='failed')
                    .filter(LoginHistory.login_time >= since)
                    .count()
                )
                if fail_count >= max_fail:
                    reason      = f'{fail_count} failed login attempts in the last {window} min from IP {ip}'
                    lockout_min = app.config.get('LOCKOUT_DURATION', 30)
                    _lock_account(user, reason, lockout_min)
                    _fire_alert(user, record, [reason], ip, ua, alert_type='brute_force')
                    if not app.config.get('TESTING', False):
                        locked_until = user.locked_until
                        threading.Thread(
                            target=send_account_locked_email,
                            args=(user.email, user.username, reason, locked_until),
                            daemon=False,
                        ).start()
                        _log_email(user.id, user.email, 'account_locked',
                                   '[HDS] Your account has been locked', True)
                else:
                    # Single failed login notification (rate-limited)
                    if not app.config.get('TESTING', False):
                        if _can_send_email(user.id, 'failed_login'):
                            loc = (record.location or get_location(ip))
                            _log_email(user.id, user.email, 'failed_login',
                                       '[HDS] Failed login attempt on your account', True)
                            threading.Thread(
                                target=send_failed_login_email,
                                args=(user.email, user.username, ip, loc, ua, datetime.utcnow()),
                                daemon=False,
                            ).start()
                        else:
                            _log_skipped_email(user.id, user.email, 'failed_login',
                                               '[HDS] Failed login attempt on your account')

                # Credential stuffing detection
                if _detect_credential_stuffing(ip):
                    cs_reason = (f'Credential stuffing detected: multiple accounts targeted '
                                 f'from IP {ip} in the last 10 minutes')
                    _create_incident(
                        user_id       = user.id,
                        incident_type = 'credential_stuffing',
                        severity      = 'high',
                        details       = cs_reason,
                        source_ip     = ip,
                        risk_score    = 75,
                    )
                    if not app.config.get('TESTING', False):
                        admin_emails = app.config.get('ADMIN_EMAILS', [])
                        if admin_emails:
                            try:
                                send_soc_admin_email(
                                    admin_emails,
                                    f'CS-{datetime.utcnow().strftime("%Y%m%d%H%M%S")}',
                                    'credential_stuffing', 'High',
                                    cs_reason, ip, user.username, 75, datetime.utcnow(),
                                )
                            except Exception:
                                pass

                db.session.commit()

            flash('Invalid username or password.', 'danger')

    return render_template('login.html', client_ip=get_client_ip())


# ── Verify 2FA ────────────────────────────────────────────────────────────
@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id = flask_session.get('pending_2fa_user_id')
    if not user_id:
        flash('No pending verification. Please log in.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        flask_session.pop('pending_2fa_user_id', None)
        return redirect(url_for('login'))

    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        entered = request.form.get('otp_code', '').strip().replace(' ', '')

        otp_id = flask_session.get('pending_2fa_otp_id')
        rec_id = flask_session.get('pending_2fa_login_rec_id')
        ip     = get_client_ip()
        ua_raw = request.headers.get('User-Agent', '')
        ua     = parse_user_agent(ua_raw)

        otp    = OTPCode.query.get(otp_id) if otp_id else None
        record = LoginHistory.query.get(rec_id) if rec_id else None

        if otp and not otp.is_used and not otp.is_expired and otp.code == entered:
            otp.is_used = True
            if record:
                record.login_status    = 'success'
                record.two_fa_verified = True

            db.session.flush()
            is_susp = _run_detection_and_commit(user, record, ip, ua) if record else False
            update_known_ip(user.id, ip)
            update_known_device(user.id, ua_raw, ua)
            user.last_login = datetime.utcnow()
            db.session.commit()

            for k in ('pending_2fa_user_id', 'pending_2fa_login_rec_id', 'pending_2fa_otp_id'):
                flask_session.pop(k, None)

            login_user(user, remember=False)
            if is_susp:
                flash(
                    'Verification successful — but suspicious activity was detected. '
                    f'An alert has been sent to {user.email}.',
                    'warning',
                )
            else:
                flash('Verification successful. Welcome back!', 'success')
                if record and not app.config.get('TESTING', False):
                    threading.Thread(
                        target=send_login_notification_email,
                        args=(user.email, user.username, ip,
                              record.location or '', ua, datetime.utcnow()),
                        daemon=False,
                    ).start()
            return redirect(url_for('dashboard'))

        else:
            if record:
                record.login_status    = 'failed_2fa'
                record.two_fa_verified = False
                db.session.commit()

            for k in ('pending_2fa_user_id', 'pending_2fa_login_rec_id', 'pending_2fa_otp_id'):
                flask_session.pop(k, None)

            if otp and otp.is_expired:
                flash('Verification code expired. Please log in again.', 'danger')
            else:
                flash('Invalid verification code. Please log in again.', 'danger')
            return redirect(url_for('login'))

    return render_template('verify_2fa.html',
                           masked_email=mask_email(user.email),
                           username=user.username)


# ── Email verification (registration) ─────────────────────────────────────
@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    user_id = flask_session.get('pending_email_verify_user_id')
    otp_id  = flask_session.get('pending_email_verify_otp_id')
    if not user_id or not otp_id:
        return redirect(url_for('register'))

    user = db.session.get(User, user_id)
    otp  = db.session.get(OTPCode, otp_id)
    if not user or not otp or otp.is_used or otp.is_expired:
        flask_session.pop('pending_email_verify_user_id', None)
        flask_session.pop('pending_email_verify_otp_id', None)
        flash('Verification code expired. Please register again.', 'danger')
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered = request.form.get('verify_code', '').strip()
        if entered == otp.code:
            otp.is_used             = True
            user.email_verified     = True
            db.session.commit()
            flask_session.pop('pending_email_verify_user_id', None)
            flask_session.pop('pending_email_verify_otp_id', None)
            flash('Email verified! Your account is ready. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect code. Please try again.', 'danger')

    return render_template('verify_email.html', masked_email=mask_email(user.email))


# ── Login 2-digit code verification ───────────────────────────────────────
@app.route('/verify-login-code', methods=['GET', 'POST'])
def verify_login_code():
    user_id = flask_session.get('pending_login_code_user_id')
    otp_id  = flask_session.get('pending_login_code_otp_id')
    if not user_id or not otp_id:
        return redirect(url_for('login'))

    user = db.session.get(User, user_id)
    otp  = db.session.get(OTPCode, otp_id)
    if not user or not otp or otp.is_used or otp.is_expired:
        flask_session.pop('pending_login_code_user_id', None)
        flask_session.pop('pending_login_code_otp_id', None)
        flash('Login code expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered = request.form.get('selected_code', '').strip().replace(' ', '')
        if entered == otp.code:
            otp.is_used = True
            ip     = get_client_ip()
            ua_raw = request.headers.get('User-Agent', '')
            ua     = parse_user_agent(ua_raw)
            geo    = get_geo_data(ip)
            record = _record_login(user, 'success', ua, ip, ua_raw, geo=geo)
            db.session.flush()
            is_susp = _run_detection_and_commit(user, record, ip, ua)
            update_known_ip(user.id, ip)
            update_known_device(user.id, ua_raw, ua)
            user.last_login = datetime.utcnow()
            db.session.commit()
            flask_session.pop('pending_login_code_user_id', None)
            flask_session.pop('pending_login_code_otp_id', None)
            login_user(user, remember=False)
            if is_susp:
                flash('Login successful — suspicious activity detected. '
                      f'A security alert has been sent to {user.email}.', 'warning')
            else:
                flash('Welcome back!', 'success')
                if not app.config.get('TESTING', False):
                    threading.Thread(
                        target=send_login_notification_email,
                        args=(user.email, user.username, ip,
                              geo.get('location', ''), ua, datetime.utcnow()),
                        daemon=False,
                    ).start()
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect code. Please check your email and try again.', 'danger')

    return render_template('verify_login_code.html',
                           masked_email=mask_email(user.email),
                           ip_address=get_client_ip())


# ── Resend OTP ────────────────────────────────────────────────────────────
@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    user_id = flask_session.get('pending_2fa_user_id')
    if not user_id:
        return redirect(url_for('login'))

    user = User.query.get(user_id)
    if not user:
        return redirect(url_for('login'))

    ip     = get_client_ip()
    ua_raw = request.headers.get('User-Agent', '')
    ua     = parse_user_agent(ua_raw)

    old_id = flask_session.get('pending_2fa_otp_id')
    if old_id:
        old = OTPCode.query.get(old_id)
        if old:
            old.is_used = True

    code = generate_otp()
    otp  = OTPCode(
        user_id          = user.id,
        code             = code,
        expires_at       = datetime.utcnow() + timedelta(minutes=5),
        ip_address       = ip,
        login_history_id = flask_session.get('pending_2fa_login_rec_id'),
    )
    db.session.add(otp)
    db.session.commit()
    flask_session['pending_2fa_otp_id'] = otp.id

    loc = get_location(ip)
    threading.Thread(
        target=send_otp_email,
        args=(user.email, user.username, code),
        kwargs={'ip_address': ip, 'location': loc, 'ua_info': ua},
        daemon=False,
    ).start()
    flash(f'A new code has been sent to {mask_email(user.email)}.', 'info')

    return redirect(url_for('verify_2fa'))


# ── Forgot Password ───────────────────────────────────────────────────────
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        user  = User.query.filter_by(email=email).first()

        if user:
            ip   = get_client_ip()
            code = generate_otp()
            otp  = OTPCode(
                user_id    = user.id,
                code       = code,
                expires_at = datetime.utcnow() + timedelta(minutes=10),
                ip_address = ip,
            )
            db.session.add(otp)
            db.session.commit()

            flask_session['pending_reset_user_id'] = user.id
            flask_session['pending_reset_otp_id']  = otp.id

            threading.Thread(
                target=send_otp_email,
                args=(user.email, user.username, code),
                kwargs={'expires_minutes': 10, 'purpose': 'reset'},
                daemon=False,
            ).start()

        # Always show the same message so we don't leak whether the email exists
        flash('If that email is registered, a reset code has been sent.', 'info')
        return redirect(url_for('verify_reset_otp'))

    return render_template('forgot_password.html')


@app.route('/verify-reset-otp', methods=['GET', 'POST'])
def verify_reset_otp():
    user_id = flask_session.get('pending_reset_user_id')
    if not user_id:
        return redirect(url_for('forgot_password'))

    user = User.query.get(user_id)
    if not user:
        flask_session.pop('pending_reset_user_id', None)
        flask_session.pop('pending_reset_otp_id', None)
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered = request.form.get('otp_code', '').strip().replace(' ', '')
        otp_id  = flask_session.get('pending_reset_otp_id')
        otp     = OTPCode.query.get(otp_id) if otp_id else None

        if otp and not otp.is_used and not otp.is_expired and otp.code == entered:
            otp.is_used = True
            db.session.commit()
            flask_session['reset_verified'] = True
            return redirect(url_for('reset_password'))

        if otp and otp.is_expired:
            for k in ('pending_reset_user_id', 'pending_reset_otp_id'):
                flask_session.pop(k, None)
            flash('Code expired. Please request a new one.', 'danger')
            return redirect(url_for('forgot_password'))

        flash('Invalid code. Please try again.', 'danger')

    return render_template('verify_reset_otp.html', masked_email=mask_email(user.email))


@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if not flask_session.get('reset_verified'):
        return redirect(url_for('forgot_password'))

    user_id = flask_session.get('pending_reset_user_id')
    user    = User.query.get(user_id) if user_id else None
    if not user:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        confirm      = request.form.get('confirm_password', '')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters.', 'danger')
        elif new_password != confirm:
            flash('Passwords do not match.', 'danger')
        else:
            user.set_password(new_password)
            user.is_locked    = False
            user.locked_until = None
            user.lock_reason  = None
            db.session.commit()
            for k in ('pending_reset_user_id', 'pending_reset_otp_id', 'reset_verified'):
                flask_session.pop(k, None)
            ip  = get_client_ip()
            loc = get_location(ip)
            now = datetime.utcnow()
            threading.Thread(
                target=send_password_changed_email,
                args=(user.email, user.username, ip, loc, now),
                daemon=False,
            ).start()
            if user.two_fa_enabled:
                threading.Thread(
                    target=send_2fa_recovery_email,
                    args=(user.email, user.username, ip, loc, now),
                    daemon=False,
                ).start()
            flash('Password reset successfully. Please log in with your new password.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html', username=user.username)


# ── Forgot Password JSON API (single-page login flow) ─────────────────────
@app.route('/api/send-reset-code', methods=['POST'])
def api_send_reset_code():
    data  = request.get_json(silent=True) or {}
    email = data.get('email', '').strip().lower()
    user  = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({'status': 'error', 'message': 'email_not_found'})

    ip   = get_client_ip()
    code = generate_otp()
    otp  = OTPCode(
        user_id    = user.id,
        code       = code,
        expires_at = datetime.utcnow() + timedelta(minutes=10),
        ip_address = ip,
    )
    db.session.add(otp)
    db.session.commit()

    flask_session['pending_reset_user_id'] = user.id
    flask_session['pending_reset_otp_id']  = otp.id

    # Send async (non-daemon thread) so AJAX returns immediately
    threading.Thread(
        target=send_otp_email,
        args=(user.email, user.username, code),
        kwargs={'expires_minutes': 10, 'purpose': 'reset'},
        daemon=False,
    ).start()

    return jsonify({'status': 'success'})


@app.route('/api/verify-reset-code', methods=['POST'])
def api_verify_reset_code():
    data    = request.get_json(silent=True) or {}
    entered = data.get('otp', '').strip().replace(' ', '')
    user_id = flask_session.get('pending_reset_user_id')
    otp_id  = flask_session.get('pending_reset_otp_id')

    if not user_id or not otp_id:
        return jsonify({'status': 'error', 'message': 'session_expired'})

    otp = OTPCode.query.get(otp_id)

    if otp and otp.is_expired:
        flask_session.pop('pending_reset_user_id', None)
        flask_session.pop('pending_reset_otp_id', None)
        return jsonify({'status': 'error', 'message': 'otp_expired'})

    if otp and not otp.is_used and not otp.is_expired and otp.code == entered:
        otp.is_used = True
        db.session.commit()
        flask_session['reset_verified'] = True
        return jsonify({'status': 'success'})

    return jsonify({'status': 'error', 'message': 'invalid_otp'})


@app.route('/api/reset-password', methods=['POST'])
def api_reset_password():
    if not flask_session.get('reset_verified'):
        return jsonify({'status': 'error', 'message': 'not_verified'})

    data         = request.get_json(silent=True) or {}
    new_password = data.get('new_password', '')
    user_id      = flask_session.get('pending_reset_user_id')
    user         = User.query.get(user_id) if user_id else None

    if not user:
        return jsonify({'status': 'error', 'message': 'session_expired'})
    if len(new_password) < 8:
        return jsonify({'status': 'error', 'message': 'too_short'})

    user.set_password(new_password)
    user.is_locked    = False
    user.locked_until = None
    user.lock_reason  = None
    db.session.commit()

    for k in ('pending_reset_user_id', 'pending_reset_otp_id', 'reset_verified'):
        flask_session.pop(k, None)

    ip  = get_client_ip()
    loc = get_location(ip)
    now = datetime.utcnow()
    threading.Thread(
        target=send_password_changed_email,
        args=(user.email, user.username, ip, loc, now),
        daemon=False,
    ).start()
    if user.two_fa_enabled:
        threading.Thread(
            target=send_2fa_recovery_email,
            args=(user.email, user.username, ip, loc, now),
            daemon=False,
        ).start()

    return jsonify({'status': 'success'})


# ── Security confirm/deny (Was this you?) ─────────────────────────────────
@app.route('/security/confirm/<token>')
def security_confirm(token: str):
    tok = SecurityToken.query.filter_by(token=token, token_type='confirm_login').first()
    if not tok or tok.is_used or tok.is_expired:
        flash('This confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    tok.is_used = True
    if tok.login_history_id:
        rec = LoginHistory.query.get(tok.login_history_id)
        if rec:
            rec.user_confirmed = True
    db.session.commit()
    flash('Login confirmed. Your account is safe and secure.', 'success')
    # If user is already logged in, go straight to dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/security/deny/<token>')
def security_deny(token: str):
    tok = SecurityToken.query.filter_by(token=token, token_type='deny_login').first()
    if not tok or tok.is_used or tok.is_expired:
        flash('This security link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    tok.is_used = True
    user = User.query.get(tok.user_id)
    if user:
        _lock_account(user, 'Account locked by user: suspicious login denied via email link')
        db.session.commit()
        if not app.config.get('TESTING', False):
            threading.Thread(
                target=send_account_locked_email,
                args=(user.email, user.username, 'Suspicious login denied by account owner'),
                daemon=False,
            ).start()
    else:
        db.session.commit()
    flash(
        'Your account has been secured. You have been logged out. '
        'Use "Forgot password?" to reset your password and regain access.',
        'warning',
    )
    return redirect(url_for('login'))


# ── Logout ────────────────────────────────────────────────────────────────
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flask_session.clear()
    flash(
        'You have been securely signed out. '
        'Sign in again to access your account.',
        'info',
    )
    return redirect(url_for('login'))


# ══════════════════════════════════════════════════════════════════════════
# AUTHENTICATED ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/dashboard')
@login_required
def dashboard():
    uid = current_user.id

    total_logins      = LoginHistory.query.filter_by(user_id=uid).filter(
        LoginHistory.login_status.in_(['success', 'failed', 'failed_2fa'])
    ).count()
    successful_logins = LoginHistory.query.filter_by(user_id=uid, login_status='success').count()
    failed_logins     = LoginHistory.query.filter(
        LoginHistory.user_id == uid,
        LoginHistory.login_status.in_(['failed', 'failed_2fa'])
    ).count()
    suspicious_count  = LoginHistory.query.filter_by(user_id=uid, is_suspicious=True).count()

    recent_logins = (
        LoginHistory.query.filter_by(user_id=uid)
        .filter(LoginHistory.login_status != 'pending_2fa')
        .order_by(LoginHistory.login_time.desc())
        .limit(10).all()
    )
    recent_alerts = (
        Alert.query.filter_by(user_id=uid)
        .order_by(Alert.created_at.desc())
        .limit(5).all()
    )

    return render_template(
        'dashboard.html',
        total_logins=total_logins,
        successful_logins=successful_logins,
        failed_logins=failed_logins,
        suspicious_count=suspicious_count,
        recent_logins=recent_logins,
        recent_alerts=recent_alerts,
    )


@app.route('/login-history')
@login_required
def login_history():
    page   = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'all')

    q = LoginHistory.query.filter_by(user_id=current_user.id).filter(
        LoginHistory.login_status != 'pending_2fa'
    )
    if status == 'success':
        q = q.filter_by(login_status='success')
    elif status == 'failed':
        q = q.filter(LoginHistory.login_status.in_(['failed', 'failed_2fa']))
    elif status == 'suspicious':
        q = q.filter_by(is_suspicious=True)

    logins = q.order_by(LoginHistory.login_time.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    return render_template('login_history.html', logins=logins, filter_status=status)


@app.route('/alerts')
@login_required
def alerts():
    page = request.args.get('page', 1, type=int)

    Alert.query.filter_by(user_id=current_user.id, is_read=False).update({'is_read': True})
    db.session.commit()

    all_alerts = (
        Alert.query.filter_by(user_id=current_user.id)
        .order_by(Alert.created_at.desc())
        .paginate(page=page, per_page=20, error_out=False)
    )
    return render_template('alerts.html', alerts=all_alerts)


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        action       = request.form.get('action', '')
        new_email    = request.form.get('email', '').strip().lower()
        cur_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm      = request.form.get('confirm_password', '')
        ip           = get_client_ip()
        location     = get_location(ip)
        now          = datetime.utcnow()

        if action == 'email':
            if new_email and new_email != current_user.email:
                if User.query.filter_by(email=new_email).first():
                    flash('That email is already in use.', 'danger')
                else:
                    old_email = current_user.email
                    current_user.email = new_email
                    db.session.commit()
                    flash('Email address updated.', 'success')
                    if not app.config.get('TESTING', False):
                        threading.Thread(
                            target=send_email_changed_email,
                            args=(new_email, current_user.username,
                                  old_email, new_email, ip, location, now),
                            daemon=False,
                        ).start()
            else:
                db.session.commit()

        elif action == 'password':
            if not current_user.check_password(cur_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm:
                flash('New passwords do not match.', 'danger')
            elif len(new_password) < 8:
                flash('New password must be at least 8 characters.', 'danger')
            else:
                current_user.set_password(new_password)
                db.session.commit()
                flash('Password updated successfully.', 'success')
                if not app.config.get('TESTING', False):
                    threading.Thread(
                        target=send_password_changed_email,
                        args=(current_user.email, current_user.username, ip, location, now),
                        daemon=False,
                    ).start()

        elif action == 'enable_2fa':
            current_user.two_fa_enabled = True
            db.session.commit()
            flash('Two-Factor Authentication enabled. Your login will now require an email code.', 'success')
            if not app.config.get('TESTING', False):
                threading.Thread(
                    target=send_2fa_changed_email,
                    args=(current_user.email, current_user.username, True, ip, location, now),
                    daemon=False,
                ).start()

        elif action == 'disable_2fa':
            current_user.two_fa_enabled = False
            db.session.commit()
            flash('Two-Factor Authentication disabled.', 'info')
            if not app.config.get('TESTING', False):
                threading.Thread(
                    target=send_2fa_changed_email,
                    args=(current_user.email, current_user.username, False, ip, location, now),
                    daemon=False,
                ).start()

        return redirect(url_for('profile'))

    login_count = LoginHistory.query.filter_by(
        user_id=current_user.id, login_status='success'
    ).count()
    return render_template('profile.html', login_count=login_count)


# ══════════════════════════════════════════════════════════════════════════
# TESTING / SIMULATION ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/testing')
@login_required
def testing():
    return render_template('testing.html')


@app.route('/testing/simulate', methods=['POST'])
@login_required
def simulate():
    scenario = request.form.get('scenario')
    uid      = current_user.id
    user     = current_user._get_current_object()
    now      = datetime.utcnow()

    if scenario == 'new_ip':
        rec = LoginHistory(
            user_id=uid, ip_address='185.220.101.99',
            device_type='PC', browser='Chrome 124.0', os='Windows 10',
            user_agent='Mozilla/5.0 (test)', login_time=now, login_status='success',
        )
        db.session.add(rec); db.session.flush()
        det = SuspiciousLoginDetector(user, rec, db.session)
        susp, reasons = det.analyze()
        rec.is_suspicious = susp; rec.suspicious_reasons = '; '.join(reasons)
        if susp:
            _fire_alert(user, rec, reasons, rec.ip_address,
                        {'device_type': rec.device_type, 'browser': rec.browser, 'os': rec.os})
        db.session.commit()
        flash(f'New-IP login simulated. Suspicious: {susp}. Reasons: {", ".join(reasons) or "none"}', 'info')

    elif scenario == 'new_device':
        existing = LoginHistory.query.filter_by(user_id=uid, login_status='success')\
            .order_by(LoginHistory.login_time.desc()).first()
        sim_dev = 'Mobile' if (not existing or existing.device_type != 'Mobile') else 'PC'
        ip = get_client_ip()
        rec = LoginHistory(
            user_id=uid, ip_address=ip,
            device_type=sim_dev, browser='Safari 17.0', os='iOS 17',
            user_agent='Mozilla/5.0 (iPhone; test)', login_time=now, login_status='success',
        )
        db.session.add(rec); db.session.flush()
        det = SuspiciousLoginDetector(user, rec, db.session)
        susp, reasons = det.analyze()
        rec.is_suspicious = susp; rec.suspicious_reasons = '; '.join(reasons)
        if susp:
            _fire_alert(user, rec, reasons, ip,
                        {'device_type': sim_dev, 'browser': rec.browser, 'os': rec.os})
        db.session.commit()
        flash(f'New-Device ({sim_dev}) login simulated. Suspicious: {susp}.', 'info')

    elif scenario == 'unusual_hour':
        ip = get_client_ip(); ua_raw = request.headers.get('User-Agent', '')
        ua = parse_user_agent(ua_raw)
        sim_time = now.replace(hour=2, minute=17, second=0)
        rec = LoginHistory(
            user_id=uid, ip_address=ip,
            device_type=ua['device_type'], browser=ua['browser'], os=ua['os'],
            user_agent=ua_raw, login_time=sim_time, login_status='success',
        )
        db.session.add(rec); db.session.flush()
        rec.is_suspicious = True
        rec.suspicious_reasons = 'Login during unusual hours: 02:17 UTC (between 00:00 and 05:00)'
        _fire_alert(user, rec, [rec.suspicious_reasons], ip, ua)
        db.session.commit()
        flash('Unusual-hour login (02:17 UTC) simulated. Marked suspicious.', 'info')

    elif scenario == 'brute_force':
        ip = '203.0.113.55'
        last_rec = None
        for _ in range(5):
            last_rec = LoginHistory(
                user_id=uid, ip_address=ip,
                device_type='PC', browser='Firefox 125.0', os='Linux',
                user_agent='Mozilla/5.0 (test-brute)', login_time=now, login_status='failed',
            )
            db.session.add(last_rec)
            db.session.add(FailedAttempt(user_id=uid, ip_address=ip))
        db.session.flush()
        _fire_alert(user, last_rec,
                    ['5 failed login attempts simulated from IP 203.0.113.55'],
                    ip, {'device_type': 'PC', 'browser': 'Firefox 125.0', 'os': 'Linux'},
                    alert_type='brute_force')
        db.session.commit()
        flash('Brute-force attack (5 failed logins) simulated. Alert generated.', 'warning')

    elif scenario == 'test_email':
        ip = get_client_ip(); ua_raw = request.headers.get('User-Agent', '')
        ua = parse_user_agent(ua_raw)
        threading.Thread(
            target=send_alert_email,
            args=(user.email, user.username, ip, ua, ['Test alert from HDS Testing Panel'], now),
            daemon=False,
        ).start()
        flash(f'Test security alert sent to {user.email}.', 'success')

    elif scenario == 'test_otp_email':
        code = generate_otp()
        threading.Thread(
            target=send_otp_email,
            args=(user.email, user.username, code),
            daemon=False,
        ).start()
        flash(f'Test OTP email queued. Check {user.email} — code: {code}.', 'success')

    return redirect(url_for('testing'))


@app.route('/testing/clear', methods=['POST'])
@login_required
def clear_test_data():
    uid = current_user.id
    SecurityToken.query.filter_by(user_id=uid).delete()
    OTPCode.query.filter_by(user_id=uid).delete()
    LoginHistory.query.filter_by(user_id=uid).delete()
    Alert.query.filter_by(user_id=uid).delete()
    FailedAttempt.query.filter_by(user_id=uid).delete()
    KnownIP.query.filter_by(user_id=uid).delete()
    KnownDevice.query.filter_by(user_id=uid).delete()
    db.session.commit()
    flash('All login history, alerts, OTP records, known IPs and devices cleared.', 'info')
    return redirect(url_for('testing'))


# ══════════════════════════════════════════════════════════════════════════
# JSON API  (dashboard charts)
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/login-stats')
@login_required
def api_login_stats():
    uid   = current_user.id
    stats = []
    for i in range(6, -1, -1):
        day   = (datetime.utcnow() - timedelta(days=i)).date()
        total = (LoginHistory.query.filter_by(user_id=uid)
                 .filter(func.date(LoginHistory.login_time) == day).count())
        susp  = (LoginHistory.query.filter_by(user_id=uid, is_suspicious=True)
                 .filter(func.date(LoginHistory.login_time) == day).count())
        stats.append({'date': str(day), 'total': total, 'suspicious': susp})
    return jsonify(stats)


@app.route('/api/device-stats')
@login_required
def api_device_stats():
    uid  = current_user.id
    rows = (
        db.session.query(LoginHistory.device_type, func.count(LoginHistory.id))
        .filter_by(user_id=uid, login_status='success')
        .group_by(LoginHistory.device_type).all()
    )
    return jsonify([{'device': r[0] or 'Unknown', 'count': r[1]} for r in rows])


# ── Init & run ─────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
