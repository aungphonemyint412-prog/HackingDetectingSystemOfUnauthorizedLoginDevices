"""
Hacking Detection System of Unauthorized Login to the Device
Flask Application – Main entry point
"""
import secrets
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
import user_agents as ua_lib

from config import Config
from models import db, User, LoginHistory, Alert, OTPCode
from detection import SuspiciousLoginDetector
from email_alert import send_alert_email, send_otp_email

# ── App factory ────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'warning'


@login_manager.user_loader
def load_user(user_id: str):
    return User.query.get(int(user_id))


# ── Context processor ─────────────────────────────────────────────────────
@app.context_processor
def inject_unread_alerts():
    try:
        if current_user.is_authenticated:
            count = Alert.query.filter_by(
                user_id=current_user.id, is_read=False
            ).count()
            return {'unread_alert_count': count}
    except Exception:
        pass
    return {'unread_alert_count': 0}


# ── Utility helpers ───────────────────────────────────────────────────────
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
    """Return a masked version of an email for display (e.g. t***r@example.com)."""
    try:
        local, domain = email.split('@', 1)
        if len(local) <= 2:
            masked = local[0] + '*'
        else:
            masked = local[0] + '*' * (len(local) - 2) + local[-1]
        return f'{masked}@{domain}'
    except Exception:
        return email


def generate_otp() -> str:
    """Return a random 6-digit string."""
    return f'{secrets.randbelow(1000000):06d}'


def _record_login(user: User, status: str, ua_info: dict, ip: str,
                  ua_raw: str, two_fa_required: bool = False) -> LoginHistory:
    record = LoginHistory(
        user_id         = user.id,
        ip_address      = ip,
        device_type     = ua_info['device_type'],
        browser         = ua_info['browser'],
        os              = ua_info['os'],
        user_agent      = ua_raw,
        login_time      = datetime.utcnow(),
        login_status    = status,
        two_fa_required = two_fa_required,
    )
    db.session.add(record)
    return record


def _fire_alert(user: User, record: LoginHistory, reasons: list[str],
                ip: str, ua_info: dict, alert_type: str = 'suspicious_login'):
    alert = Alert(
        user_id          = user.id,
        login_history_id = record.id,
        alert_type       = alert_type,
        message          = '; '.join(reasons),
        created_at       = datetime.utcnow(),
    )
    db.session.add(alert)
    try:
        sent = send_alert_email(
            user.email, user.username, ip, ua_info, reasons, datetime.utcnow()
        )
        alert.email_sent = sent
    except Exception:
        pass


def _run_detection_and_commit(user: User, record: LoginHistory,
                               ip: str, ua_info: dict) -> bool:
    """Run suspicious-login detection, fire alert if needed, commit. Returns is_suspicious."""
    detector = SuspiciousLoginDetector(user, record, db.session)
    is_suspicious, reasons = detector.analyze()
    if is_suspicious:
        record.is_suspicious      = True
        record.suspicious_reasons = '; '.join(reasons)
        _fire_alert(user, record, reasons, ip, ua_info)
    db.session.commit()
    return is_suspicious


# ══════════════════════════════════════════════════════════════════════════
# PUBLIC ROUTES
# ══════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


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

        flash('Account created successfully! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


# ── Login ─────────────────────────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        ip     = get_client_ip()
        ua_raw = request.headers.get('User-Agent', '')
        ua     = parse_user_agent(ua_raw)

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            # ── Correct password ──────────────────────────────────────────
            if user.two_fa_enabled:
                # Create a pending login record
                record = _record_login(user, 'pending_2fa', ua, ip, ua_raw,
                                       two_fa_required=True)
                db.session.flush()

                # Generate and persist OTP
                code = generate_otp()
                otp  = OTPCode(
                    user_id          = user.id,
                    code_hash        = secrets.token_hex(32),  # placeholder; real check below
                    expires_at       = datetime.utcnow() + timedelta(minutes=5),
                    ip_address       = ip,
                    login_history_id = record.id,
                )
                # Store the plain code hashed via werkzeug
                from werkzeug.security import generate_password_hash
                otp.code_hash = generate_password_hash(code)
                db.session.add(otp)
                db.session.commit()

                # Store pending state in the Flask session (cookie)
                flask_session['pending_2fa_user_id']      = user.id
                flask_session['pending_2fa_login_rec_id'] = record.id
                flask_session['pending_2fa_otp_id']       = otp.id

                # Email the code
                sent = send_otp_email(user.email, user.username, code)
                if sent:
                    flash(
                        f'A 6-digit verification code has been sent to '
                        f'{mask_email(user.email)}. It expires in 5 minutes.',
                        'info',
                    )
                else:
                    flash(
                        'Could not send verification email. Check MAIL settings in .env, '
                        'or disable 2FA in your profile.',
                        'warning',
                    )

                return redirect(url_for('verify_2fa'))

            else:
                # ── No 2FA – log straight in ──────────────────────────────
                record = _record_login(user, 'success', ua, ip, ua_raw)
                db.session.flush()
                is_susp = _run_detection_and_commit(user, record, ip, ua)
                login_user(user, remember=False)

                if is_susp:
                    flash(
                        f'Login successful — suspicious activity detected. '
                        f'A security alert has been sent to {user.email}.',
                        'warning',
                    )
                else:
                    flash('Welcome back!', 'success')

                next_page = request.args.get('next')
                return redirect(next_page or url_for('dashboard'))

        else:
            # ── Wrong password ────────────────────────────────────────────
            if user:
                record = _record_login(user, 'failed', ua, ip, ua_raw)
                db.session.flush()

                window    = app.config['FAILED_ATTEMPT_WINDOW']
                max_fail  = app.config['MAX_FAILED_ATTEMPTS']
                since     = datetime.utcnow() - timedelta(minutes=window)
                fail_count = (
                    LoginHistory.query
                    .filter_by(user_id=user.id, login_status='failed')
                    .filter(LoginHistory.login_time >= since)
                    .count()
                )

                if fail_count >= max_fail:
                    _fire_alert(
                        user, record,
                        [f'{fail_count} failed login attempts in the last {window} min from IP {ip}'],
                        ip, ua, alert_type='brute_force',
                    )
                db.session.commit()

            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


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

        otp_id  = flask_session.get('pending_2fa_otp_id')
        rec_id  = flask_session.get('pending_2fa_login_rec_id')
        ip      = get_client_ip()
        ua_raw  = request.headers.get('User-Agent', '')
        ua      = parse_user_agent(ua_raw)

        otp = OTPCode.query.get(otp_id) if otp_id else None
        record = LoginHistory.query.get(rec_id) if rec_id else None

        from werkzeug.security import check_password_hash as _chk

        if (otp and not otp.is_used and not otp.is_expired
                and _chk(otp.code_hash, entered)):
            # ── Valid OTP ─────────────────────────────────────────────────
            otp.is_used = True
            if record:
                record.login_status  = 'success'
                record.two_fa_verified = True

            db.session.flush()
            is_susp = _run_detection_and_commit(user, record, ip, ua) if record else False

            # Clear pending session keys
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
            return redirect(url_for('dashboard'))

        else:
            # ── Invalid / expired OTP ─────────────────────────────────────
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

    # Invalidate old OTP
    old_id = flask_session.get('pending_2fa_otp_id')
    if old_id:
        old = OTPCode.query.get(old_id)
        if old:
            old.is_used = True

    # New OTP
    from werkzeug.security import generate_password_hash as _hash
    code = generate_otp()
    otp  = OTPCode(
        user_id          = user.id,
        code_hash        = _hash(code),
        expires_at       = datetime.utcnow() + timedelta(minutes=5),
        ip_address       = ip,
        login_history_id = flask_session.get('pending_2fa_login_rec_id'),
    )
    db.session.add(otp)
    db.session.commit()
    flask_session['pending_2fa_otp_id'] = otp.id

    sent = send_otp_email(user.email, user.username, code)
    if sent:
        flash(f'A new code has been sent to {mask_email(user.email)}.', 'info')
    else:
        flash('Could not send email. Check MAIL settings.', 'danger')

    return redirect(url_for('verify_2fa'))


# ── Logout ────────────────────────────────────────────────────────────────
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
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

        if action == 'email':
            if new_email and new_email != current_user.email:
                if User.query.filter_by(email=new_email).first():
                    flash('That email is already in use.', 'danger')
                else:
                    current_user.email = new_email
                    flash('Email address updated.', 'success')
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

        elif action == 'enable_2fa':
            current_user.two_fa_enabled = True
            db.session.commit()
            flash('Two-Factor Authentication enabled. Your login will now require an email code.', 'success')

        elif action == 'disable_2fa':
            current_user.two_fa_enabled = False
            db.session.commit()
            flash('Two-Factor Authentication disabled.', 'info')

        return redirect(url_for('profile'))

    login_count = LoginHistory.query.filter_by(
        user_id=current_user.id, login_status='success'
    ).count()
    return render_template('profile.html', login_count=login_count)


# ══════════════════════════════════════════════════════════════════════════
# TESTING / SIMULATION ROUTES  (demonstration purposes)
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
        for _ in range(5):
            rec = LoginHistory(
                user_id=uid, ip_address=ip,
                device_type='PC', browser='Firefox 125.0', os='Linux',
                user_agent='Mozilla/5.0 (test-brute)', login_time=now, login_status='failed',
            )
            db.session.add(rec)
        db.session.flush()
        _fire_alert(user, rec, ['5 failed login attempts simulated from IP 203.0.113.55'], ip,
                    {'device_type': 'PC', 'browser': 'Firefox 125.0', 'os': 'Linux'},
                    alert_type='brute_force')
        db.session.commit()
        flash('Brute-force attack (5 failed logins) simulated. Alert generated.', 'warning')

    elif scenario == 'test_email':
        ip = get_client_ip(); ua_raw = request.headers.get('User-Agent', '')
        ua = parse_user_agent(ua_raw)
        sent = send_alert_email(user.email, user.username, ip, ua,
                                ['Test alert from HDS Testing Panel'], now)
        flash(f'Test email {"sent to " + user.email if sent else "failed — check MAIL settings in .env"}.',
              'success' if sent else 'danger')

    elif scenario == 'test_otp_email':
        code = generate_otp()
        sent = send_otp_email(user.email, user.username, code)
        flash(
            f'Test OTP email {"sent to " + user.email + " (code: " + code + ")" if sent else "failed — check MAIL settings in .env"}.',
            'success' if sent else 'danger',
        )

    return redirect(url_for('testing'))


@app.route('/testing/clear', methods=['POST'])
@login_required
def clear_test_data():
    uid = current_user.id
    OTPCode.query.filter_by(user_id=uid).delete()
    LoginHistory.query.filter_by(user_id=uid).delete()
    Alert.query.filter_by(user_id=uid).delete()
    db.session.commit()
    flash('All login history, alerts, and OTP records cleared.', 'info')
    return redirect(url_for('testing'))


# ══════════════════════════════════════════════════════════════════════════
# JSON API  (dashboard charts)
# ══════════════════════════════════════════════════════════════════════════

@app.route('/api/login-stats')
@login_required
def api_login_stats():
    uid = current_user.id
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
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print('Database tables created.')
    app.run(debug=True, host='0.0.0.0', port=5000)
