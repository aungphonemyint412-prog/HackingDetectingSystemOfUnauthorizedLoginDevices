"""
Unit and integration tests for the HDS Flask application.

Run:  python -m pytest tests/ -v
"""
import sys, os, tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from datetime import datetime, timedelta

from werkzeug.security import generate_password_hash

from app import app as flask_app, generate_otp, mask_email
from models import db, User, LoginHistory, Alert, OTPCode
from detection import SuspiciousLoginDetector


# ── Fixtures ───────────────────────────────────────────────────────────
@pytest.fixture
def app():
    """
    Function-scoped fixture: fresh temp-file SQLite DB per test.
    Each test gets a completely isolated database — no shared state.
    """
    db_fd, db_path = tempfile.mkstemp(suffix='_hds_test.db')

    flask_app.config.update({
        'TESTING':                 True,
        'SQLALCHEMY_DATABASE_URI': f'sqlite:///{db_path}',
        'WTF_CSRF_ENABLED':        False,
        'SECRET_KEY':              'test-secret',
        'LOGIN_DISABLED':          False,
        'MAIL_USERNAME':           '',
        'MAIL_PASSWORD':           '',
    })

    # Push a single long-lived app context for the test.
    ctx = flask_app.app_context()
    ctx.push()
    db.create_all()

    yield flask_app

    db.session.close()
    db.drop_all()
    ctx.pop()
    os.close(db_fd)
    try:
        os.unlink(db_path)
    except OSError:
        pass


@pytest.fixture
def client(app):
    return app.test_client()


# ── Helpers ────────────────────────────────────────────────────────────
def _register(client, username='testuser', email='test@example.com',
              password='Password123'):
    return client.post('/register', data={
        'username':         username,
        'email':            email,
        'password':         password,
        'confirm_password': password,
    }, follow_redirects=True)


def _login(client, username='testuser', password='Password123'):
    return client.post('/login', data={
        'username': username,
        'password': password,
    }, follow_redirects=True)


def _logout(client):
    return client.get('/logout', follow_redirects=True)


# ══════════════════════════════════════════════════════════════════════════
# Registration
# ══════════════════════════════════════════════════════════════════════════

class TestRegistration:

    def test_register_success(self, client):
        _register(client)
        db.session.expire_all()
        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        assert user.email == 'test@example.com'

    def test_register_duplicate_username(self, client):
        _register(client)
        r = _register(client)
        assert b'Username already taken' in r.data

    def test_register_duplicate_email(self, client):
        _register(client)
        r = _register(client, username='other', email='test@example.com')
        assert b'Email address already registered' in r.data

    def test_register_short_password(self, client):
        r = _register(client, password='abc')
        assert b'8 characters' in r.data

    def test_register_password_mismatch(self, client):
        r = client.post('/register', data={
            'username':         'testuser',
            'email':            'test@example.com',
            'password':         'Password123',
            'confirm_password': 'Different123',
        }, follow_redirects=True)
        assert b'do not match' in r.data


# ══════════════════════════════════════════════════════════════════════════
# Authentication
# ══════════════════════════════════════════════════════════════════════════

class TestAuthentication:

    def test_login_success(self, client):
        _register(client)
        _logout(client)
        r = _login(client)
        assert r.status_code == 200
        assert b'testuser' in r.data or b'Dashboard' in r.data

    def test_login_records_history(self, client):
        _register(client)
        _logout(client)
        _login(client)
        db.session.expire_all()
        user = User.query.filter_by(username='testuser').first()
        assert user is not None
        record = LoginHistory.query.filter_by(
            user_id=user.id, login_status='success'
        ).first()
        assert record is not None
        assert record.ip_address is not None

    def test_login_wrong_password(self, client):
        _register(client)
        _logout(client)
        r = _login(client, password='WrongPassword')
        assert b'Invalid username or password' in r.data

    def test_failed_login_recorded(self, client):
        _register(client)
        _logout(client)
        _login(client, password='WrongPassword')
        db.session.expire_all()
        user  = User.query.filter_by(username='testuser').first()
        assert user is not None
        count = LoginHistory.query.filter_by(
            user_id=user.id, login_status='failed'
        ).count()
        assert count >= 1

    def test_login_unknown_user(self, client):
        r = _login(client, username='nobody')
        assert b'Invalid username or password' in r.data

    def test_logout(self, client):
        _register(client)
        _login(client)
        r = _logout(client)
        assert b'logged out' in r.data


# ══════════════════════════════════════════════════════════════════════════
# Dashboard access control
# ══════════════════════════════════════════════════════════════════════════

class TestAccessControl:

    def test_dashboard_redirects_unauthenticated(self, client):
        r = client.get('/dashboard', follow_redirects=False)
        assert r.status_code == 302
        assert '/login' in r.headers.get('Location', '')

    def test_dashboard_accessible_after_login(self, client):
        _register(client)
        _logout(client)
        _login(client)
        r = client.get('/dashboard')
        assert r.status_code == 200

    def test_login_history_requires_auth(self, client):
        r = client.get('/login-history', follow_redirects=False)
        assert r.status_code == 302

    def test_alerts_requires_auth(self, client):
        r = client.get('/alerts', follow_redirects=False)
        assert r.status_code == 302

    def test_profile_requires_auth(self, client):
        r = client.get('/profile', follow_redirects=False)
        assert r.status_code == 302


# ══════════════════════════════════════════════════════════════════════════
# Detection Engine
# ══════════════════════════════════════════════════════════════════════════

class TestDetection:
    """Detection tests work directly against db.session (no HTTP client needed)."""

    def _make_user(self):
        user = User(username='detuser', email='det@example.com')
        user.set_password('Password123')
        db.session.add(user)
        db.session.flush()
        return user

    def _make_login(self, user, ip='10.0.0.1', device='PC',
                    browser='Chrome 124.0', os_='Windows 10',
                    status='success', hour=10):
        t = datetime.utcnow().replace(hour=hour, minute=0, second=0)
        rec = LoginHistory(
            user_id=user.id, ip_address=ip, device_type=device,
            browser=browser, os=os_, login_time=t, login_status=status,
        )
        db.session.add(rec)
        db.session.flush()
        return rec

    def test_first_login_not_suspicious(self, app):
        user = self._make_user()
        rec  = self._make_login(user)
        det  = SuspiciousLoginDetector(user, rec, db.session)
        susp, reasons = det.analyze()
        assert not susp, f'First login should not be suspicious: {reasons}'

    def test_new_ip_flagged(self, app):
        user = self._make_user()
        self._make_login(user, ip='192.168.1.1')
        db.session.commit()
        new_rec = self._make_login(user, ip='203.0.113.1')
        det = SuspiciousLoginDetector(user, new_rec, db.session)
        susp, reasons = det.analyze()
        assert susp
        assert any('IP' in r for r in reasons)

    def test_same_ip_not_flagged(self, app):
        user = self._make_user()
        self._make_login(user, ip='192.168.1.1')
        db.session.commit()
        rec2 = self._make_login(user, ip='192.168.1.1')
        _, reasons = SuspiciousLoginDetector(user, rec2, db.session).analyze()
        assert not any('IP' in r for r in reasons)

    def test_unusual_hour_flagged(self, app):
        user = self._make_user()
        rec  = self._make_login(user, hour=2)
        _, reasons = SuspiciousLoginDetector(user, rec, db.session).analyze()
        assert any('unusual hour' in r.lower() for r in reasons)

    def test_new_device_flagged(self, app):
        user = self._make_user()
        self._make_login(user, device='PC')
        db.session.commit()
        rec2 = self._make_login(user, device='Mobile')
        susp, reasons = SuspiciousLoginDetector(user, rec2, db.session).analyze()
        assert any('device' in r.lower() for r in reasons)

    def test_new_browser_flagged(self, app):
        user = self._make_user()
        for _ in range(2):
            self._make_login(user, browser='Chrome 124.0')
        db.session.commit()
        rec3 = self._make_login(user, browser='Firefox 125.0')
        _, reasons = SuspiciousLoginDetector(user, rec3, db.session).analyze()
        assert any('browser' in r.lower() for r in reasons)


# ══════════════════════════════════════════════════════════════════════════
# Password hashing
# ══════════════════════════════════════════════════════════════════════════

class TestPasswordSecurity:

    def test_password_is_hashed(self, app):
        user = User(username='htest', email='htest@example.com')
        user.set_password('MySecretPassword')
        assert user.password_hash != 'MySecretPassword'
        assert len(user.password_hash) > 30

    def test_correct_password_accepted(self, app):
        user = User(username='htest2', email='htest2@example.com')
        user.set_password('MySecretPassword')
        assert user.check_password('MySecretPassword')

    def test_wrong_password_rejected(self, app):
        user = User(username='htest3', email='htest3@example.com')
        user.set_password('MySecretPassword')
        assert not user.check_password('WrongPassword')


# ══════════════════════════════════════════════════════════════════════════
# Two-Factor Authentication
# ══════════════════════════════════════════════════════════════════════════

class TestTwoFactorAuth:

    def _register_and_enable_2fa(self, client):
        """Helper: register, log out, enable 2FA, log out."""
        _register(client)
        _login(client)
        # Enable 2FA via profile POST
        client.post('/profile', data={'action': 'enable_2fa'}, follow_redirects=True)
        _logout(client)

    def test_enable_2fa_sets_flag(self, client, app):
        _register(client)
        _login(client)
        client.post('/profile', data={'action': 'enable_2fa'}, follow_redirects=True)
        db.session.expire_all()
        user = User.query.filter_by(username='testuser').first()
        assert user.two_fa_enabled is True

    def test_disable_2fa_clears_flag(self, client, app):
        _register(client)
        _login(client)
        client.post('/profile', data={'action': 'enable_2fa'}, follow_redirects=True)
        client.post('/profile', data={'action': 'disable_2fa'}, follow_redirects=True)
        db.session.expire_all()
        user = User.query.filter_by(username='testuser').first()
        assert user.two_fa_enabled is False

    def test_login_with_2fa_redirects_to_verify(self, client, app):
        """With 2FA on, correct password → redirect to /verify-2fa."""
        self._register_and_enable_2fa(client)
        # Login with correct password (no follow_redirects to see raw 302)
        r = client.post('/login', data={'username': 'testuser', 'password': 'Password123'},
                        follow_redirects=False)
        assert r.status_code == 302
        assert 'verify-2fa' in r.headers.get('Location', '')

    def test_verify_2fa_with_valid_otp(self, client, app):
        """Supplying the correct OTP code completes login."""
        self._register_and_enable_2fa(client)

        # Trigger login (creates OTP in DB)
        client.post('/login', data={'username': 'testuser', 'password': 'Password123'},
                    follow_redirects=False)

        # Fetch the OTP record directly
        db.session.expire_all()
        user = User.query.filter_by(username='testuser').first()
        otp_record = OTPCode.query.filter_by(user_id=user.id, is_used=False).first()
        assert otp_record is not None

        # Build the correct code: we need the raw code. Re-create using known hash is
        # impossible, so we patch the hash to a known code instead.
        known_code = '123456'
        otp_record.code_hash = generate_password_hash(known_code)
        db.session.commit()

        r = client.post('/verify-2fa', data={'otp_code': known_code},
                        follow_redirects=True)
        assert r.status_code == 200
        assert b'Verification successful' in r.data or b'testuser' in r.data

    def test_verify_2fa_with_wrong_otp(self, client, app):
        """Wrong OTP redirects back to login with error."""
        self._register_and_enable_2fa(client)
        client.post('/login', data={'username': 'testuser', 'password': 'Password123'},
                    follow_redirects=False)

        r = client.post('/verify-2fa', data={'otp_code': '000000'},
                        follow_redirects=True)
        assert b'Invalid' in r.data or b'expired' in r.data.lower()

    def test_verify_2fa_records_2fa_required_in_history(self, client, app):
        """Successful 2FA verification sets two_fa_required=True on login record."""
        self._register_and_enable_2fa(client)
        client.post('/login', data={'username': 'testuser', 'password': 'Password123'},
                    follow_redirects=False)

        db.session.expire_all()
        user = User.query.filter_by(username='testuser').first()
        otp_record = OTPCode.query.filter_by(user_id=user.id, is_used=False).first()

        known_code = '654321'
        otp_record.code_hash = generate_password_hash(known_code)
        db.session.commit()

        client.post('/verify-2fa', data={'otp_code': known_code}, follow_redirects=True)

        db.session.expire_all()
        rec = (LoginHistory.query
               .filter_by(user_id=user.id, login_status='success')
               .order_by(LoginHistory.id.desc())
               .first())
        assert rec is not None
        assert rec.two_fa_required is True
        assert rec.two_fa_verified is True

    def test_verify_2fa_without_session_redirects_to_login(self, client):
        """Accessing /verify-2fa without pending session → redirect to login."""
        r = client.get('/verify-2fa', follow_redirects=False)
        assert r.status_code == 302
        assert 'login' in r.headers.get('Location', '').lower()

    def test_generate_otp_format(self, app):
        for _ in range(20):
            code = generate_otp()
            assert len(code) == 6
            assert code.isdigit()

    def test_mask_email(self, app):
        assert mask_email('alice@example.com') == 'a***e@example.com'
        assert mask_email('ab@example.com') == 'a*@example.com'
        assert mask_email('a@example.com') == 'a*@example.com'


# ══════════════════════════════════════════════════════════════════════════
# Public pages
# ══════════════════════════════════════════════════════════════════════════

class TestPublicPages:

    def test_index_loads(self, client):
        r = client.get('/')
        assert r.status_code == 200
        assert b'Hacking Detection' in r.data

    def test_login_page_loads(self, client):
        r = client.get('/login')
        assert r.status_code == 200
        assert b'Sign In' in r.data

    def test_register_page_loads(self, client):
        r = client.get('/register')
        assert r.status_code == 200
        assert b'Create account' in r.data
