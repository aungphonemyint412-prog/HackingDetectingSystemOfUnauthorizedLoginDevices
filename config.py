import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ──────────────────────────────────────────────────────────────
    SECRET_KEY = os.environ.get('SECRET_KEY', 'hds-dev-secret-key-2024')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # ── Database ───────────────────────────────────────────────────────────
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 'sqlite:///hacking_detection.db'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── Google OAuth ───────────────────────────────────────────────────────
    GOOGLE_OAUTH_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID', '')
    GOOGLE_OAUTH_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')

    # ── Gmail SMTP ─────────────────────────────────────────────────────────
    MAIL_SERVER   = 'smtp.gmail.com'
    MAIL_PORT     = 587
    MAIL_USE_TLS  = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')

    # ── Detection Rules ────────────────────────────────────────────────────
    MAX_FAILED_ATTEMPTS   = 3
    FAILED_ATTEMPT_WINDOW = 30
    RAPID_LOGIN_COUNT     = 3
    RAPID_LOGIN_WINDOW    = 10
    UNUSUAL_HOUR_START         = 0
    UNUSUAL_HOUR_END           = 5
    HISTORY_LOOKUP             = 50
    LOCKOUT_DURATION           = 30   # minutes to lock after brute force
    IMPOSSIBLE_TRAVEL_SPEED    = 900  # km/h threshold for R7

    # ── Admin / SOC ────────────────────────────────────────────────────────
    ADMIN_EMAILS = [
        e.strip() for e in os.environ.get('ADMIN_EMAILS', '').split(',') if e.strip()
    ]

    # ── Email rate limits: {email_type: (max_count, window_minutes)} ───────
    EMAIL_RATE_LIMITS = {
        'login_notification': (3,  360),   # max 3 per 6 h
        'failed_login':       (1,   30),   # max 1 per 30 min
        'password_changed':   (2,   60),   # max 2 per hour
        'email_changed':      (2,   60),
        'twofa_changed':      (2,   60),
        'twofa_recovery':     (2,   60),
    }
    # alert / account_locked / admin_soc are never rate-limited
