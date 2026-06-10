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

    # ── Gmail SMTP ─────────────────────────────────────────────────────────
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '')   # sender Gmail
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', '')   # Gmail App Password

    # ── Detection Rules ────────────────────────────────────────────────────
    MAX_FAILED_ATTEMPTS = 3       # failed logins in window before alert
    FAILED_ATTEMPT_WINDOW = 30    # minutes
    RAPID_LOGIN_COUNT = 3         # successful logins in rapid window
    RAPID_LOGIN_WINDOW = 10       # minutes
    UNUSUAL_HOUR_START = 0        # midnight
    UNUSUAL_HOUR_END = 5          # 5 AM  (exclusive)
    HISTORY_LOOKUP = 50           # previous logins to compare against
