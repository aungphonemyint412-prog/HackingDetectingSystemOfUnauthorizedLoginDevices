# Hacking Detection System (HDS)

A Flask web application that monitors user logins, detects suspicious activity, and alerts account owners via Gmail. Built as a final-year Computing Research Project (Pearson BTEC HND Unit 16).

## Features

- **Suspicious login detection** — six rule-based checks run on every login
- **Real-time email alerts** — Gmail SMTP notifications when suspicious activity is found
- **Two-Factor Authentication (2FA)** — OTP code sent to email, required per-account
- **IP geolocation in 2FA email** — every OTP email shows the login's City, Country, Device, Browser, and OS
- **Forgot Password with OTP** — self-service password reset via email code
- **Google OAuth login** — sign in or link a Gmail account via Google
- **Login history** — full paginated log of every login attempt with status and location
- **Alerts dashboard** — view all security alerts with read/unread tracking
- **Attack simulation panel** — trigger test scenarios (new IP, new device, unusual hour, brute force)
- **Brute-force detection** — alert fired after configurable failed-attempt threshold

## Detection Rules

| Rule | Trigger |
|------|---------|
| R1 | New IP address not seen before |
| R2 | New device type (PC / Mobile / Tablet) |
| R3 | New browser family |
| R4 | New operating system |
| R5 | Login between 00:00–04:59 UTC |
| R6 | Multiple successful logins within a short window |

## Tech Stack

- **Backend** — Python 3, Flask 3, Flask-SQLAlchemy, Flask-Login, Flask-Dance
- **Database** — SQLite (dev) — swap `DATABASE_URL` for Postgres in production
- **Auth** — Werkzeug password hashing, Google OAuth 2.0, TOTP-style OTP via Gmail SMTP
- **Geolocation** — ip-api.com (free, no API key required)
- **Frontend** — Bootstrap 5, Chart.js, Font Awesome

## Project Structure

```
├── app.py               # All routes and application factory
├── config.py            # Configuration (reads from .env)
├── models.py            # SQLAlchemy models (User, LoginHistory, Alert, OTPCode, ...)
├── detection.py         # Rule-based suspicious login engine (R1–R6)
├── email_alert.py       # Gmail SMTP — alert emails and OTP emails
├── create_test_data.py  # Seeds demo user and sample login history
├── requirements.txt
├── .env.example         # Environment variable template
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── forgot_password.html
│   ├── verify_2fa.html
│   ├── verify_reset_otp.html
│   ├── reset_password.html
│   ├── dashboard.html
│   ├── login_history.html
│   ├── alerts.html
│   ├── profile.html
│   └── testing.html
└── tests/
    └── test_app.py      # 28 pytest tests
```

## Setup

### 1. Clone and install

```bash
git clone https://github.com/aungphonemyint412-prog/HackingDetectingSystemOfUnauthorizedLoginDevices.git
cd HackingDetectingSystemOfUnauthorizedLoginDevices
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
```

Edit `.env`:

```env
SECRET_KEY=change-me-to-a-long-random-string

# Gmail SMTP (required for 2FA and alerts)
MAIL_USERNAME=your-gmail@gmail.com
MAIL_PASSWORD=your-16-char-app-password   # Gmail App Password, not your login password

# Google OAuth (optional — enables "Sign in with Google")
GOOGLE_CLIENT_ID=your_google_client_id_here
GOOGLE_CLIENT_SECRET=your_google_client_secret_here
```

**Gmail App Password:** Go to [myaccount.google.com](https://myaccount.google.com) → Security → 2-Step Verification → App passwords.

**Google OAuth:** Create credentials at [console.cloud.google.com](https://console.cloud.google.com) → APIs & Services → Credentials → OAuth 2.0 Client ID. Set the redirect URI to `http://localhost:5000/login/google/authorized`.

### 3. Run

```bash
python app.py
```

Visit [http://localhost:5000](http://localhost:5000).

### 4. Demo data (optional)

```bash
python create_test_data.py
# Creates: demouser / Password123
```

## Forgot Password Flow

1. Click **Forgot password?** on the login page
2. Enter your registered email address
3. Check your inbox for a 6-digit reset code (valid 10 minutes)
4. Enter the code, then set your new password

## Running Tests

```bash
python -m pytest tests/ -v
```

28 tests covering registration, login, 2FA, detection rules, brute-force alerts, and API endpoints. Each test uses a fresh in-memory SQLite database.

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask session signing key |
| `MAIL_USERNAME` | Yes | Gmail address used to send alerts |
| `MAIL_PASSWORD` | Yes | Gmail App Password (16 characters) |
| `GOOGLE_CLIENT_ID` | No | Enables Google OAuth login |
| `GOOGLE_CLIENT_SECRET` | No | Enables Google OAuth login |
| `DATABASE_URL` | No | Defaults to `sqlite:///hacking_detection.db` |

## Detection Thresholds (config.py)

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_FAILED_ATTEMPTS` | 3 | Failed logins before brute-force alert |
| `FAILED_ATTEMPT_WINDOW` | 30 min | Window for counting failed attempts |
| `RAPID_LOGIN_COUNT` | 3 | Successful logins that trigger R6 |
| `RAPID_LOGIN_WINDOW` | 10 min | Window for R6 check |
| `UNUSUAL_HOUR_START` | 0 | Start of unusual-hour window (UTC) |
| `UNUSUAL_HOUR_END` | 5 | End of unusual-hour window (UTC) |
