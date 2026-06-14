# Hacking Detection System (HDS)

A Flask web application that monitors user logins, detects suspicious activity, and alerts account owners via Gmail. Built as a final-year Computing Research Project (Pearson BTEC HND Unit 16).

## Live Demo

**https://hacking-detection-system-production.up.railway.app**

## Features

### Authentication
- **User registration & login** — username/password with Werkzeug hashing
- **Google OAuth** — sign in or link a Gmail account via Google
- **Two-Factor Authentication (2FA)** — OTP code sent to email, required per-account
- **Forgot Password with OTP** — self-service password reset via 6-digit email code
- **Account lockout** — automatically locks after too many failed login attempts; auto-unlocks after 30 minutes or immediately on password reset

### Suspicious Login Detection (R1–R8)

| Rule | Trigger |
|------|---------|
| R1 | New IP address not seen before |
| R2 | New device type (PC / Mobile / Tablet) |
| R3 | New browser family |
| R4 | New operating system |
| R5 | Login between 00:00–04:59 UTC |
| R6 | Multiple successful logins within a short window |
| R7 | **Impossible travel** — consecutive logins are geographically impossible given elapsed time (haversine formula, >900 km/h threshold) |
| R8 | **VPN / proxy / TOR exit node** detected via ip-api.com |

### Security Alerts & Notifications
- **Suspicious login alert** — email sent when any rule R1–R8 triggers, including:
  - **Risk score (0–100)** — calculated from triggered rules, shown with a colour-coded badge
  - **Security recommendations** — tailored advice based on detected threats
  - **"Was this you?" buttons** — confirm the login as legitimate (green) or deny and lock the account (red); links expire after 48 hours
- **Login notification** — quiet email on every successful non-suspicious login
- **Password changed** — email notification whenever the password is updated
- **Email address changed** — notification sent to both old and new address
- **2FA enabled/disabled** — email confirmation of the change
- **Account locked** — email with unlock instructions when brute-force lockout triggers

### Geolocation
- **IP geolocation in all emails** — every alert and OTP email shows City, Region, Country, Device, Browser, and OS of the login attempt
- **Coordinates stored** — lat/lon saved per login for impossible travel detection (R7)
- Powered by ip-api.com (free, no API key required)

### Dashboard & History
- **Login history** — full paginated log of every login attempt with status, location, risk score
- **Alerts dashboard** — view all security alerts with read/unread tracking
- **Attack simulation panel** — trigger test scenarios (new IP, new device, unusual hour, brute force, test emails)
- **Login statistics charts** — 7-day login volume and device breakdown (Chart.js)

## Detection Thresholds (config.py)

| Setting | Default | Description |
|---------|---------|-------------|
| `MAX_FAILED_ATTEMPTS` | 3 | Failed logins before brute-force alert and lockout |
| `FAILED_ATTEMPT_WINDOW` | 30 min | Window for counting failed attempts |
| `LOCKOUT_DURATION` | 30 min | How long the account stays locked after brute force |
| `RAPID_LOGIN_COUNT` | 3 | Successful logins that trigger R6 |
| `RAPID_LOGIN_WINDOW` | 10 min | Window for R6 check |
| `UNUSUAL_HOUR_START` | 0 | Start of unusual-hour window (UTC) |
| `UNUSUAL_HOUR_END` | 5 | End of unusual-hour window (UTC) |
| `IMPOSSIBLE_TRAVEL_SPEED` | 900 km/h | Speed threshold for R7 impossible travel |

## Tech Stack

- **Backend** — Python 3, Flask 3, Flask-SQLAlchemy, Flask-Login, Flask-Dance
- **Database** — SQLite (dev) — swap `DATABASE_URL` for Postgres in production
- **Auth** — Werkzeug password hashing, Google OAuth 2.0, OTP via Gmail SMTP
- **Geolocation** — ip-api.com (free, no API key required; returns city, region, country, lat, lon, VPN flag)
- **Frontend** — Bootstrap 5, Chart.js, Font Awesome

## Project Structure

```
├── app.py               # All routes and application logic
├── config.py            # Configuration (reads from .env)
├── models.py            # SQLAlchemy models
├── detection.py         # Rule-based suspicious login engine (R1–R8)
├── email_alert.py       # Gmail SMTP — all security notification emails
├── create_test_data.py  # Seeds demo user and sample login history
├── requirements.txt
├── .env.example         # Environment variable template
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── register.html
│   ├── forgot_password.html
│   ├── verify_reset_otp.html
│   ├── reset_password.html
│   ├── verify_2fa.html
│   ├── dashboard.html
│   ├── login_history.html
│   ├── alerts.html
│   ├── profile.html
│   └── testing.html
└── tests/
    └── test_app.py      # 37 pytest tests
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

# Gmail SMTP (required for 2FA, alerts, and all notification emails)
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

## Running Tests

```bash
python -m pytest tests/ -v
```

37 tests covering registration, login, 2FA, detection rules R1–R6, brute-force alerts, access control, and API endpoints. Each test uses a fresh in-memory SQLite database.

## Security Flows

### Forgot Password
1. Click **Forgot password?** on the login page
2. Enter your registered email address
3. Check your inbox for a 6-digit reset code (valid 10 minutes)
4. Enter the code, then set your new password
5. Account is automatically unlocked if it was locked

### "Was This You?" Alert Response
1. Suspicious login detected → alert email sent with confirm/deny buttons
2. **Yes, this was me** → login marked as confirmed, no action needed
3. **No, secure my account** → account is immediately locked, locked-account email sent
4. Use Forgot Password to reset password and regain access

### Account Lockout
- Triggered after `MAX_FAILED_ATTEMPTS` failed logins within `FAILED_ATTEMPT_WINDOW` minutes
- Account auto-unlocks after `LOCKOUT_DURATION` minutes
- Can be unlocked immediately by completing a password reset

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | Yes | Flask session signing key |
| `MAIL_USERNAME` | Yes | Gmail address used to send all security emails |
| `MAIL_PASSWORD` | Yes | Gmail App Password (16 characters) |
| `GOOGLE_CLIENT_ID` | No | Enables Google OAuth login |
| `GOOGLE_CLIENT_SECRET` | No | Enables Google OAuth login |
| `DATABASE_URL` | No | Defaults to `sqlite:///hacking_detection.db` |
