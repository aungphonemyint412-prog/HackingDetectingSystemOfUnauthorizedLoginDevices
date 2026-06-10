"""
Populate the database with demo data so the dashboard looks meaningful
on first presentation.

Usage:  python create_test_data.py
"""
from datetime import datetime, timedelta
import random

from app import app
from models import db, User, LoginHistory, Alert

DEMO_USER = {'username': 'demouser', 'email': 'demo@example.com', 'password': 'Password123'}

IPS        = ['192.168.1.10', '192.168.1.10', '10.0.0.5', '185.220.101.99', '203.0.113.55']
DEVICES    = ['PC', 'PC', 'PC', 'Mobile', 'PC']
BROWSERS   = ['Chrome 124.0', 'Chrome 124.0', 'Firefox 125.0', 'Safari 17.0', 'Edge 124.0']
OS_LIST    = ['Windows 10', 'Windows 10', 'Windows 10', 'iOS 17', 'Windows 10']


def create_demo():
    with app.app_context():
        db.create_all()

        # Create demo user if not present
        user = User.query.filter_by(username=DEMO_USER['username']).first()
        if not user:
            user = User(username=DEMO_USER['username'], email=DEMO_USER['email'])
            user.set_password(DEMO_USER['password'])
            db.session.add(user)
            db.session.commit()
            print(f"Created demo user: {DEMO_USER['username']} / {DEMO_USER['password']}")
        else:
            print(f"Demo user already exists: {DEMO_USER['username']}")

        # Create 30 days of login history
        now = datetime.utcnow()
        records = []
        for day_offset in range(30, -1, -1):
            base_time = now - timedelta(days=day_offset)
            # 1-3 logins per day
            for _ in range(random.randint(1, 3)):
                idx    = random.randint(0, len(IPS) - 1)
                hour   = random.choice([8, 9, 10, 11, 13, 14, 15, 16, 17, 2])
                minute = random.randint(0, 59)
                t      = base_time.replace(hour=hour, minute=minute, second=0)

                status = random.choices(['success', 'failed'], weights=[85, 15])[0]
                susp   = (idx == 3 or hour == 2)  # foreign IP or 2 AM

                rec = LoginHistory(
                    user_id            = user.id,
                    ip_address         = IPS[idx],
                    device_type        = DEVICES[idx],
                    browser            = BROWSERS[idx],
                    os                 = OS_LIST[idx],
                    user_agent         = f'Mozilla/5.0 (demo-seed)',
                    login_time         = t,
                    login_status       = status,
                    is_suspicious      = susp and status == 'success',
                    suspicious_reasons = (
                        'New IP address; Login during unusual hours'
                        if susp and hour == 2 else
                        'New IP address: 185.220.101.99'
                        if susp else ''
                    ),
                )
                records.append(rec)

        db.session.add_all(records)
        db.session.flush()

        # Create sample alerts
        suspicious = [r for r in records if r.is_suspicious]
        for r in suspicious[:5]:
            alert = Alert(
                user_id          = user.id,
                login_history_id = r.id,
                alert_type       = 'suspicious_login',
                message          = r.suspicious_reasons,
                created_at       = r.login_time,
                is_read          = False,
                email_sent       = False,
            )
            db.session.add(alert)

        db.session.commit()
        print(f'Inserted {len(records)} login records and {len(suspicious[:5])} alerts.')
        print('\nDemo credentials:')
        print(f'  Username : {DEMO_USER["username"]}')
        print(f'  Password : {DEMO_USER["password"]}')


if __name__ == '__main__':
    create_demo()
