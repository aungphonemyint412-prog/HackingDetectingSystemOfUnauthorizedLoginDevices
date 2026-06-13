"""
Populate the database with demo data so the dashboard looks meaningful
on first presentation.

Usage:  python create_test_data.py
"""
from datetime import datetime, timedelta
import random

from app import app
from models import db, User, LoginHistory, Alert, KnownIP, KnownDevice, device_fingerprint

DEMO_USER = {'username': 'demouser', 'email': 'demo@example.com', 'password': 'Password123'}

IPS      = ['192.168.1.10', '192.168.1.10', '10.0.0.5', '185.220.101.99', '203.0.113.55']
DEVICES  = ['PC', 'PC', 'PC', 'Mobile', 'PC']
BROWSERS = ['Chrome 124.0', 'Chrome 124.0', 'Firefox 125.0', 'Safari 17.0', 'Edge 124.0']
OS_LIST  = ['Windows 10', 'Windows 10', 'Windows 10', 'iOS 17', 'Windows 10']
UA_LIST  = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/125.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/124.0',
]


def create_demo():
    with app.app_context():
        db.create_all()

        user = User.query.filter_by(username=DEMO_USER['username']).first()
        if not user:
            user = User(
                username=DEMO_USER['username'],
                email=DEMO_USER['email'],
                email_verified=True,
            )
            user.set_password(DEMO_USER['password'])
            db.session.add(user)
            db.session.commit()
            print(f"Created demo user: {DEMO_USER['username']} / {DEMO_USER['password']}")
        else:
            print(f"Demo user already exists: {DEMO_USER['username']}")

        # 30 days of login history
        now     = datetime.utcnow()
        records = []
        for day_offset in range(30, -1, -1):
            base_time = now - timedelta(days=day_offset)
            for _ in range(random.randint(1, 3)):
                idx    = random.randint(0, len(IPS) - 1)
                hour   = random.choice([8, 9, 10, 11, 13, 14, 15, 16, 17, 2])
                minute = random.randint(0, 59)
                t      = base_time.replace(hour=hour, minute=minute, second=0)

                status = random.choices(['success', 'failed'], weights=[85, 15])[0]
                susp   = (idx == 3 or hour == 2) and status == 'success'

                rec = LoginHistory(
                    user_id            = user.id,
                    ip_address         = IPS[idx],
                    device_type        = DEVICES[idx],
                    browser            = BROWSERS[idx],
                    os                 = OS_LIST[idx],
                    user_agent         = UA_LIST[idx],
                    login_time         = t,
                    login_status       = status,
                    is_suspicious      = susp,
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

        # Sample alerts from suspicious logins
        suspicious = [r for r in records if r.is_suspicious]
        for r in suspicious[:5]:
            db.session.add(Alert(
                user_id          = user.id,
                login_history_id = r.id,
                alert_type       = 'suspicious_login',
                message          = r.suspicious_reasons,
                created_at       = r.login_time,
                is_read          = False,
                email_sent       = False,
            ))

        # Seed known IPs and devices
        for ip in set(IPS):
            existing = KnownIP.query.filter_by(user_id=user.id, ip_address=ip).first()
            if not existing:
                db.session.add(KnownIP(
                    user_id     = user.id,
                    ip_address  = ip,
                    login_count = random.randint(1, 20),
                ))

        for ua in set(UA_LIST):
            fp = device_fingerprint(ua)
            existing = KnownDevice.query.filter_by(user_id=user.id, device_fingerprint=fp).first()
            if not existing:
                idx = UA_LIST.index(ua)
                db.session.add(KnownDevice(
                    user_id            = user.id,
                    device_fingerprint = fp,
                    device_type        = DEVICES[idx],
                    browser            = BROWSERS[idx],
                    os                 = OS_LIST[idx],
                ))

        db.session.commit()
        print(f'Inserted {len(records)} login records and {len(suspicious[:5])} alerts.')
        print(f'Seeded {KnownIP.query.filter_by(user_id=user.id).count()} known IPs and '
              f'{KnownDevice.query.filter_by(user_id=user.id).count()} known devices.')
        print('\nDemo credentials:')
        print(f'  Username : {DEMO_USER["username"]}')
        print(f'  Password : {DEMO_USER["password"]}')


if __name__ == '__main__':
    create_demo()
