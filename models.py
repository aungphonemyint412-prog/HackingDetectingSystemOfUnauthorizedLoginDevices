import hashlib
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(80),  unique=True, nullable=False)
    email          = db.Column(db.String(120), unique=True, nullable=False)
    password_hash  = db.Column(db.String(256))
    google_id      = db.Column(db.String(100), unique=True)
    profile_pic    = db.Column(db.Text)
    email_verified = db.Column(db.Boolean, default=False)
    two_fa_enabled = db.Column(db.Boolean, default=False)
    is_active      = db.Column(db.Boolean, default=True)
    is_locked      = db.Column(db.Boolean, default=False)
    locked_until   = db.Column(db.DateTime, nullable=True)
    lock_reason    = db.Column(db.String(300), nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    last_login     = db.Column(db.DateTime)

    login_history    = db.relationship('LoginHistory',  backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')
    alerts           = db.relationship('Alert',          backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')
    otp_codes        = db.relationship('OTPCode',        backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')
    known_ips        = db.relationship('KnownIP',        backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')
    known_devices    = db.relationship('KnownDevice',    backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')
    failed_attempts  = db.relationship('FailedAttempt',  backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')
    security_tokens  = db.relationship('SecurityToken',  backref='user', lazy='dynamic',
                                        cascade='all, delete-orphan')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f'<User {self.username}>'


class LoginHistory(db.Model):
    __tablename__ = 'login_history'

    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address         = db.Column(db.String(45))
    device_type        = db.Column(db.String(50))
    browser            = db.Column(db.String(120))
    os                 = db.Column(db.String(120))
    user_agent         = db.Column(db.String(500))
    location           = db.Column(db.String(200))
    lat                = db.Column(db.Float, nullable=True)
    lon                = db.Column(db.Float, nullable=True)
    is_vpn             = db.Column(db.Boolean, default=False)
    risk_score         = db.Column(db.Integer, default=0)
    user_confirmed     = db.Column(db.Boolean, nullable=True)
    login_time         = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    login_status       = db.Column(db.String(20))
    is_suspicious      = db.Column(db.Boolean, default=False)
    suspicious_reasons = db.Column(db.Text)
    two_fa_required    = db.Column(db.Boolean, default=False)
    two_fa_verified    = db.Column(db.Boolean, nullable=True)

    def __repr__(self) -> str:
        return f'<LoginHistory user={self.user_id} status={self.login_status}>'


class Alert(db.Model):
    __tablename__ = 'alerts'

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    login_history_id = db.Column(db.Integer, db.ForeignKey('login_history.id'), nullable=True)
    alert_type       = db.Column(db.String(50))
    message          = db.Column(db.Text)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    is_read          = db.Column(db.Boolean, default=False)
    email_sent       = db.Column(db.Boolean, default=False)

    def __repr__(self) -> str:
        return f'<Alert {self.alert_type} user={self.user_id}>'


class OTPCode(db.Model):
    __tablename__ = 'otp_codes'

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    code             = db.Column(db.String(6), nullable=False)   # plain 6-digit code
    is_used          = db.Column(db.Boolean, default=False)
    expires_at       = db.Column(db.DateTime, nullable=False)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address       = db.Column(db.String(45))
    login_history_id = db.Column(db.Integer, db.ForeignKey('login_history.id'), nullable=True)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def __repr__(self) -> str:
        return f'<OTPCode user={self.user_id} used={self.is_used}>'


class KnownIP(db.Model):
    __tablename__ = 'known_ips'

    id          = db.Column(db.Integer, primary_key=True)
    user_id     = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address  = db.Column(db.String(45), nullable=False)
    first_seen  = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen   = db.Column(db.DateTime, default=datetime.utcnow)
    login_count = db.Column(db.Integer, default=1)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'ip_address', name='uq_user_ip'),
    )

    def __repr__(self) -> str:
        return f'<KnownIP user={self.user_id} ip={self.ip_address}>'


class KnownDevice(db.Model):
    __tablename__ = 'known_devices'

    id                 = db.Column(db.Integer, primary_key=True)
    user_id            = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    device_fingerprint = db.Column(db.String(64), nullable=False)
    device_type        = db.Column(db.String(20))
    browser            = db.Column(db.String(120))
    os                 = db.Column(db.String(120))
    first_seen         = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen          = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.UniqueConstraint('user_id', 'device_fingerprint', name='uq_user_device'),
    )

    def __repr__(self) -> str:
        return f'<KnownDevice user={self.user_id} fp={self.device_fingerprint[:8]}>'


class FailedAttempt(db.Model):
    __tablename__ = 'failed_attempts'

    id           = db.Column(db.Integer, primary_key=True)
    user_id      = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    ip_address   = db.Column(db.String(45), nullable=False)
    attempt_time = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def __repr__(self) -> str:
        return f'<FailedAttempt user={self.user_id} ip={self.ip_address}>'


class SecurityToken(db.Model):
    __tablename__ = 'security_tokens'

    id               = db.Column(db.Integer, primary_key=True)
    user_id          = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    token            = db.Column(db.String(64), unique=True, nullable=False, index=True)
    token_type       = db.Column(db.String(50))  # confirm_login | deny_login
    login_history_id = db.Column(db.Integer, db.ForeignKey('login_history.id'), nullable=True)
    is_used          = db.Column(db.Boolean, default=False)
    expires_at       = db.Column(db.DateTime, nullable=False)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def __repr__(self) -> str:
        return f'<SecurityToken user={self.user_id} type={self.token_type}>'


class EmailQueue(db.Model):
    """Log of every security email attempted — enables rate limiting and audit trail."""
    __tablename__ = 'email_queue'

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    recipient  = db.Column(db.String(120), nullable=False)
    email_type = db.Column(db.String(50))   # alert | login_notification | failed_login | etc.
    subject    = db.Column(db.String(300))
    status     = db.Column(db.String(20), default='sent')  # sent | failed | skipped
    attempts   = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    sent_at    = db.Column(db.DateTime, nullable=True)
    error_msg  = db.Column(db.String(500), nullable=True)

    def __repr__(self) -> str:
        return f'<EmailQueue {self.email_type} to={self.recipient} status={self.status}>'


class SecurityIncident(db.Model):
    """Tracks security incidents created from suspicious events."""
    __tablename__ = 'security_incidents'

    id            = db.Column(db.Integer, primary_key=True)
    incident_ref  = db.Column(db.String(25), unique=True, index=True)   # INC-YYYYMMDD-NNNN
    user_id       = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    incident_type = db.Column(db.String(100))   # suspicious_login | brute_force | credential_stuffing | etc.
    severity      = db.Column(db.String(20))    # informational | low | medium | high | critical
    status        = db.Column(db.String(20), default='open')   # open | investigating | resolved
    details       = db.Column(db.Text)
    source_ip     = db.Column(db.String(45))
    risk_score    = db.Column(db.Integer, default=0)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at    = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at   = db.Column(db.DateTime, nullable=True)

    def __repr__(self) -> str:
        return f'<SecurityIncident {self.incident_ref} severity={self.severity} status={self.status}>'


def device_fingerprint(ua_string: str) -> str:
    return hashlib.md5(ua_string.encode()).hexdigest()[:32]
