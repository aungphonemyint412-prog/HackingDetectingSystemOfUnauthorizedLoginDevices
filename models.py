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
    password_hash  = db.Column(db.String(256), nullable=False)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    two_fa_enabled = db.Column(db.Boolean, default=False)

    login_history = db.relationship('LoginHistory', backref='user', lazy='dynamic')
    alerts        = db.relationship('Alert',        backref='user', lazy='dynamic')
    otp_codes     = db.relationship('OTPCode',      backref='user', lazy='dynamic')

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
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
    login_time         = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    login_status       = db.Column(db.String(20))    # success | failed | failed_2fa
    is_suspicious      = db.Column(db.Boolean, default=False)
    suspicious_reasons = db.Column(db.Text)
    two_fa_required    = db.Column(db.Boolean, default=False)
    two_fa_verified    = db.Column(db.Boolean, nullable=True)  # None = not required

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
    code_hash        = db.Column(db.String(256), nullable=False)
    created_at       = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at       = db.Column(db.DateTime, nullable=False)
    is_used          = db.Column(db.Boolean, default=False)
    ip_address       = db.Column(db.String(45))
    login_history_id = db.Column(db.Integer, db.ForeignKey('login_history.id'), nullable=True)

    @property
    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def __repr__(self) -> str:
        return f'<OTPCode user={self.user_id} used={self.is_used}>'
