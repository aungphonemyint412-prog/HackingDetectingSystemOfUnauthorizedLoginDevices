"""
Rule-based suspicious login detection engine.

Rules evaluated on every successful login:
  R1 – New IP address not seen in recent history
  R2 – New device type (PC / Mobile / Tablet)
  R3 – New browser family
  R4 – New operating-system family
  R5 – Login during unusual hours (00:00–04:59)
  R6 – Rapid multiple successful logins in short window
  R7 – Impossible travel (speed between consecutive logins > threshold km/h)
  R8 – VPN / proxy / TOR exit node detected
"""
import math
from datetime import datetime, timedelta
from flask import current_app
from models import LoginHistory


class SuspiciousLoginDetector:

    def __init__(self, user, current_login: LoginHistory, session):
        self.user    = user
        self.current = current_login
        self.session = session
        self.reasons: list[str] = []

    # ── Public API ─────────────────────────────────────────────────────────
    def analyze(self) -> tuple[bool, list[str]]:
        """Return (is_suspicious, list_of_reasons)."""
        prev = self._previous_logins()

        if prev:                      # skip most checks on the very first login
            self._r1_new_ip(prev)
            self._r2_new_device(prev)
            self._r3_new_browser(prev)
            self._r4_new_os(prev)
            self._r6_rapid_logins()
            self._r7_impossible_travel(prev)

        self._r5_unusual_hour()       # always check time
        self._r8_vpn_proxy()          # always check VPN flag

        return bool(self.reasons), self.reasons

    # ── Helpers ────────────────────────────────────────────────────────────
    def _previous_logins(self) -> list:
        limit = current_app.config.get('HISTORY_LOOKUP', 50)
        return (
            LoginHistory.query
            .filter_by(user_id=self.user.id, login_status='success')
            .filter(LoginHistory.id != self.current.id)
            .order_by(LoginHistory.login_time.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def _family(value: str | None) -> str:
        """Return the first word (family) of a 'Family Version' string."""
        if not value:
            return 'Unknown'
        return value.split()[0]

    # ── Detection Rules ────────────────────────────────────────────────────
    def _r1_new_ip(self, prev):
        known = {r.ip_address for r in prev}
        if self.current.ip_address not in known:
            self.reasons.append(
                f'New IP address: {self.current.ip_address}'
            )

    def _r2_new_device(self, prev):
        known = {r.device_type for r in prev if r.device_type}
        if self.current.device_type and self.current.device_type not in known:
            self.reasons.append(
                f'New device type: {self.current.device_type}'
            )

    def _r3_new_browser(self, prev):
        known = {self._family(r.browser) for r in prev}
        cur   = self._family(self.current.browser)
        if cur not in known:
            self.reasons.append(
                f'New browser: {self.current.browser}'
            )

    def _r4_new_os(self, prev):
        known = {self._family(r.os) for r in prev}
        cur   = self._family(self.current.os)
        if cur and cur not in known:
            self.reasons.append(
                f'New operating system: {self.current.os}'
            )

    def _r5_unusual_hour(self):
        h_start = current_app.config.get('UNUSUAL_HOUR_START', 0)
        h_end   = current_app.config.get('UNUSUAL_HOUR_END', 5)
        hour    = self.current.login_time.hour
        if h_start <= hour < h_end:
            self.reasons.append(
                f'Login during unusual hours: '
                f'{self.current.login_time.strftime("%H:%M")} UTC '
                f'(between {h_start:02d}:00 and {h_end:02d}:00)'
            )

    def _r6_rapid_logins(self):
        window    = current_app.config.get('RAPID_LOGIN_WINDOW', 10)
        threshold = current_app.config.get('RAPID_LOGIN_COUNT', 3)
        since     = datetime.utcnow() - timedelta(minutes=window)
        count     = (
            LoginHistory.query
            .filter_by(user_id=self.user.id, login_status='success')
            .filter(LoginHistory.login_time >= since)
            .filter(LoginHistory.id != self.current.id)
            .count()
        )
        if count >= threshold:
            self.reasons.append(
                f'Multiple logins in short period: '
                f'{count} successful logins in the last {window} minutes'
            )

    def _r7_impossible_travel(self, prev):
        """Flag if consecutive logins are geographically impossible given elapsed time."""
        max_speed = current_app.config.get('IMPOSSIBLE_TRAVEL_SPEED', 900)
        cur = self.current
        if cur.lat is None or cur.lon is None:
            return
        for p in prev:
            if p.lat is None or p.lon is None:
                continue
            hours = (cur.login_time - p.login_time).total_seconds() / 3600.0
            if hours <= 0.25:          # less than 15 min — skip, same session noise
                continue
            dist_km = self._haversine(p.lat, p.lon, cur.lat, cur.lon)
            speed   = dist_km / hours
            if speed > max_speed:
                self.reasons.append(
                    f'Impossible travel: {dist_km:.0f} km in {hours:.1f} h '
                    f'({speed:.0f} km/h) from previous login location'
                )
            break  # only compare with the most recent geo-located login

    @staticmethod
    def _haversine(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        R = 6371.0
        φ1, φ2 = math.radians(lat1), math.radians(lat2)
        dφ = math.radians(lat2 - lat1)
        dλ = math.radians(lon2 - lon1)
        a  = math.sin(dφ / 2) ** 2 + math.cos(φ1) * math.cos(φ2) * math.sin(dλ / 2) ** 2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    def _r8_vpn_proxy(self):
        if getattr(self.current, 'is_vpn', False):
            self.reasons.append(
                'VPN / proxy / TOR exit node detected: login may be masking true location'
            )
