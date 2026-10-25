"""Attendance Maintenance System with Intelligent Security (demonstration).

Pure Python, standard library only.

IMPORTANT — SIMULATED BIOMETRICS:
    This system does NOT use real biometric hardware, real fingerprints,
    or real biometric data. A "biometric sample" here is an arbitrary
    string supplied by the caller (for example ``"alice-sample-001"``).
    Enrolment stores only a SHA-256 hash of that sample string, never
    the sample itself, and verification hashes the presented sample and
    compares hashes. There is no fuzzy biometric matching, liveness
    detection, or spoof resistance. This is a demonstration of the
    surrounding system design (enrolment, access control, attendance
    rules, tamper-evident audit log) from the IEEE-published concept,
    not a production biometric or security-certified system.

Design:
    * Users have a role: ``admin``, ``teacher``, ``student`` or
      ``employee``. Passwords are stored salted with PBKDF2-HMAC-SHA256.
    * Enrolment (admin only) stores a hashed biometric template.
    * Attendance can be marked only after successful biometric
      verification, once per user per day (UNIQUE constraint).
    * Every security-relevant action appends a hash-chained audit entry:
      each entry's hash covers the previous entry's hash, so editing or
      deleting an entry in the middle of the chain is detectable by
      :meth:`AttendanceSystem.verify_audit`.

Storage: a single SQLite database file (default ``attendance.db``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from datetime import date, datetime, timezone

ROLES = ("admin", "teacher", "student", "employee")

# Roles allowed to perform each gated action.
_CAN_ENROL = ("admin",)
_CAN_MARK = ("admin", "teacher")
_CAN_REPORT_ALL = ("admin", "teacher")


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, salt: bytes) -> str:
    """PBKDF2-HMAC-SHA256 password hash (hex)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000).hex()


def _hash_biometric_sample(sample: str) -> str:
    """Deterministic hash of a SIMULATED biometric sample string.

    The sample is normalised (stripped, lower-cased) before hashing so
    that verification of the same sample string reproduces the template.
    Only the hash is ever stored.
    """
    normalised = sample.strip().lower().encode("utf-8")
    return hashlib.sha256(normalised).hexdigest()


def _audit_hash(prev_hash: str, timestamp: str, action: str, actor: str, details: str) -> str:
    payload = "|".join([prev_hash, timestamp, action, actor, details])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AttendanceError(Exception):
    """Base error for attendance-system rule violations."""


class PermissionDenied(AttendanceError):
    """Raised when a caller's role is not allowed to perform an action."""


class VerificationFailed(AttendanceError):
    """Raised when biometric verification (or login) fails."""


class DuplicateAttendance(AttendanceError):
    """Raised when attendance is already marked for a user on a date."""


class AttendanceSystem:
    """SQLite-backed attendance system with role gating and audit chain."""

    def __init__(self, db_path: str = "attendance.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    # -- schema ---------------------------------------------------------
    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                role TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                biometric_template TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                day TEXT NOT NULL,
                marked_at TEXT NOT NULL,
                marked_by TEXT NOT NULL,
                UNIQUE(user_id, day)
            );
            CREATE TABLE IF NOT EXISTS audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                details TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    # -- audit ----------------------------------------------------------
    def _audit(self, action: str, actor: str, details: str = "") -> None:
        row = self.conn.execute(
            "SELECT entry_hash FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()
        prev_hash = row["entry_hash"] if row else "GENESIS"
        timestamp = _utcnow_iso()
        entry_hash = _audit_hash(prev_hash, timestamp, action, actor, details)
        self.conn.execute(
            "INSERT INTO audit (timestamp, action, actor, details, prev_hash, entry_hash)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (timestamp, action, actor, details, prev_hash, entry_hash),
        )

    def verify_audit(self) -> tuple[bool, list[int]]:
        """Recompute the hash chain. Returns (ok, [tampered entry ids])."""
        rows = self.conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
        tampered: list[int] = []
        prev_hash = "GENESIS"
        for row in rows:
            expected = _audit_hash(
                prev_hash, row["timestamp"], row["action"], row["actor"], row["details"]
            )
            if expected != row["entry_hash"] or row["prev_hash"] != prev_hash:
                tampered.append(row["id"])
            prev_hash = row["entry_hash"]
        return (not tampered, tampered)

    # -- users ----------------------------------------------------------
    def create_user(self, username: str, name: str, role: str, password: str) -> int:
        """Create a user account (no biometric template yet).

        The very first user may be created without an existing admin
        (bootstrap); afterwards creation is admin-only via enrol_user /
        create_user_by. Use :meth:`create_user_by` for gated creation.
        """
        if role not in ROLES:
            raise AttendanceError(f"unknown role: {role!r} (expected one of {ROLES})")
        salt = os.urandom(16)
        pw_hash = _hash_password(password, salt)
        try:
            cur = self.conn.execute(
                "INSERT INTO users (username, name, role, password_hash, password_salt,"
                " biometric_template, created_at) VALUES (?, ?, ?, ?, ?, NULL, ?)",
                (username, name, role, pw_hash, salt.hex(), _utcnow_iso()),
            )
        except sqlite3.IntegrityError as exc:
            raise AttendanceError(f"username already exists: {username}") from exc
        user_id = cur.lastrowid
        self._audit("user_created", username, json.dumps({"role": role}))
        self.conn.commit()
        return user_id

    def create_user_by(self, actor_role: str, actor: str, username: str,
                       name: str, role: str, password: str) -> int:
        if actor_role not in _CAN_ENROL:
            raise PermissionDenied("only admin can create users")
        user_id = self.create_user(username, name, role, password)
        # create_user already audited as user_created; add the actor context.
        self._audit("user_created_by", actor, json.dumps({"username": username}))
        self.conn.commit()
        return user_id

    def get_user(self, username: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    def verify_login(self, username: str, password: str) -> sqlite3.Row:
        user = self.get_user(username)
        if user is None:
            raise VerificationFailed("unknown user or wrong password")
        salt = bytes.fromhex(user["password_salt"])
        if not hmac.compare_digest(_hash_password(password, salt), user["password_hash"]):
            raise VerificationFailed("unknown user or wrong password")
        self._audit("login", username, "")
        self.conn.commit()
        return user

    # -- biometrics (SIMULATED) ------------------------------------------
    def enrol_biometric(self, actor_role: str, actor: str, username: str, sample: str) -> None:
        """Admin-only: store the hash of a SIMULATED biometric sample."""
        if actor_role not in _CAN_ENROL:
            raise PermissionDenied("only admin can enrol biometric templates")
        user = self.get_user(username)
        if user is None:
            raise AttendanceError(f"unknown user: {username}")
        template = _hash_biometric_sample(sample)
        self.conn.execute(
            "UPDATE users SET biometric_template = ? WHERE username = ?",
            (template, username),
        )
        self._audit("biometric_enrolled", actor, json.dumps({"username": username}))
        self.conn.commit()

    def verify_biometric(self, username: str, sample: str) -> bool:
        """Return True iff the presented sample hashes to the stored template."""
        user = self.get_user(username)
        if user is None or user["biometric_template"] is None:
            return False
        return hmac.compare_digest(
            _hash_biometric_sample(sample), user["biometric_template"]
        )

    # -- attendance -------------------------------------------------------
    def mark_attendance(self, actor_role: str, actor: str, username: str,
                        sample: str, day: str | None = None) -> int:
        """Mark attendance for ``username`` on ``day`` (default: today).

        Requires a teacher/admin caller AND successful biometric
        verification of the subject. One record per user per day.
        """
        if actor_role not in _CAN_MARK:
            raise PermissionDenied("only teacher or admin can mark attendance")
        user = self.get_user(username)
        if user is None:
            raise AttendanceError(f"unknown user: {username}")
        if not self.verify_biometric(username, sample):
            self._audit("attendance_denied_biometric", actor,
                       json.dumps({"username": username}))
            self.conn.commit()
            raise VerificationFailed("biometric verification failed")
        day = day or date.today().isoformat()
        try:
            cur = self.conn.execute(
                "INSERT INTO attendance (user_id, day, marked_at, marked_by)"
                " VALUES (?, ?, ?, ?)",
                (user["id"], day, _utcnow_iso(), actor),
            )
        except sqlite3.IntegrityError as exc:
            raise DuplicateAttendance(
                f"attendance already marked for {username} on {day}"
            ) from exc
        self._audit("attendance_marked", actor,
                   json.dumps({"username": username, "day": day}))
        self.conn.commit()
        return cur.lastrowid

    # -- reports ----------------------------------------------------------
    def report_for_user(self, requester_role: str, requester: str, username: str) -> list[dict]:
        """Attendance days for one user.

        Teachers/admins may view anyone; students/employees may view
        only their own record.
        """
        if requester_role not in _CAN_REPORT_ALL and requester != username:
            raise PermissionDenied("cannot view another user's attendance")
        user = self.get_user(username)
        if user is None:
            raise AttendanceError(f"unknown user: {username}")
        rows = self.conn.execute(
            "SELECT day, marked_at, marked_by FROM attendance"
            " WHERE user_id = ? ORDER BY day",
            (user["id"],),
        ).fetchall()
        return [dict(r) for r in rows]

    def report_for_day(self, requester_role: str, day: str) -> list[dict]:
        """All users marked present on ``day`` (teacher/admin only)."""
        if requester_role not in _CAN_REPORT_ALL:
            raise PermissionDenied("only teacher or admin can view day reports")
        rows = self.conn.execute(
            "SELECT u.username, u.name, u.role, a.marked_at, a.marked_by"
            " FROM attendance a JOIN users u ON u.id = a.user_id"
            " WHERE a.day = ? ORDER BY u.username",
            (day,),
        ).fetchall()
        return [dict(r) for r in rows]

    def summary(self, requester_role: str) -> list[dict]:
        """Total days present per user (teacher/admin only)."""
        if requester_role not in _CAN_REPORT_ALL:
            raise PermissionDenied("only teacher or admin can view summaries")
        rows = self.conn.execute(
            "SELECT u.username, u.name, u.role, COUNT(a.id) AS days_present"
            " FROM users u LEFT JOIN attendance a ON a.user_id = u.id"
            " GROUP BY u.id ORDER BY u.username"
        ).fetchall()
        return [dict(r) for r in rows]
