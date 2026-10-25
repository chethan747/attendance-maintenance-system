"""Unit tests for the Attendance Maintenance System.

Run from the project directory:

    python3 -m unittest discover -s tests -v

All biometric samples below are SIMULATED strings, not real data.
"""

import os
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attendance import (  # noqa: E402
    AttendanceSystem,
    DuplicateAttendance,
    PermissionDenied,
    VerificationFailed,
)


class AttendanceTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = os.path.join(self.tmp.name, "test.db")
        self.sys = AttendanceSystem(self.db)
        self.sys.create_user("admin", "Admin", "admin", "admin-pass")
        self.sys.create_user_by("admin", "admin", "teacher1", "Teacher", "teacher", "t-pass")
        self.sys.create_user_by("admin", "admin", "alice", "Alice", "student", "a-pass")
        self.sys.enrol_biometric("admin", "admin", "alice", "alice-sample-001")

    def tearDown(self):
        self.sys.close()
        self.tmp.cleanup()

    def test_enrol_and_verify_match(self):
        self.assertTrue(self.sys.verify_biometric("alice", "alice-sample-001"))

    def test_verify_mismatch(self):
        self.assertFalse(self.sys.verify_biometric("alice", "someone-else-sample"))
        self.assertFalse(self.sys.verify_biometric("alice", "ALICE-SAMPLE-002"))

    def test_verify_unknown_or_unenrolled_user(self):
        self.assertFalse(self.sys.verify_biometric("nobody", "x"))
        self.sys.create_user_by("admin", "admin", "bob", "Bob", "student", "b-pass")
        self.assertFalse(self.sys.verify_biometric("bob", "bob-sample"))

    def test_biometric_template_stored_as_hash_only(self):
        row = self.sys.get_user("alice")
        self.assertIsNotNone(row["biometric_template"])
        self.assertNotIn("alice-sample-001", row["biometric_template"])
        self.assertEqual(len(row["biometric_template"]), 64)  # SHA-256 hex

    def test_mark_attendance_after_verification(self):
        self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-25")
        rows = self.sys.report_for_user("teacher", "teacher1", "alice")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["day"], "2026-10-25")

    def test_mark_attendance_fails_on_biometric_mismatch(self):
        with self.assertRaises(VerificationFailed):
            self.sys.mark_attendance("teacher", "teacher1", "alice", "wrong-sample", day="2026-10-25")
        self.assertEqual(self.sys.report_for_user("teacher", "teacher1", "alice"), [])

    def test_duplicate_attendance_prevented(self):
        self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-25")
        with self.assertRaises(DuplicateAttendance):
            self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-25")
        # A different day is still allowed.
        self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-26")
        self.assertEqual(len(self.sys.report_for_user("teacher", "teacher1", "alice")), 2)

    def test_role_gating_enrol(self):
        with self.assertRaises(PermissionDenied):
            self.sys.enrol_biometric("teacher", "teacher1", "alice", "new-sample")

    def test_role_gating_mark(self):
        with self.assertRaises(PermissionDenied):
            self.sys.mark_attendance("student", "alice", "alice", "alice-sample-001", day="2026-10-25")

    def test_role_gating_reports(self):
        # Students may view their own record but not another user's.
        self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-25")
        self.assertEqual(len(self.sys.report_for_user("student", "alice", "alice")), 1)
        with self.assertRaises(PermissionDenied):
            self.sys.report_for_user("student", "alice", "teacher1")
        with self.assertRaises(PermissionDenied):
            self.sys.report_for_day("student", "2026-10-25")

    def test_login_password(self):
        user = self.sys.verify_login("alice", "a-pass")
        self.assertEqual(user["username"], "alice")
        with self.assertRaises(VerificationFailed):
            self.sys.verify_login("alice", "wrong-pass")

    def test_audit_chain_verifies_when_untampered(self):
        self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-25")
        ok, tampered = self.sys.verify_audit()
        self.assertTrue(ok)
        self.assertEqual(tampered, [])

    def test_audit_chain_detects_tampering(self):
        self.sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day="2026-10-25")
        # Tamper with an early audit entry directly in the database.
        conn = sqlite3.connect(self.db)
        conn.execute("UPDATE audit SET details = 'forged' WHERE id = 1")
        conn.commit()
        conn.close()
        ok, tampered = self.sys.verify_audit()
        self.assertFalse(ok)
        self.assertIn(1, tampered)


if __name__ == "__main__":
    unittest.main()
