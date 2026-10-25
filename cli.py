"""Command-line interface for the Attendance Maintenance System demo.

Usage examples (run from the project directory):

    python3 cli.py demo
    python3 cli.py enrol --db attendance.db --actor admin --username alice \\
        --name "Alice Rao" --role student --password secret123 \\
        --sample alice-sample-001
    python3 cli.py mark --db attendance.db --actor teacher1 --role teacher \\
        --username alice --sample alice-sample-001
    python3 cli.py report-user --db attendance.db --role teacher --requester teacher1 \\
        --username alice
    python3 cli.py report-day --db attendance.db --role teacher --day 2026-10-25
    python3 cli.py verify-audit --db attendance.db

The ``--sample`` values are SIMULATED biometric samples (plain strings
used only for the demonstration). No real biometric data is involved.
"""

from __future__ import annotations

import argparse
import os
import sys

from attendance import (
    AttendanceSystem,
    DuplicateAttendance,
    PermissionDenied,
    VerificationFailed,
)

TODAY = "2026-10-25"


def _system(db: str) -> AttendanceSystem:
    return AttendanceSystem(db)


def cmd_demo(args: argparse.Namespace) -> int:
    db = args.db
    if os.path.exists(db):
        os.remove(db)
    sys = _system(db)
    print("== Attendance Maintenance System — demo ==")
    print("NOTE: biometrics here are SIMULATED sample strings, not real data.\n")

    # Bootstrap: first admin, then the rest via the admin role.
    sys.create_user("admin", "System Admin", "admin", "admin-pass")
    sys.create_user_by("admin", "admin", "teacher1", "Ms. Teacher", "teacher", "teacher-pass")
    sys.create_user_by("admin", "admin", "alice", "Alice Rao", "student", "alice-pass")
    sys.create_user_by("admin", "admin", "bob", "Bob Chen", "student", "bob-pass")
    sys.create_user_by("admin", "admin", "erin", "Erin Park", "employee", "erin-pass")
    print("Enrolled users: admin, teacher1, alice, bob, erin")

    for username, sample in [
        ("alice", "alice-sample-001"),
        ("bob", "bob-sample-002"),
        ("erin", "erin-sample-003"),
    ]:
        sys.enrol_biometric("admin", "admin", username, sample)
    print("Biometric templates enrolled (hashes only) for alice, bob, erin.\n")

    # Successful marks.
    for username, sample in [
        ("alice", "alice-sample-001"),
        ("bob", "bob-sample-002"),
    ]:
        sys.mark_attendance("teacher", "teacher1", username, sample, day=TODAY)
        print(f"  present: {username} on {TODAY} (biometric verified)")

    # A failed verification must not mark attendance.
    try:
        sys.mark_attendance("teacher", "teacher1", "erin", "wrong-sample", day=TODAY)
    except VerificationFailed:
        print("  denied:  erin with a mismatched sample (not marked)")

    # A duplicate mark must be refused.
    try:
        sys.mark_attendance("teacher", "teacher1", "alice", "alice-sample-001", day=TODAY)
    except DuplicateAttendance as exc:
        print(f"  refused: duplicate mark for alice — {exc}")

    # Role gating: a student cannot mark attendance.
    try:
        sys.mark_attendance("student", "alice", "bob", "bob-sample-002", day=TODAY)
    except PermissionDenied as exc:
        print(f"  refused: student marking attendance — {exc}")

    print(f"\n-- Report for {TODAY} --")
    for row in sys.report_for_day("teacher", TODAY):
        print(f"  {row['username']} ({row['name']}, {row['role']}) — marked by {row['marked_by']}")

    print("\n-- Summary (days present) --")
    for row in sys.summary("teacher"):
        print(f"  {row['username']}: {row['days_present']}")

    ok, tampered = sys.verify_audit()
    print(f"\nAudit chain verified: {'OK' if ok else 'TAMPERED: ' + str(tampered)}")
    sys.close()
    print(f"\nDemo database written to {db}")
    return 0


def cmd_enrol(args: argparse.Namespace) -> int:
    sys = _system(args.db)
    sys.create_user_by("admin", args.actor, args.username, args.name, args.role, args.password)
    sys.enrol_biometric("admin", args.actor, args.username, args.sample)
    print(f"Enrolled {args.username} ({args.role}) with a simulated biometric template.")
    sys.close()
    return 0


def cmd_mark(args: argparse.Namespace) -> int:
    sys = _system(args.db)
    try:
        sys.mark_attendance(args.role, args.actor, args.username, args.sample, day=args.day)
    except (PermissionDenied, VerificationFailed, DuplicateAttendance) as exc:
        print(f"Refused: {exc}")
        sys.close()
        return 1
    print(f"Marked {args.username} present on {args.day or 'today'} (biometric verified).")
    sys.close()
    return 0


def cmd_report_user(args: argparse.Namespace) -> int:
    sys = _system(args.db)
    try:
        rows = sys.report_for_user(args.role, args.requester, args.username)
    except PermissionDenied as exc:
        print(f"Refused: {exc}")
        sys.close()
        return 1
    for row in rows:
        print(f"{row['day']}  marked by {row['marked_by']} at {row['marked_at']}")
    if not rows:
        print("(no attendance records)")
    sys.close()
    return 0


def cmd_report_day(args: argparse.Namespace) -> int:
    sys = _system(args.db)
    try:
        rows = sys.report_for_day(args.role, args.day)
    except PermissionDenied as exc:
        print(f"Refused: {exc}")
        sys.close()
        return 1
    for row in rows:
        print(f"{row['username']} ({row['name']}, {row['role']})")
    if not rows:
        print("(nobody marked present)")
    sys.close()
    return 0


def cmd_verify_audit(args: argparse.Namespace) -> int:
    sys = _system(args.db)
    ok, tampered = sys.verify_audit()
    print("Audit chain OK" if ok else f"Audit chain TAMPERED at entries: {tampered}")
    sys.close()
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Attendance Maintenance System (demo)")
    parser.add_argument("--db", default="attendance.db", help="SQLite database file")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="Run the end-to-end demo")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("enrol", help="Create a user and enrol a simulated template")
    p.add_argument("--actor", required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--role", required=True, choices=["admin", "teacher", "student", "employee"])
    p.add_argument("--password", required=True)
    p.add_argument("--sample", required=True, help="SIMULATED biometric sample string")
    p.set_defaults(func=cmd_enrol)

    p = sub.add_parser("mark", help="Mark attendance after biometric verification")
    p.add_argument("--actor", required=True)
    p.add_argument("--role", required=True)
    p.add_argument("--username", required=True)
    p.add_argument("--sample", required=True, help="SIMULATED biometric sample string")
    p.add_argument("--day", default=None)
    p.set_defaults(func=cmd_mark)

    p = sub.add_parser("report-user", help="Attendance for one user")
    p.add_argument("--role", required=True)
    p.add_argument("--requester", required=True)
    p.add_argument("--username", required=True)
    p.set_defaults(func=cmd_report_user)

    p = sub.add_parser("report-day", help="All users present on a day")
    p.add_argument("--role", required=True)
    p.add_argument("--day", required=True)
    p.set_defaults(func=cmd_report_day)

    p = sub.add_parser("verify-audit", help="Verify the hash-chained audit log")
    p.set_defaults(func=cmd_verify_audit)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
