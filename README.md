# Attendance Maintenance System with Intelligent Security

A system combining biometric authentication with secure access control for reliable, tamper-resistant attendance maintenance — implemented here in pure Python (standard library only, no external dependencies).

**IEEE publication:** this project implements the concept from Chethan Thubharahalli Ramesh's IEEE-published work, *Attendance Maintenance System with Intelligent Security* — [IEEE Xplore](https://ieeexplore.ieee.org/document/10592721). The paper itself is not reproduced here; see that link for the publication.

## What it does

- **User enrolment with simulated biometric templates.** Enrolling a user stores only a SHA-256 hash of a sample string — clearly labelled SIMULATED throughout the code and CLI. No real biometric hardware or real fingerprint data is involved.
- **Secure access control.** Roles are `admin`, `teacher`, `student`, and `employee`. Passwords are stored salted with PBKDF2-HMAC-SHA256. Only admins enrol users and biometric templates; only teachers/admins mark attendance; students/employees can view only their own records.
- **Attendance, only after verification.** Attendance is marked only after successful biometric verification, once per user per day — a second mark for the same user on the same day is refused.
- **Tamper-resistant audit log.** Every security-relevant action appends a hash-chained audit entry: each entry's hash covers the previous entry's hash, so editing an entry is detectable with `verify-audit`.
- **Reports.** Attendance per user, per day, and a days-present summary.

## How to run

Requires Python 3.10+; no packages to install.

```bash
# End-to-end demo: enrols sample users, marks attendance, prints reports
python3 cli.py demo

# The demo writes attendance.db in the current directory
# (or the file given as `python3 cli.py --db demo.db demo`).
# Run the tests:
python3 -m unittest discover -s tests -v
```

Individual commands (see `python3 cli.py --help` for all options):

```bash
# Enrol a user with a SIMULATED biometric sample
python3 cli.py enrol --actor admin --username alice --name "Alice Rao" \
    --role student --password secret123 --sample alice-sample-001

# Mark attendance (teacher/admin only, after biometric verification)
python3 cli.py mark --actor teacher1 --role teacher \
    --username alice --sample alice-sample-001

# Reports and audit verification
python3 cli.py report-user --role teacher --requester teacher1 --username alice
python3 cli.py report-day --role teacher --day 2026-10-25
python3 cli.py verify-audit
```

## Architecture

```
cli.py            Argument parsing and demo flow
attendance.py     Core system:
                    - users / roles / salted password hashing
                    - simulated biometric enrolment + verification (hashes only)
                    - attendance rules (verified + one-per-day)
                    - hash-chained audit log + verification
                    - per-user, per-day and summary reports
                  Storage: one SQLite file (attendance.db)
                    users, attendance, audit tables
tests/            unittest suite (see below)
```

## Tests

`tests/test_attendance.py` covers:

- Enrol/verify: matching sample verifies, mismatched and unenrolled samples do not
- Templates stored as hashes only (the sample string never appears in storage)
- Duplicate attendance prevention (same user, same day refused; other days allowed)
- Role gating: enrol, marking, and reports restricted by role
- Password login (correct vs wrong password)
- Audit chain: verifies clean, and detects a forged audit entry

## Honest limitations

- **Simulated biometrics for demonstration.** Samples are plain strings hashed with SHA-256. There is no fingerprint sensor, no fuzzy matching, no liveness or spoof detection, and no biometric accuracy measurement. Do not use this as a real biometric system.
- **Not a production or security-certified system.** No claim of production deployment, accuracy, or security certification is made. Password hashing (PBKDF2) and the hash-chained audit log are standard-library demonstrations, not a substitute for a reviewed security implementation.
- The demo database (`demo.db`, `attendance.db`) is a local file; protect it like any file containing password hashes and audit records.
