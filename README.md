# Sentinel: A Linux Security Monitoring Tool

A Python-based security monitoring tool that parses SSH authentication logs
to detect failed login attempts, suspicious activity and produce safe response
plans.

## Features
- Parses `/var/log/auth.log`
- Detects failed SSH login attempts
- Extracts username, IP address (IPv4 & IPv6), and timestamp
- Scores alert intensity and correlates events into incidents
- Produces response decisions and execution plans (dry-run only)
- Designed for security learning and log analysis

## Tech Stack
- Python 3
- Linux (Ubuntu)
- SSH authentication logs

## Detection & Response Pipeline

auth.log
  ↓
Detection        (facts only)
  ↓
Scoring          (intensity)
  ↓
Correlation      (attack meaning)
  ↓
Response Decision (policy)
  ↓
Execution Planning (dry-run)
  ↓
Execution        (disabled by default)


## Architecture Principles
- Detectors emit factual signals only
- Scoring measures intensity, not intent
- Correlation infers attack type and timelines
- Response decisions are policy-based and non-destructive
- Execution capability exists but is disabled by default
- System state is tracked for deduplication and cooldowns

## Safety Notice
All response and execution logic operates in DRY-RUN mode by default.
No firewall or system-level actions are automatically executed unless
explicitly enabled and validated.


## Project Status
Active development — architecture frozen, detection and response layers
implemented, execution disabled by design.
"Work in progress"

