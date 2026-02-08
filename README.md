
# Sentinel: Linux Security Monitoring Tool

<div align="center">

**A production-grade SSH security monitoring system with behavioral attack detection**

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Status: Active Development](https://img.shields.io/badge/status-active%20development-green.svg)]()

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Architecture](#architecture) • [Detection Rules](#detection-rules)

</div>

---

## Overview

Sentinel is a Python-based security monitoring tool that analyzes SSH authentication logs to detect and classify authentication attacks. Built with a production-minded architecture, it separates detection, correlation, and response into distinct layers—mirroring real-world SIEM/SOAR systems.

**Key differentiator:** Safe-by-default design with dry-run execution, behavioral analysis, and alert deduplication.

---

## Features

### Detection Capabilities
- ✅ **Fast Brute-Force** - High-frequency login attempts (5+ failures in 2 minutes)
- ✅ **Slow Brute-Force** - Stealthy attacks spread over time (10+ failures in 1 hour)
- ✅ **Password Spraying** - Multiple users targeted with few attempts each
- ✅ **IPv4 & IPv6 Support** - Handles modern network configurations
- ✅ **Real-time Monitoring** - Continuous log analysis

### Intelligence Features
- 🎯 **Behavioral Analysis** - Detects attack patterns, not just failures
- 📊 **Severity Scoring** - Prioritizes alerts by intensity
- 🔗 **Alert Correlation** - Groups related events into incidents
- 🚫 **Deduplication** - Prevents alert fatigue
- ⏰ **Time-based Windows** - Sliding window analysis

### Safety Features
- 🛡️ **Dry-Run by Default** - No automatic system changes
- 📝 **Policy-Based Responses** - Configurable decision logic
- 🔍 **Incident Enrichment** - Updates existing alerts with new data
- 📈 **State Tracking** - Maintains history for cooldowns

---

## Architecture

```
┌──────────────────┐
│   auth.log       │  System authentication logs
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Parser         │  Extracts structured events (IP, user, timestamp)
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Detector       │  Identifies attack patterns (fast/slow brute, spray)
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Scoring        │  Measures intensity (5 attempts vs 50 attempts)
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Correlation    │  Infers attack type and builds incident timeline
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Response       │  Policy-based decision (BLOCK, MONITOR, IGNORE)
└────────┬─────────┘
         │
┌────────▼─────────┐
│   Execution      │  DRY-RUN: Generates firewall rules (not executed)
└──────────────────┘
```

### Architecture Principles

| Layer | Responsibility | Example |
|-------|---------------|---------|
| **Parser** | Extract facts only | "Failed login from 192.168.1.100 for user 'admin'" |
| **Detector** | Identify patterns | "5 failures in 2 minutes = fast brute-force candidate" |
| **Scorer** | Measure intensity | "5 attempts = low, 50 attempts = high" |
| **Correlator** | Infer attack meaning | "SLOW_BRUTE attack against user 'admin' from 192.168.1.100" |
| **Response** | Policy decision | "Action: BLOCK (policy: brute-force → block)" |
| **Executor** | Generate plan | "iptables -A INPUT -s 192.168.1.100 -j DROP (DRY-RUN)" |

---

## Installation

### Prerequisites
- Python 3.8+
- Linux system (tested on Ubuntu 24.04)
- SSH server running (for log generation)
- Read access to `/var/log/auth.log`

### Setup

```bash
# Clone the repository
git clone https://github.com/afk-abhishek/sentinel.git
cd sentinel

# Install dependencies (if any)
pip install -r requirements.txt

# Verify log access
sudo ls -l /var/log/auth.log
```

---

## Usage

### Basic Usage

```bash
# Run the monitor (dry-run mode, safe by default)
python3 main.py

# Monitor continuously
python3 main.py --continuous

# Specify custom log file
python3 main.py --log /custom/path/auth.log
```

### Sample Output

```
[2026-02-08 14:32:15] INFO: Sentinel started
[2026-02-08 14:32:15] INFO: Parsing /var/log/auth.log...

[ALERT] FAST_BRUTE_FORCE detected
  Source IP: 192.168.1.100
  Target User: admin
  Attempts: 7
  Time Window: 1m 45s
  Severity: HIGH
  Response: BLOCK (DRY-RUN)
  
  Execution Plan:
    → iptables -A INPUT -s 192.168.1.100 -j DROP
    [Not executed - dry-run mode]

[2026-02-08 14:35:42] INFO: 1 incident detected, 0 false positives
```

### Configuration

Edit detection thresholds in `config.py` (or your config file):

```python
# Fast brute-force detection
FAST_BRUTE_THRESHOLD = 5      # attempts
FAST_BRUTE_WINDOW = 120       # seconds

# Slow brute-force detection
SLOW_BRUTE_THRESHOLD = 10     # attempts
SLOW_BRUTE_WINDOW = 3600      # seconds (1 hour)

# Password spray detection
PASSWORD_SPRAY_USERS = 5      # distinct users
PASSWORD_SPRAY_WINDOW = 300   # seconds (5 minutes)
```

---

## Detection Rules

### Fast Brute-Force
**Pattern:** Multiple rapid login attempts from the same IP
```
Trigger: ≥5 failed attempts in ≤2 minutes
Example: 
  14:00:00 - Failed login (admin)
  14:00:15 - Failed login (admin)
  14:00:30 - Failed login (admin)
  14:00:45 - Failed login (admin)
  14:01:00 - Failed login (admin) → ALERT
```

### Slow Brute-Force
**Pattern:** Sustained attempts spread over time to evade detection
```
Trigger: ≥10 failed attempts in ≤1 hour (same user, same IP)
Example:
  13:00 - Failed (admin)
  13:05 - Failed (admin)
  13:10 - Failed (admin)
  ...
  13:50 - Failed (admin) → ALERT (10th attempt)
```

### Password Spraying
**Pattern:** Testing one password against many accounts
```
Trigger: ≥5 different users from same IP in ≤5 minutes
Example:
  14:00 - Failed (admin)
  14:01 - Failed (user1)
  14:02 - Failed (user2)
  14:03 - Failed (user3)
  14:04 - Failed (user4) → ALERT (5 distinct users)
```

---

## Testing

### Generate Test Data

```bash
# Install SSH server (if not already)
sudo apt install openssh-server

# Generate failed login attempts
ssh fakeuser@localhost   # Intentional failure
ssh admin@localhost      # Another failure
ssh root@localhost       # And another


# Either way a faster way to generate attacks:
for i in {1..n};do
    ssh zoro@localhost
done
```

### Validated Against

- ✅ Hydra brute-force attacks
- ✅ Manual slow credential stuffing
- ✅ Medusa password spraying
- ✅ Legitimate failed logins (confirmed no false positives)

---

## Project Status

**Current:** Active Development  
**Architecture:** Frozen (pipeline design complete)  
**Detection:** Implemented (fast/slow brute, password spray)  
**Response:** Implemented (policy-based decisions)  
**Execution:** Disabled by design (dry-run only)

### Roadmap

- [x] Log parsing with IPv4/IPv6 support
- [x] Fast brute-force detection
- [x] Slow brute-force detection
- [x] Password spray detection
- [x] Alert deduplication and enrichment
- [x] Severity-based correlation
- [x] Safe response planning (dry-run)
- [ ] Web dashboard for alerts
- [ ] Email/Slack notifications
- [ ] Custom detection rules (YAML config)
- [ ] Multi-log source support (fail2ban, nginx)
- [ ] GeoIP lookup and visualization
- [ ] Database backend (SQLite/PostgreSQL)

---

## Why Sentinel?

| Feature | fail2ban | OSSEC | Custom Scripts | Sentinel |
|---------|----------|-------|----------------|----------|
| **Attack Classification** | Basic | Advanced | Variable | Advanced |
| **Behavioral Analysis** | ❌ | ✅ | ❌ | ✅ |
| **Safe by Default** | ⚠️ Blocks immediately | ⚠️ Blocks immediately | Depends | ✅ Dry-run |
| **Learning-Focused** | ❌ | ❌ | ❌ | ✅ |
| **Modular Pipeline** | ❌ | ✅ | ❌ | ✅ |
| **Lightweight** | ✅ | ❌ | ✅ | ✅ |

---

## Safety Notice

⚠️ **All response and execution logic operates in DRY-RUN mode by default.**

No firewall rules, IP blocks, or system-level actions are automatically executed unless explicitly enabled and validated. This design prioritizes learning and testing over automated enforcement.

**To enable execution** (advanced users only):
1. Review the execution plan output
2. Validate it won't block legitimate traffic
3. Test in a non-production environment
4. Enable via config flag (when implemented)

---

## Acknowledgments

Built as a hands-on security engineering learning project. Inspired by production SIEM/SOAR systems and influenced by real-world SSH attack patterns.

---

## Contact

**Author:** Abhishek  
**GitHub:** [@afk-abhishek](https://github.com/afk-abhishek)  
**Project Link:** [https://github.com/afk-abhishek/sentinel](https://github.com/afk-abhishek/sentinel)

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ☕ and 🛡️ by Abhishek

</div>
