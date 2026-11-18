# SentinelGuard – Advanced File Integrity Monitoring System

SentinelGuard is a Python desktop application that monitors a selected directory for file additions, modifications, and deletions using SHA-256 content hashes. It stores a trusted baseline and timestamped events in SQLite.

## Features
- SHA-256 content hashing, processed in chunks
- Trusted baseline stored in SQLite
- Detects **ADDED**, **MODIFIED**, **DELETED**, and **UNCHANGED** files
- Continuous periodic monitoring
- Timestamped audit history
- Desktop GUI dashboard with event table and scan counters
- Export audit history to CSV
- Built with Python standard library only

## Requirements
- Python 3.9+
- Tkinter (usually included with Python; on some Linux distributions install `python3-tk`)

## Run locally
```bash
python main.py
```

## Demo
1. Create or choose a folder containing files you own or are authorized to monitor.
2. Open SentinelGuard and select that folder.
3. Click **Create Baseline**.
4. Modify one file, add a new file, and delete another file in that folder.
5. Click **Scan Now**. The dashboard should show MODIFIED, ADDED and DELETED events.
6. Click **Export CSV** to export the audit trail.
7. Click **Start Watch** to repeat scans at the configured interval.

## Database
`sentinelguard.db` is created automatically beside `main.py`.
- `baseline`: relative path, SHA-256 hash, size and modification time
- `audit_log`: timestamp, event type, path, old/new hashes and details

## Project structure
```text
SentinelGuard/
├── main.py
├── README.md
├── requirements.txt
└── test_files/
    ├── sample1.txt
    └── sample2.txt
```

## Security limitations
This is an academic/portfolio prototype, not a certified enterprise endpoint security product.
- Run with least privilege and monitor only folders you own or are authorized to inspect.
- Protect the SQLite database and its backups with restrictive operating-system permissions.
- An attacker who can alter both monitored files and the local baseline database may evade detection. Stronger deployments should protect baselines and send audit events to a separate trusted host or append-only logging service.
- Periodic scans can miss a change that is made and reverted between scans. Higher-assurance monitoring should combine OS file-event notifications with periodic hash verification.
- The application detects changes; it does not automatically restore files or identify the person responsible.

## License
For educational and portfolio use. Add an explicit license before redistributing the project.
