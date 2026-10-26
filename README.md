# LogLens — Security Log Analysis

## Overview

LogLens is a Python-based project that analyses web access logs and detects basic suspicious request patterns.

## Features

- Apache-style access log parsing
- Basic SQL injection detection
- Cross-Site Scripting (XSS) pattern detection
- Directory traversal detection
- JSON analysis report generation
- Request counts by IP address
- Attack summary
- Flask API
- Web dashboard with search and attack filters
- Automated tests using Python unittest

## Technology Stack

- Python
- Regular Expressions
- Flask
- HTML, CSS and JavaScript
- JSON
- unittest

## Project Setup

Install Flask:

```bash
python -m pip install flask
```

## Run the Analysis Pipeline

```bash
python pipeline.py
```

This reads the configured sample log file and generates `analysis_report.json`.

## Run Automated Tests

```bash
python -m unittest test_pipeline.py
```

## Start the Web Application

```bash
python app.py
```

Open the dashboard:

http://127.0.0.1:5000/dashboard

API endpoints:

- `/` — API status
- `/api/logs` — Analysed log entries
- `/api/summary` — Summary of logs and detected attacks
- `/dashboard` — Web dashboard

## Limitations

Detection relies on basic signatures and can produce false positives or miss attacks. Severity is a simplified demonstration rule and is not a production risk assessment.

## Disclaimer

This project is intended for educational use and authorised security log analysis only.