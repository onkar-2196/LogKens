

import re

SIGNATURES = {
    "sql_injection": r"(\bunion\s+select\b|'?\sor\s+1=1)",
    "xss": r"(<script\b|javascript:)",
    "directory_traversal": r"(\.\./|\.\.\\)"
}


def detect_attacks(log_entry):
    detected = []

    text = str(log_entry)

    for attack_type, pattern in SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(attack_type)

    return detected


sample_log = {
    "ip": "192.168.1.10",
    "path": "/search?q=<script>alert(1)</script>",
    "status_code": 200
}

result = detect_attacks(sample_log)
print(result)
