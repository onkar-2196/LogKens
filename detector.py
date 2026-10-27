
import re
from urllib.parse import unquote

SIGNATURES = {
    "sql_injection": r"(\bunion\s+select\b|'?\s*or\s+1=1)",
    "xss": r"(<script\b|javascript:)",
    "directory_traversal": r"(\.\./|\.\.\\)"
}


def detect_attacks(log_entry):
    detected = []

    # Convert the log entry to text
    text = unquote(str(log_entry))

    for attack_type, pattern in SIGNATURES.items():
        if re.search(pattern, text, re.IGNORECASE):
            detected.append(attack_type)

    return detected


if __name__ == "__main__":
    sample_log = {
        "ip": "192.0.2.50",
        "path": "/search?q=' OR 1=1",
        "status_code": 200
    }

    result = detect_attacks(sample_log)
    print("Detected attacks:", result)
