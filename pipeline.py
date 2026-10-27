
from urllib.parse import unquote
import json
import re
from collections import Counter
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_FILE = BASE_DIR / "sample.log"
REPORT_FILE = BASE_DIR / "analysis_report.json"


SIGNATURES = {    
    "sql_injection": r"(\bunion\s+select\b|'\s*or\s+1=1|\bor\s+1=1)",
    "xss": r"(<script\b|javascript:)",
    "directory_traversal": r"(\.\./|\.\.\\)"
}



LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]+" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)


def parse_log(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return None

    data = match.groupdict()
    data["status"] = int(data["status"])
    return data



def detect_attacks(path):
    detected = []
    decoded_path = unquote(path)

    for attack, pattern in SIGNATURES.items():
        if re.search(pattern, path, re.IGNORECASE):
            detected.append(attack)
        elif re.search(pattern, decoded_path, re.IGNORECASE):
            detected.append(attack)

    return detected



def analyze_lines(lines):
    results = []
    for line in lines:
        log = parse_log(line)
        if log is None:
            continue

        log["attacks"] = detect_attacks(log["path"])
        log["severity"] = "high" if log["attacks"] else "none"
        results.append(log)
    return results


def build_summary(results):
    ip_counts = Counter(log["ip"] for log in results)
    attack_counts = Counter(
        attack for log in results for attack in log["attacks"]
    )
    suspicious_ips = {
        log["ip"] for log in results if log["attacks"]
    }

    return {
        "total_logs": len(results),
        "suspicious_ip_count": len(suspicious_ips),
        "ip_counts": dict(ip_counts),
        "attack_counts": dict(attack_counts)
    }


def main():
    if not SAMPLE_FILE.exists():
        print("sample.log file nahi mili.")
        return

    with SAMPLE_FILE.open(
        "r", encoding="utf-8", errors="replace"
    ) as file:
        results = analyze_lines(file)

    with REPORT_FILE.open("w", encoding="utf-8") as file:
        json.dump(results, file, indent=4)

    summary = build_summary(results)
    print(f"Total logs analysed: {summary['total_logs']}")
    print("Report saved to analysis_report.json")

    print("\n--- IP Summary ---")
    for ip, count in Counter(
        log["ip"] for log in results
    ).most_common():
        print(f"{ip}: {count} request(s)")

    print("\n--- Attack Summary ---")
    for attack, count in Counter(
        attack for log in results for attack in log["attacks"]
    ).most_common():
        print(f"{attack}: {count}")


if __name__ == "__main__":
    main()
