
import re
import json

LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+\S+\s+"[^"]*"\s+'
    r'"(?P<user_agent>[^"]*)"$'
)

def parse_log_line(line):
    match = LOG_PATTERN.match(line.strip())

    if not match:
        return None

    log_data = match.groupdict()
    log_data["status"] = int(log_data["status"])

    return log_data


def parse_log_file(filename):
    results = []

    with open(filename, "r", encoding="utf-8") as file:
        for line in file:
            parsed = parse_log_line(line)

            if parsed is not None:
                results.append(parsed)

    return results


if __name__ == "__main__":
    logs = parse_log_file("sample.log")

    with open("output.json", "w", encoding="utf-8") as file:
        json.dump(logs, file, indent=4)

    print("Total parsed logs:", len(logs))
    print("Output saved to output.json")
