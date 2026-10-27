
import pipeline

with open(pipeline.SAMPLE_FILE, encoding="utf-8") as file:
    for line in file:
        log = pipeline.parse_log(line)

        if log:
            attacks = pipeline.detect_attacks(log["path"])
            print("IP:", log["ip"])
            print("Parsed path:", repr(log["path"]))
            print("Detected:", attacks)
            print("-" * 40)
