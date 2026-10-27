
import pipeline

tests = [
    "test OR 1=1",
    "' OR 1=1",
    "/search?q=%27%20OR%201%3D1",
    "UNION SELECT username FROM users",
]

for text in tests:
    print(f"Input: {text}")
    print(f"Decoded: {pipeline.unquote(text)}")
    print(f"Detected: {pipeline.detect_attacks(text)}")
    print("-" * 40)

