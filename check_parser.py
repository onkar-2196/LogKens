
import pipeline

line = '203.0.113.25 - - [26/Oct/2026:10:16:10 +0530] "GET /search?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 512'

results = pipeline.analyze_lines([line])

print("Analysis result:", results)
print("Attacks:", results[0]["attacks"])
print("Severity:", results[0]["severity"])
