import re
from collections import Counter

def parse_alerts(log_path="./log/snort.alert.fast", threshold=2):
    ip_counter = Counter()
    classifications = {}

    current_class = None

    try:
        with open(log_path, "r") as file:
            for line in file:
                if "[**]" in line:
                    class_match = re.search(r"\[\*\*\] \[.*?\] (.*?) \[\*\*\]", line)
                    if class_match:
                        current_class = class_match.group(1).strip()

                if "->" in line:
                    ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+->", line)
                    if ip_match:
                        ip = ip_match.group(1)
                        ip_counter[ip] += 1
                        if ip not in classifications:
                            classifications[ip] = current_class
    except FileNotFoundError:
        print(f"❌ Log file not found: {log_path}")
        return

    print("\n📊 Snort Alert Summary:")
    for ip, count in ip_counter.items():
        classification = classifications.get(ip, "Unknown")
        status = "ATTACK" if count > threshold else "NORMAL"
        print(f"IP: {ip} | Count: {count} | Classification: {classification} | Status: {status}")

if __name__ == "__main__":
    parse_alerts()