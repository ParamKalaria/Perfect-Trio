import re
from collections import Counter

class Auth:
    def __init__(self, log_path="/var/log/auth.log"):
        self.log_path = log_path

    def get_failed_login_counts(self):
        ip_counter = Counter()
        try:
            with open(self.log_path, "r") as file:
                for line in file:
                    if "Failed password for" in line:
                        match = re.search(r"from ([\d\.]+)", line)
                        if match:
                            ip = match.group(1)
                            ip_counter[ip] += 1
        except FileNotFoundError:
            print(f"Log file not found: {self.log_path}")
        return dict(ip_counter)