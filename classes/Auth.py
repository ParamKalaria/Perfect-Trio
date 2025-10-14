import os
import re
import sqlite3
from collections import Counter

class Auth:
    def __init__(self, log_path="./log/auth.log", threshold=5, db_root="db", db_subfolder="auth_logs", db_name="auth_data.db"):
        self.log_path = log_path
        self.threshold = threshold
        self.db_folder = os.path.join(db_root, db_subfolder)
        self.db_path = os.path.join(self.db_folder, db_name)
        self._ensure_folder()
        self._init_db()

    def _ensure_folder(self):
        if not os.path.exists(self.db_folder):
            os.makedirs(self.db_folder)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS failed_logins (
                    ip TEXT PRIMARY KEY,
                    count INTEGER,
                    status TEXT
                )
            """)

    def get_failed_login_counts(self):
        ip_counter = Counter()
        if not os.path.isfile(self.log_path):
            return {}

        with open(self.log_path, "r") as file:
            for line in file:
                if "Failed password for" in line:
                    match = re.search(r"from ([\d\.]+)", line)
                    if match:
                        ip = match.group(1)
                        ip_counter[ip] += 1
        return dict(sorted(ip_counter.items(), key=lambda x: x[1], reverse=True))

    def detect_attacks(self):
        failed_counts = self.get_failed_login_counts()
        return {ip: count for ip, count in failed_counts.items() if count > self.threshold}

    def store_to_db(self):
        failed_counts = self.get_failed_login_counts()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for ip, count in failed_counts.items():
                cursor.execute("SELECT 1 FROM failed_logins WHERE ip = ?", (ip,))
                if cursor.fetchone() is None:
                    status = "attack" if count > self.threshold else "normal"
                    cursor.execute("""
                        INSERT INTO failed_logins (ip, count, status)
                        VALUES (?, ?, ?)
                    """, (ip, count, status))
            conn.commit()