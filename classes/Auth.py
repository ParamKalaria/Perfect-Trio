import os
import re
import sqlite3
import sys
from collections import Counter

class Auth:
    def __init__(self, config):
        self.log_path = config.get("log_path")
        self.threshold = config.get("threshold")
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        
        db_root = os.path.join(base_dir, "db")
        self.db_path = os.path.join(db_root, "auth_data.db")
        self._ensure_folder(db_root)
        self._init_db()

    def _ensure_folder(self, folder):
        if not os.path.exists(folder):
            os.makedirs(folder)

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
                    match = re.search(r"from ([\d\.]+|[a-fA-F0-9:]+)", line)
                    if match:
                        ip = match.group(1)
                        ip_counter[ip] += 1
        return dict(sorted(ip_counter.items(), key=lambda x: x[1], reverse=True))

    def store_to_db(self):
        failed_counts = self.get_failed_login_counts()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for ip, count in failed_counts.items():
                status = "attack" if count > self.threshold else "normal"
                cursor.execute("""
                    INSERT INTO failed_logins (ip, count, status)
                    VALUES (?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET count=excluded.count, status=excluded.status
                """, (ip, count, status))
            conn.commit()