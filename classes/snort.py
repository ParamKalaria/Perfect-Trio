import os
import re
import sqlite3
from collections import Counter

class Snort:
    def __init__(self, log_path="./log/snort.alert.fast", threshold=5, db_root="db", db_subfolder="snort_logs", db_name="snort_data.db"):
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
                CREATE TABLE IF NOT EXISTS snort_alerts (
                    ip TEXT PRIMARY KEY,
                    count INTEGER,
                    classification TEXT,
                    protocol TEXT,
                    status TEXT
                )
            """)

    def parse_alerts(self):
        ip_counter = Counter()
        details = {}

        if not os.path.isfile(self.log_path):
            return {}, {}

        with open(self.log_path, "r") as file:
            for line in file:
                class_match = re.search(r"\[Classification: (.*?)\]", line)
                proto_match = re.search(r"\{(\w+)\}", line)
                src_match = re.search(r"\{.*?\}\s+(\d{1,3}(?:\.\d{1,3}){3}):\d+\s+->", line)

                if class_match and proto_match and src_match:
                    classification = class_match.group(1).strip()
                    protocol = proto_match.group(1).strip()
                    ip = src_match.group(1)

                    ip_counter[ip] += 1
                    if ip not in details:
                        details[ip] = {
                            "classification": classification,
                            "protocol": protocol
                        }

        return dict(ip_counter), details

    def store_to_db(self):
        ip_counts, details = self.parse_alerts()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for ip, count in ip_counts.items():
                cursor.execute("SELECT 1 FROM snort_alerts WHERE ip = ?", (ip,))
                if cursor.fetchone() is None:
                    classification = details[ip]["classification"]
                    protocol = details[ip]["protocol"]
                    status = "attack" if count > self.threshold else "normal"
                    cursor.execute("""
                        INSERT INTO snort_alerts (ip, count, classification, protocol, status)
                        VALUES (?, ?, ?, ?, ?)
                    """, (ip, count, classification, protocol, status))
            conn.commit()