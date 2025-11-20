import os
import re
import sqlite3
from collections import Counter

class Snort:
    def __init__(self, config):
        self.log_path = config.get("log_path")
        self.threshold = config.get("threshold")
        db_root = config.get("db_root")
        db_name = config.get("db_name")
        self.db_path = os.path.join(db_root, db_name)
        self._ensure_folder(db_root)
        self._init_db()

    def _ensure_folder(self, folder):
        if not os.path.exists(folder):
            os.makedirs(folder)

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
                classification = details[ip]["classification"]
                protocol = details[ip]["protocol"]
                status = "attack" if count > self.threshold else "normal"
                cursor.execute("""
                    INSERT INTO snort_alerts (ip, count, classification, protocol, status)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET count=excluded.count, classification=excluded.classification, protocol=excluded.protocol, status=excluded.status
                """, (ip, count, classification, protocol, status))
            conn.commit()