import os
import re
import sqlite3
from collections import Counter

class UFW:
    def __init__(self, log_path="./log/ufw.log", threshold=5, db_root="db", db_subfolder="ufw_logs", db_name="ufw_data.db"):
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
                CREATE TABLE IF NOT EXISTS ufw_alerts (
                    ip TEXT PRIMARY KEY,
                    count INTEGER,
                    proto TEXT,
                    spt TEXT,
                    dpt TEXT,
                    status TEXT
                )
            """)

    def parse_logs(self):
        ip_counter = Counter()
        details = {}

        if not os.path.isfile(self.log_path):
            return {}, {}

        with open(self.log_path, "r") as file:
            for line in file:
                src_match = re.search(r"SRC=(\d{1,3}(?:\.\d{1,3}){3})", line)
                proto_match = re.search(r"PROTO=(\w+)", line)
                spt_match = re.search(r"SPT=(\d+)", line)
                dpt_match = re.search(r"DPT=(\d+)", line)

                if src_match:
                    ip = src_match.group(1)
                    ip_counter[ip] += 1

                    if ip not in details:
                        details[ip] = {
                            "proto": proto_match.group(1) if proto_match else "Unknown",
                            "spt": spt_match.group(1) if spt_match else "Unknown",
                            "dpt": dpt_match.group(1) if dpt_match else "Unknown"
                        }

        return dict(ip_counter), details

    def store_to_db(self):
        ip_counts, details = self.parse_logs()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for ip, count in ip_counts.items():
                cursor.execute("SELECT 1 FROM ufw_alerts WHERE ip = ?", (ip,))
                if cursor.fetchone() is None:
                    proto = details[ip]["proto"]
                    spt = details[ip]["spt"]
                    dpt = details[ip]["dpt"]
                    status = "attack" if count > self.threshold else "normal"
                    cursor.execute("""
                        INSERT INTO ufw_alerts (ip, count, proto, spt, dpt, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (ip, count, proto, spt, dpt, status))
            conn.commit()