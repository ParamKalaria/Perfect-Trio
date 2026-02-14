import os
import re
import sqlite3
import sys
from collections import Counter

class UFW:
    def __init__(self, config):
        self.log_path = config.get("log_path")
        self.threshold = config.get("threshold")
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        db_root = os.path.join(base_dir, "db")
        self.db_path = os.path.join(db_root, "ufw_data.db")
        self._ensure_folder(db_root)
        self._init_db()

    def _ensure_folder(self, folder):
        if not os.path.exists(folder):
            os.makedirs(folder)

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
                proto = details[ip]["proto"]
                spt = details[ip]["spt"]
                dpt = details[ip]["dpt"]
                status = "attack" if count > self.threshold else "normal"
                cursor.execute("""
                    INSERT INTO ufw_alerts (ip, count, proto, spt, dpt, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET count=excluded.count, proto=excluded.proto, spt=excluded.spt, dpt=excluded.dpt, status=excluded.status
                """, (ip, count, proto, spt, dpt, status))
            conn.commit()