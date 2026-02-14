import os
import re
import sqlite3
import json
import sys
from collections import Counter

class IDS_IPS:
    def __init__(self, config):
        self.log_path = config.get("log_path")
        self.threshold = config.get("threshold")
        self.ids_type = config.get("type", "snort").lower()  # "snort" or "suricata"
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        db_root = os.path.join(base_dir, "db")
        self.db_path = os.path.join(db_root, "ids_ips_data.db")
        self._ensure_folder(db_root)
        self._init_db()

    def _ensure_folder(self, folder):
        if not os.path.exists(folder):
            os.makedirs(folder)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ids_ips_alerts (
                    ip TEXT PRIMARY KEY,
                    count INTEGER,
                    ids_type TEXT,
                    classification TEXT,
                    protocol TEXT,
                    status TEXT
                )
            """)

    def parse_snort_alerts(self):
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

    def parse_suricata_alerts(self):
        ip_counter = Counter()
        details = {}

        if not os.path.isfile(self.log_path):
            return {}, {}

        with open(self.log_path, "r") as file:
            for line in file:
                # Suricata EVE JSON format parsing (common format)
                try:
                    # Try to parse JSON (Suricata EVE format)
                    record = json.loads(line.strip())
                    if "alert" in record and "src_ip" in record:
                        ip = record["src_ip"]
                        classification = record.get("alert", {}).get("category", "Unknown")
                        protocol = record.get("proto", "Unknown")

                        ip_counter[ip] += 1
                        if ip not in details:
                            details[ip] = {
                                "classification": classification,
                                "protocol": protocol
                            }
                except (json.JSONDecodeError, KeyError):
                    # Fallback to text parsing for non-JSON format
                    src_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]", line)
                    class_match = re.search(r"\[Classification: (.*?)\]", line)
                    proto_match = re.search(r"\{(\w+)\}", line)

                    if src_match:
                        ip = src_match.group(1)
                        classification = class_match.group(1).strip() if class_match else "Unknown"
                        protocol = proto_match.group(1).strip() if proto_match else "Unknown"

                        ip_counter[ip] += 1
                        if ip not in details:
                            details[ip] = {
                                "classification": classification,
                                "protocol": protocol
                            }

        return dict(ip_counter), details

    def parse_alerts(self):
        if self.ids_type == "suricata":
            return self.parse_suricata_alerts()
        else:  # default to snort
            return self.parse_snort_alerts()

    def store_to_db(self):
        ip_counts, details = self.parse_alerts()
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for ip, count in ip_counts.items():
                classification = details[ip]["classification"]
                protocol = details[ip]["protocol"]
                status = "attack" if count > self.threshold else "normal"
                cursor.execute("""
                    INSERT INTO ids_ips_alerts (ip, count, ids_type, classification, protocol, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(ip) DO UPDATE SET count=excluded.count, ids_type=excluded.ids_type, classification=excluded.classification, protocol=excluded.protocol, status=excluded.status
                """, (ip, count, self.ids_type, classification, protocol, status))
            conn.commit()
