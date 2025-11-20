import os
import sqlite3
from classes.logger import Logger

class Analyzer:
    def __init__(self, config):
        self.logger = Logger()
        self.auth_db = config.get("auth_db")
        self.snort_db = config.get("snort_db")
        self.ufw_db = config.get("ufw_db")
        self.analysis_folder = config.get("analysis_folder")
        self.analysis_path = os.path.join(self.analysis_folder, config.get("analysis_db"))
        self._ensure_folder()
        self._init_db()

    def _ensure_folder(self):
        if not os.path.exists(self.analysis_folder):
            os.makedirs(self.analysis_folder)

    def _init_db(self):
        try:
            with sqlite3.connect(self.analysis_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS threat_summary (
                        ip TEXT PRIMARY KEY,
                        auth_flag INTEGER,
                        snort_flag INTEGER,
                        ufw_flag INTEGER,
                        classification TEXT
                    )
                """)
        except Exception as e:
            self.logger.error(f"Analyzer DB init error: {e}")

    def fetch_ips(self, db_path, table):
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(f"SELECT ip FROM {table}")
                return set(row[0] for row in cursor.fetchall())
        except Exception as e:
            self.logger.error(f"Analyzer DB read error from {db_path}: {e}")
            return set()

    def analyze(self):
        auth_ips = self.fetch_ips(self.auth_db, "failed_logins")
        snort_ips = self.fetch_ips(self.snort_db, "snort_alerts")
        ufw_ips = self.fetch_ips(self.ufw_db, "ufw_alerts")

        all_ips = auth_ips | snort_ips | ufw_ips

        try:
            with sqlite3.connect(self.analysis_path) as conn:
                cursor = conn.cursor()
                for ip in all_ips:
                    a = int(ip in auth_ips)
                    s = int(ip in snort_ips)
                    u = int(ip in ufw_ips)
                    classification = "attack" if a + s + u == 3 else "suspicious"
                    cursor.execute("""
                        INSERT OR REPLACE INTO threat_summary (ip, auth_flag, snort_flag, ufw_flag, classification)
                        VALUES (?, ?, ?, ?, ?)
                    """, (ip, a, s, u, classification))
                conn.commit()
            self.logger.info("Threat analysis DB updated successfully")
        except Exception as e:
            self.logger.error(f"Analyzer DB write error: {e}")