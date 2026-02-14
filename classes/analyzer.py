import os
import sqlite3
import sys
from classes.logger import Logger

class Analyzer:
    def __init__(self, config):
        self.logger = Logger()
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        self.analysis_folder = os.path.join(base_dir, "db")
        self.auth_db = os.path.join(self.analysis_folder, "auth_data.db")
        self.ids_ips_db = os.path.join(self.analysis_folder, "ids_ips_data.db")
        self.ufw_db = os.path.join(self.analysis_folder, "ufw_data.db")
        self.analysis_path = os.path.join(self.analysis_folder, "threats.db")
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
                        ids_ips_flag INTEGER,
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
        ids_ips_ips = self.fetch_ips(self.ids_ips_db, "ids_ips_alerts")
        ufw_ips = self.fetch_ips(self.ufw_db, "ufw_alerts")

        all_ips = auth_ips | ids_ips_ips | ufw_ips

        try:
            with sqlite3.connect(self.analysis_path) as conn:
                cursor = conn.cursor()
                for ip in all_ips:
                    a = int(ip in auth_ips)
                    s = int(ip in ids_ips_ips)
                    u = int(ip in ufw_ips)
                    # Classify as attack if present in at least 2 systems, or strict 3 based on preference
                    classification = "attack" if (a + s + u) >= 2 else "suspicious"
                    cursor.execute("""
                        INSERT OR REPLACE INTO threat_summary (ip, auth_flag, ids_ips_flag, ufw_flag, classification)
                        VALUES (?, ?, ?, ?, ?)
                    """, (ip, a, s, u, classification))
                conn.commit()
            self.logger.info("Threat analysis DB updated successfully")
        except Exception as e:
            self.logger.error(f"Analyzer DB write error: {e}")