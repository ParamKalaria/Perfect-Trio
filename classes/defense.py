import os
import sqlite3
import subprocess
import sys
from classes.logger import Logger

class Defense:
    def __init__(self, config):
        self.logger = Logger()
        
        if getattr(sys, 'frozen', False):
            base_dir = os.path.dirname(sys.executable)
        else:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
        self.db_root = os.path.join(base_dir, "db")
        self.analysis_db = os.path.join(self.db_root, "threats.db")
        self.db_path = os.path.join(self.db_root, "defense.db")
        self._ensure_folder(self.db_root)
        self._init_db()

    def _ensure_folder(self, folder):
        if not os.path.exists(folder):
            os.makedirs(folder)

    def _init_db(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS blocked_ips (
                        ip TEXT PRIMARY KEY,
                        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        status TEXT
                    )
                """)
                conn.commit()
        except Exception as e:
            self.logger.error(f"Defense DB init error: {e}")

    def get_blocked_ips(self):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip FROM blocked_ips")
                return set(row[0] for row in cursor.fetchall())
        except Exception as e:
            self.logger.error(f"Defense DB read error: {e}")
            return set()

    def get_attack_ips(self):
        try:
            with sqlite3.connect(self.analysis_db) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT ip FROM threat_summary WHERE classification = 'attack'")
                return set(row[0] for row in cursor.fetchall())
        except Exception as e:
            self.logger.error(f"Analyzer DB read error: {e}")
            return set()

    def block_ip(self, ip):
        try:
            command = f"ufw deny from {ip}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True, check=False)
            
            if result.returncode == 0:
                self.logger.info(f"UFW rule added: deny from {ip}")
                return True
            else:
                self.logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Error executing UFW command for {ip}: {e}")
            return False

    def record_blocked_ip(self, ip, status="blocked"):
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR IGNORE INTO blocked_ips (ip, status)
                    VALUES (?, ?)
                """, (ip, status))
                conn.commit()
        except Exception as e:
            self.logger.error(f"Error recording blocked IP {ip}: {e}")

    def defend(self):
        try:
            attack_ips = self.get_attack_ips()
            blocked_ips = self.get_blocked_ips()
            
            # IPs to block = attack IPs - already blocked IPs
            ips_to_block = attack_ips - blocked_ips
            
            if not ips_to_block:
                self.logger.info("No new IPs to block")
                return
            
            for ip in ips_to_block:
                if self.block_ip(ip):
                    self.record_blocked_ip(ip, "blocked")
                    self.logger.info(f"IP {ip} blocked and recorded")
                else:
                    self.record_blocked_ip(ip, "block_failed")
                    self.logger.error(f"Failed to block IP {ip}")
            
            self.logger.info(f"Defense: Blocked {len(ips_to_block)} new IP(s)")
        except Exception as e:
            self.logger.error(f"Defense system error: {e}")
