import time
import threading
import json
import sys
import os
from datetime import datetime, timedelta

from classes.Auth import Auth
from classes.ids_ips import IDS_IPS
from classes.ufw import UFW
from classes.analyzer import Analyzer
from classes.defense import Defense
from classes.logger import Logger

logger = Logger()
last_analysis = datetime.min  # Track last Analyzer run

# Determine execution path (works for both script and PyInstaller executable)
if getattr(sys, 'frozen', False):
    application_path = os.path.dirname(sys.executable)
else:
    application_path = os.path.dirname(os.path.abspath(__file__))

config_path = os.path.join(application_path, "config.json")

# Default configuration
DEFAULT_CONFIG = {
    "auth": {
        "log_path": "/var/log/auth.log",
        "threshold": 5
    },
    "ids_ips": {
        "log_path": "/var/log/snort/snort.alert.fast",
        "type": "snort",
        "threshold": 5
    },
    "ufw": {
        "log_path": "/var/log/ufw.log",
        "threshold": 5
    },
    "analyzer": {},
    "defense": {}
}

# Load or create config.json
if not os.path.exists(config_path):
    logger.info("Config file not found. Creating default config.json")
    try:
        with open(config_path, "w") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        config = DEFAULT_CONFIG
    except Exception as e:
        logger.error(f"Failed to create config.json: {e}")
        config = DEFAULT_CONFIG
else:
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error loading config.json: {e}. Using defaults.")
        config = DEFAULT_CONFIG

def resolve_and_ensure_path(path_key, section_config, create_dir=False):
    """Resolves path to absolute relative to app and optionally creates directory."""
    if path_key in section_config:
        path = section_config[path_key]
        if not os.path.isabs(path):
            path = os.path.join(application_path, path)
            section_config[path_key] = path
        if create_dir:
            os.makedirs(path, exist_ok=True)

def run_auth():
    logger.thread_event("Auth", "started")
    try:
        auth = Auth(config["auth"])
        auth.store_to_db()
        logger.info("Auth DB update completed")
    except Exception as e:
        logger.error(f"Auth error: {e}")
    logger.thread_event("Auth", "stopped")

def run_ids_ips():
    logger.thread_event("IDS/IPS", "started")
    try:
        ids_ips = IDS_IPS(config["ids_ips"])
        ids_ips.store_to_db()
        logger.info("IDS/IPS DB update completed")
    except Exception as e:
        logger.error(f"IDS/IPS error: {e}")
    logger.thread_event("IDS/IPS", "stopped")

def run_ufw():
    logger.thread_event("UFW", "started")
    try:
        ufw = UFW(config["ufw"])
        ufw.store_to_db()
        logger.info("UFW DB update completed")
    except Exception as e:
        logger.error(f"UFW error: {e}")
    logger.thread_event("UFW", "stopped")

def run_analysis():
    logger.thread_event("Analyzer", "started")
    try:
        analyzer = Analyzer(config["analyzer"])
        analyzer.analyze()
        logger.info("Threat analysis DB updated")
    except Exception as e:
        logger.error(f"Analyzer error: {e}")
    logger.thread_event("Analyzer", "stopped")

def run_defense():
    logger.thread_event("Defense", "started")
    try:
        defense = Defense(config["defense"])
        defense.defend()
        logger.info("Defense system executed")
    except Exception as e:
        logger.error(f"Defense error: {e}")
    logger.thread_event("Defense", "stopped")

def run_analysis_cycle():
    """Runs analysis and defense sequentially to ensure data consistency."""
    run_analysis()
    run_defense()

if __name__ == "__main__":
    try:
        while True:
            now = datetime.now()

            # Launch core systems
            threading.Thread(target=run_auth).start()
            threading.Thread(target=run_ids_ips).start()
            threading.Thread(target=run_ufw).start()

            # Launch Analyzer every 1 hour
            if now - last_analysis >= timedelta(hours=1):
                threading.Thread(target=run_analysis_cycle).start()
                last_analysis = now

            time.sleep(900)  # Sleep for 15 minutes
    except KeyboardInterrupt:
        logger.info("Main thread interrupted. Shutting down.")