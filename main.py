import time
import threading
import json
from datetime import datetime, timedelta

from classes.Auth import Auth
from classes.snort import Snort
from classes.ufw import UFW
from classes.analyzer import Analyzer
from classes.logger import Logger

logger = Logger()
last_analysis = datetime.min  # Track last Analyzer run

# Load config.json once
with open("config.json", "r") as f:
    config = json.load(f)

def run_auth():
    logger.thread_event("Auth", "started")
    try:
        auth = Auth(config["auth"])
        auth.store_to_db()
        logger.info("Auth DB update completed")
    except Exception as e:
        logger.error(f"Auth error: {e}")
    logger.thread_event("Auth", "stopped")

def run_snort():
    logger.thread_event("Snort", "started")
    try:
        snort = Snort(config["snort"])
        snort.store_to_db()
        logger.info("Snort DB update completed")
    except Exception as e:
        logger.error(f"Snort error: {e}")
    logger.thread_event("Snort", "stopped")

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

if __name__ == "__main__":
    try:
        while True:
            now = datetime.now()

            # Launch core systems
            threading.Thread(target=run_auth).start()
            threading.Thread(target=run_snort).start()
            threading.Thread(target=run_ufw).start()

            # Launch Analyzer every 1 hour
            if now - last_analysis >= timedelta(hours=1):
                threading.Thread(target=run_analysis).start()
                last_analysis = now

            time.sleep(900)  # Sleep for 15 minutes
    except KeyboardInterrupt:
        logger.info("Main thread interrupted. Shutting down.")