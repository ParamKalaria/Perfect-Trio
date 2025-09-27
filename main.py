from classes.Auth import Auth
from classes.snort import Snort
from classes.logger import Logger
from classes.ufw import UFW


import time
import threading

logger = Logger()

def run_auth():
    logger.thread_event("Auth", "started")
    try:
        auth = Auth()
        auth.store_to_db()
        logger.info("Auth DB update completed")
    except Exception as e:
        logger.error(f"Auth error: {e}")
    logger.thread_event("Auth", "stopped")

def run_snort():
    logger.thread_event("Snort", "started")
    try:
        snort = Snort()
        snort.store_to_db()
        logger.info("Snort DB update completed")
    except Exception as e:
        logger.error(f"Snort error: {e}")
    logger.thread_event("Snort", "stopped")

def run_ufw():
    logger.thread_event("UFW", "started")
    try:
        ufw = UFW()
        ufw.store_to_db()
        logger.info("UFW DB update completed")
    except Exception as e:
        logger.error(f"UFW error: {e}")
    logger.thread_event("UFW", "stopped")







if __name__ == "__main__":
    try:
        while True:
            auth_thread = threading.Thread(target=run_auth)
            snort_thread = threading.Thread(target=run_snort)
            ufw_thread = threading.Thread(target=run_ufw)

            auth_thread.start()
            snort_thread.start()
            ufw_thread.start()

            auth_thread.join()
            snort_thread.join()
            ufw_thread.join()

            time.sleep(900)  # 15 minutes
    
    except KeyboardInterrupt:
        logger.info("Main thread interrupted. Shutting down.")