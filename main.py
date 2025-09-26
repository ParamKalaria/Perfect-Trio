from classes.Auth import Auth
from classes.logger import Logger  # new import
import time
import threading

logger = Logger()  # initialize logger

def run_auth():
    logger.thread_event("AuthThread", "started")
    try:
        auth = Auth()
        auth.store_to_db()
        logger.info("Auth DB update completed")
    except Exception as e:
        logger.error(f"Auth error: {e}")
    logger.thread_event("AuthThread", "stopped")

if __name__ == "__main__":
    try:
        while True:
            thread = threading.Thread(target=run_auth)
            thread.start()
            thread.join()
            time.sleep(900)
    except KeyboardInterrupt:
        logger.info("Main thread interrupted. Shutting down.")