from classes.Auth import Auth
import time
import threading


def run_auth():
    auth = Auth()
    auth.store_to_db()

if __name__ == "__main__":
    try:
        while True:
            thread = threading.Thread(target=run_auth)
            thread.start()
            thread.join()
            time.sleep(900)
    except KeyboardInterrupt:
        print("🛑 Main thread stopped. Exiting...")