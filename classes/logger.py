import os
import logging

class Logger:
    def __init__(self, log_folder="logs", log_file="activity.log"):
        self.log_folder = log_folder
        self.log_file = log_file
        self.log_path = os.path.join(log_folder, log_file)
        self._ensure_log_file()
        self._setup_logger()

    def _ensure_log_file(self):
        if not os.path.exists(self.log_folder):
            os.makedirs(self.log_folder)
        if not os.path.exists(self.log_path):
            with open(self.log_path, "w") as f:
                f.write("")  # create empty log file

    def _setup_logger(self):
        logging.basicConfig(
            filename=self.log_path,
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        self.logger = logging.getLogger()

    def info(self, message):
        self.logger.info(message)

    def error(self, message):
        self.logger.error(message)

    def thread_event(self, thread_name, action):
        self.info(f"Thread '{thread_name}' {action}")