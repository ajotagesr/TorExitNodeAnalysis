import os
import logging
from logging.handlers import RotatingFileHandler

LOG_FILE = os.path.join(os.path.dirname(__file__), "update_ipmasks.log")

class Logger:
    def __init__(self, log_file_path, log_level=logging.INFO):
        self.log_file_path = log_file_path
        self.log_level = log_level
        self.logger = self.get_logger()

    def get_logger(self):
        logger = logging.getLogger(__name__)
        
        # Avoid adding multiple handlers
        if not logger.hasHandlers():
            logger.setLevel(self.log_level)
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

            # Use append mode by default
            handler = RotatingFileHandler(self.log_file_path, maxBytes=1000000, backupCount=10)
            handler.setLevel(self.log_level)
            handler.setFormatter(formatter)

            logger.addHandler(handler)

        return logger

    def log(self, event, message, log_level=logging.INFO):
        self.logger.log(log_level, f"{event} - {message}")

    def info(self, event, message):
        self.log(event, message, log_level=logging.INFO)

    def warning(self, event, message):
        self.log(event, message, log_level=logging.WARNING)

    def error(self, event, message):
        self.log(event, message, log_level=logging.ERROR)

    def debug(self, event, message):
        self.log(event, message, log_level=logging.DEBUG)

    def critical(self, event, message):
        self.log(event, message, log_level=logging.CRITICAL)

    def separator(self):
        self.logger.info("-------------------------------------------------")

