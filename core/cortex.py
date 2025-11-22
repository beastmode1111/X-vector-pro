# core/cortex.py

import os
import json
import time
from datetime import datetime
import logging
from logging.handlers import RotatingFileHandler
from utils.setup_logger import create_logger  # optional override

# ---------------------------------------------------------
# CONFIG
# ---------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "xvectorpro.log")

# ---------------------------------------------------------
# LOGGER INITIALIZATION (idempotent)
# ---------------------------------------------------------

def _build_default_logger():
    logger = logging.getLogger("XVectorPro")
    
    if logger.handlers:   # prevents duplicate handlers
        return logger

    logger.setLevel(logging.INFO)

    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    # Console Output
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    # File Output (rotating)
    fh = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,
        backupCount=5
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


# ---------------------------------------------------------
# OPTIONAL CUSTOM LOGGER OVERRIDE
# ---------------------------------------------------------

logger = create_logger() or _build_default_logger()


# ---------------------------------------------------------
# STRUCTURED LOGGING WRAPPER
# ---------------------------------------------------------

def log_event(category: str, data, level: str = "info",
              write_structured_file: bool = False,
              log_dir: str = LOG_DIR):
    """
    Unified structured logging function.
    """

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    payload = {
        "time": time.time(),
        "category": category,
        "data": data
    }

    try:
        # convert payload to JSON
        json_msg = json.dumps(payload)

        # send to logger
        log_func = getattr(logger, level.lower(), logger.info)
        log_func(json_msg)

        # write structured JSON file if requested
        if write_structured_file:
            os.makedirs(log_dir, exist_ok=True)
            file_name = f"{category}_{timestamp}.json"
            full_path = os.path.join(log_dir, file_name)

            with open(full_path, "w") as f:
                json.dump(payload, f, indent=4)

            return full_path

    except Exception as e:
        logger.error(f"Logging failed: {e}")

    return LOG_FILE
