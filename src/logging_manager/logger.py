"""
CENTINELA – Structured logging with file rotation.

Levels used:
  INFO    – normal operational events
  WARNING – anomalies that may not need immediate action
  ALERT   – security events needing attention (maps to WARNING in stdlib)
  CRITICAL – severe threats requiring immediate response
"""
import logging
import logging.handlers
import os
import sys
from pathlib import Path


# Custom ALERT level sits between WARNING and ERROR
ALERT_LEVEL = 35
logging.addLevelName(ALERT_LEVEL, "ALERT")


def _alert(self, msg, *args, **kwargs):
    if self.isEnabledFor(ALERT_LEVEL):
        self._log(ALERT_LEVEL, msg, args, **kwargs)


# Patch the base Logger class so ALL instances (even those created before
# this module was imported) have the .alert() method.
logging.Logger.alert = _alert  # type: ignore[attr-defined]


class CentinelaLogger(logging.Logger):
    pass


logging.setLoggerClass(CentinelaLogger)


class _ColorFormatter(logging.Formatter):
    """ANSI colors for console output."""
    COLORS = {
        logging.DEBUG:    "\033[36m",   # cyan
        logging.INFO:     "\033[32m",   # green
        logging.WARNING:  "\033[33m",   # yellow
        ALERT_LEVEL:      "\033[35m",   # magenta
        logging.ERROR:    "\033[31m",   # red
        logging.CRITICAL: "\033[41m",   # red background
    }
    RESET = "\033[0m"

    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logging(log_dir: str = "/app/logs",
                  log_level: str = "INFO") -> logging.Logger:
    """
    Configure the root 'centinela' logger with:
      - Console handler (colored)
      - Rotating file handler for all levels  (centinela.log)
      - Rotating file handler for ALERT+      (centinela-alerts.log)

    Returns the root centinela logger.
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root = logging.getLogger("centinela")
    root.setLevel(logging.DEBUG)  # capture everything; handlers filter

    if root.handlers:
        return root  # already set up (avoid duplicate handlers on reload)

    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    datefmt = "%Y-%m-%dT%H:%M:%S"

    # --- Console ---
    console_stream = open(sys.stdout.fileno(), mode='w', encoding='utf-8', closefd=False, buffering=1) if hasattr(sys.stdout, 'fileno') else sys.stdout
    console_handler = logging.StreamHandler(console_stream)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(_ColorFormatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(console_handler)

    # --- All-levels rotating file (10 MB × 5 backups) ---
    all_handler = logging.handlers.RotatingFileHandler(
        log_path / "centinela.log",
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    all_handler.setLevel(logging.INFO)
    all_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(all_handler)

    # --- Alerts-only rotating file (20 MB × 10 backups) ---
    alert_handler = logging.handlers.RotatingFileHandler(
        log_path / "centinela-alerts.log",
        maxBytes=20 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    alert_handler.setLevel(ALERT_LEVEL)
    alert_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(alert_handler)

    # Silence noisy third-party loggers
    for noisy in ("docker", "urllib3", "asyncio", "aiohttp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    root.info("Logging initialised -> %s", log_path)
    return root
