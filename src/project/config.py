from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

"""
avatar2
"""
AVATAR_LOG_PATH = str(LOG_DIR / "avatar")

"""
Renode
"""
RENODE_GDB_PORT = 3333

"""
Logging
"""
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "datefmt": "%H:%M:%S",
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
        "file": {
            "class": "logging.FileHandler",
            "filename": str(LOG_DIR / "project.log"),
            "formatter": "standard",
            "level": "DEBUG",
            "encoding": "utf-8",
        },
    },
    "loggers": {
        "": {"handlers": ["console", "file"], "level": "WARNING"},
        __package__: {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
        "__main__": {
            "handlers": ["console", "file"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
