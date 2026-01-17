from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

"""
avatar2
"""
AVATAR_LOG_PATH = "/tmp/avatar"

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
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
            "level": "INFO",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": "WARNING",
        },
        __package__: {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}
