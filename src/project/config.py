import avatar2
import archinfo
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

"""
Path
"""
FIRMWARE_PATH = str(
    PROJECT_ROOT / "firmwares/STM32/I2C/Interrupt_Mode/HAL/build/clockstretching.elf"
)
AVATAR_LOG_PATH = "/tmp/avatar"
OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

"""
Architecture
"""
AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

"""
Renode
"""
USE_RENODE = True
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
