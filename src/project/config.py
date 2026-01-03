import avatar2
import archinfo
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

"""
Path
"""
FIRMWARE_PATH = str(
    PROJECT_ROOT / "firmwares/STM32/I2C/DMA_Mode/build/clockstretching.elf"
)
AVATAR_LOG_PATH = "/tmp/avatar"
OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

"""
Architecture
"""
AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)
THUMB_MODE = True

"""
Symbolic Execution
"""
BEGIN_SYMBOL = "HAL_I2C_EV_IRQHandler"
END_SYMBOL = "END_SYMBOLIC_EXECUTION"
# SYSTICK_VARIABLE_SYMBOL = "uwTick"

"""
Renode
"""
USE_RENODE = True
RENODE_GDB_PORT = 3333
