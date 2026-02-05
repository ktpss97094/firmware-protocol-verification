"""
Stethogram AT Command Escape Sequence Spec

1. send_escape_sequence() 執行時:
    (1) 此次發送距離上一次 UART 傳輸結束的時間間隔必須 >= 1 秒
    (2) 發送內容須為 +++
    (3) 發送結束後，距離下一次 UART 傳輸開始的時間間隔必須 >= 1 秒
"""

import angr
import archinfo
import avatar2

from project import config, utils
from project.types import (
    BaseSpecs,
    MemoryRegion,
    MMIOMemoryRegion,
    VariableMemoryRegion,
)


class SysTickVariable(VariableMemoryRegion):
    def read(self, state, offset):
        origin_val = utils.load(state, self.start + offset)

        # new_val = utils.generate_symbolic(state, self.name)
        # state.add_constraints(new_val > origin_val)
        delta = 1

        new_val = origin_val + delta

        utils.store(state, self.start + offset, new_val)


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT / "firmwares/Stethogram/copd-master/COPD/Debug/exe/COPD.out"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = "openocd/scripts/interface/jlink.cfg"
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/efm32.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Renode ---
    USE_RENODE = False

    # --- Constants ---

    def _define_specs(self):
        self.MEMORY_REGIONS = {
            "RAM": MemoryRegion(start=0x20000000, size=0x80000, name="RAM"),
            "FLASH": MemoryRegion(
                start=0x00000000, size=0x200000, name="FLASH", transfer=False
            ),
            "USART0": MMIOMemoryRegion(start=0x40010000, size=0x400, name="USART0"),
            "SysTickVariable": SysTickVariable(
                start=utils.get_symbol_addr(self.proj, "msTicks", is_variable=True),
                size=0x4,
                name="SysTickVariable",
            ),
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj, "BEGIN_SYMBOLIC_EXECUTION", is_variable=False
        )
        self.END_ADDRS = [
            utils.get_symbol_addr(
                self.proj, "END_SYMBOLIC_EXECUTION", is_variable=False
            )
        ]
        # self.DEBUG_FUNC_ADDR = utils.get_symbol_addr(self.proj, "SYMBOL_FUNCTION", is_variable=False)

    def init_inspect(self, state):
        state.inspect.b(
            "mem_read",
            when=angr.BP_BEFORE,
            condition=self.MEMORY_REGIONS["SysTickVariable"].in_region_read,
            action=self.MEMORY_REGIONS["SysTickVariable"].read,
        )

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )
