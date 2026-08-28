"""
Stethogram AT Command Escape Sequence Spec

1. 此次發送距離上一次 UART 傳輸結束的時間間隔必須 >= 1 秒
2. 發送內容須為 +++
3. 發送結束後，距離下一次 UART 傳輸開始的時間間隔必須 >= 1 秒
"""

import angr
import archinfo
import avatar2
from angr import SimProcedure

from project import config, utils
from project.peripherals.efm32gg11.usart import USART as EFM32GG11_USART
from project.types import BaseSpec, MemoryRegion


class USART(EFM32GG11_USART):
    def post_write_spec(self, state, offset, value):
        char = chr(state.solver.eval(value))
        delta_time = state.globals.get("delay", 0) - state.globals.get(
            "last_tx_time", 0
        )

        match offset:
            case USART.USARTn_TXDATA.OFFSET:
                # [Spec (Part 1)]
                if char != "+":
                    print(f"Spec violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True
                elif state.globals.get("plus_cnt", 0) == 0:
                    if delta_time < 1000:
                        print(f"Spec violation (pc: {state.regs.pc})")
                        state.globals["violation"] = True
                elif state.globals.get("plus_cnt", 0) < 3:
                    if delta_time >= 1000:
                        print(f"Spec violation (pc: {state.regs.pc})")
                        state.globals["violation"] = True
                else:
                    print(f"Spec violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True

                state.globals["plus_cnt"] = state.globals.get("plus_cnt", 0) + 1
                state.globals["last_tx_time"] = state.globals.get("delay", 0)


class Delay(SimProcedure):
    def run(self, dlyTicks):
        self.state.globals["delay"] = self.state.globals.get(
            "delay", 0
        ) + self.state.solver.eval(dlyTicks)


class Specs(BaseSpec):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/efm32gg11/protocols/AT_Command/Stethogram/copd-master/COPD/Debug/exe/COPD.out"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = str(
        config.PROJECT_ROOT / "openocd/scripts/interface/jlink.cfg"
    )
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
            "USART0": USART(start=0x40010000, size=0x400, name="USART0"),
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj, "LTE_SwitchToCmdMode", is_variable=False
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
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["USART0"].in_region_read,
            action=self.MEMORY_REGIONS["USART0"].read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["USART0"].in_region_write,
            action=self.MEMORY_REGIONS["USART0"].write,
        )

        """
        FIXME: hook function 等會造成把裡面使用的指令全部被取代，有可能會覆蓋掉 interrupt point 的檢查 (例如 global variable read 前)
        例如這裡 hook Delay 的話，裡面 read msTicks (global variable) 就會被覆蓋。只要有 interrupt 有可能會改變 msTicks，就可能會漏掉驗證可能的路徑
        """
        self.proj.hook_symbol("Delay", Delay())

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )

    def init_input(self, state):
        usartn_status = utils.load(
            state, self.MEMORY_REGIONS["USART0"].start + USART.USARTn_STATUS.OFFSET
        )
        new_usartn_status = utils.symbolic_bit(
            state,
            usartn_status,
            USART.USARTn_STATUS.TXBL,
            f"{__name__}_{USART.USARTn_STATUS.OFFSET:#x}_TXBL",
        )
        utils.store(
            state,
            self.MEMORY_REGIONS["USART0"].start + USART.USARTn_STATUS.OFFSET,
            new_usartn_status,
        )

    def final(self, simgr):
        # [Spec (Part 2)]
        for state in simgr.found:
            delta_time = state.globals.get("delay", 0) - state.globals.get(
                "last_tx_time", 0
            )

            if delta_time < 1000:
                print("Spec violation")
                simgr.stashes["violated"].append(state)
