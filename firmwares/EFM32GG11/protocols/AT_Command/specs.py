"""
Stethogram AT Command Escape Sequence Spec

1. 此次發送距離上一次 UART 傳輸結束的時間間隔必須 >= 1 秒
2. 發送內容須為 +++
3. 發送結束後，距離下一次 UART 傳輸開始的時間間隔必須 >= 1 秒
"""

import angr
import archinfo
import avatar2
import claripy
from angr import SimProcedure

from project import config, utils
from project.types import BaseSpecs, MemoryRegion, MMIOMemoryRegion


class USART(MMIOMemoryRegion):
    class USARTn_STATUS:
        OFFSET = 0x010

        TXBL = 6  # 1 為 TX buffer empty

    class USARTn_TXDATA:
        OFFSET = 0x034

    def read(self, state, offset):
        usartn_status = utils.load(state, self.start + USART.USARTn_STATUS.OFFSET)
        new_usartn_status = usartn_status

        match offset:
            case self.USARTn_STATUS.OFFSET:
                # 不需要先判斷 TXBL 是不是 symbolic，這跟 STM32 I2C ADDR 等狀況不同，ADDR 是在設為 symbolic 後才有這個 replace_bit 規則，但 TXBL 是任何時候這個規則都成立
                new_usartn_status = utils.replace_bit(
                    new_usartn_status,
                    USART.USARTn_STATUS.TXBL,
                    claripy.If(
                        new_usartn_status[USART.USARTn_STATUS.TXBL] == 1,
                        new_usartn_status[USART.USARTn_STATUS.TXBL],
                        utils.generate_symbolic(
                            state,
                            f"{self.name}_{USART.USARTn_STATUS.OFFSET:#x}_TXBL",
                            size=1,
                        ),
                    ),
                )

        utils.store(state, self.start + USART.USARTn_STATUS.OFFSET, new_usartn_status)

    def write(self, state, offset, value):
        usartn_status = utils.load(state, self.start + USART.USARTn_STATUS.OFFSET)
        new_usartn_status = usartn_status
        char = chr(state.solver.eval(value))
        delta_time = state.globals.get("delay", 0) - state.globals.get(
            "last_tx_time", 0
        )

        match offset:
            case self.USARTn_TXDATA.OFFSET:
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

                new_usartn_status = utils.symbolic_bit(
                    state,
                    new_usartn_status,
                    USART.USARTn_STATUS.TXBL,
                    f"{self.name}_{USART.USARTn_STATUS.OFFSET:#x}_TXBL",
                )

        utils.store(state, self.start + USART.USARTn_STATUS.OFFSET, new_usartn_status)


class Delay(SimProcedure):
    def run(self, dlyTicks):
        self.state.globals["delay"] = self.state.globals.get(
            "delay", 0
        ) + self.state.solver.eval(dlyTicks)


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/EFM32GG11/protocols/AT_Command/Stethogram/copd-master/COPD/Debug/exe/COPD.out"
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

        self.proj.hook_symbol("Delay", Delay())

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )

    def precondition(self, state):
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

        return True

    def postcondition(self, simgr):
        # [Spec (Part 2)]
        for state in simgr.found:
            delta_time = state.globals.get("delay", 0) - state.globals.get(
                "last_tx_time", 0
            )

            if delta_time < 1000:
                print("Spec violation")
                simgr.stashes["violated"].append(state)
