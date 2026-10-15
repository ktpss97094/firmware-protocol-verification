r"""
escape_sequence
1. The time interval between this transmission and the end of the previous UART transmission must be >= 1 second
2. The message must be +++
3. After transmission is complete, the time interval until the next UART transmission begins must be >= 1 second
"""

import angr
import archinfo
import avatar2
from angr import SimProcedure

from project import config, utils
from project.cores.base import BaseCPU
from project.peripherals.efm32gg11.usart import USART as EFM32GG11_USART
from project.types import BaseSpec, MemoryRegion


class USART(EFM32GG11_USART):
    def post_write(self, state):
        _, offset, value = super().post_write(state)

        char = chr(state.solver.eval(value))
        delta_time = state.globals.get("delay", 0) - state.globals.get(
            "last_tx_time", 0
        )

        match offset:
            case USART.USARTn_TXDATA.OFFSET:
                # --- Spec (Part 1) ---
                if char != "+":
                    state.project.verification.verify(state, "escape_sequence (spec 2)")
                elif state.globals.get("plus_cnt", 0) == 0:
                    state.project.verification.verify(
                        state,
                        "escape_sequence (spec 1)",
                        extra_constraints=[delta_time < 1000],
                    )
                elif state.globals.get("plus_cnt", 0) < 3:
                    state.project.verification.verify(
                        state,
                        "escape_sequence (spec 2)",
                        extra_constraints=[delta_time >= 1000],
                    )
                else:
                    state.project.verification.verify(state, "escape_sequence (spec 2)")

                state.globals["plus_cnt"] = state.globals.get("plus_cnt", 0) + 1
                state.globals["last_tx_time"] = state.globals.get("delay", 0)

        return _, offset, value


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
    OPENOCD_SCRIPT_PATH = str(config.PROJECT_ROOT / "openocd/stethogram.cfg")

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)
    ARCH = BaseCPU

    # --- Parameters ---
    PROPERTY_NAMES = [
        "escape_sequence (spec 1)",
        "escape_sequence (spec 2)",
        "escape_sequence (spec 3)",
    ]

    def _define_specs(self):
        self.MEMORY_REGIONS = {
            "RAM": MemoryRegion(start=0x20000000, size=0x80000, spec=self, name="RAM"),
            "FLASH": MemoryRegion(
                start=0x00000000, size=0x200000, spec=self, name="FLASH", transfer=False
            ),
            "USART0": USART(start=0x40010000, size=0x400, spec=self, name="USART0"),
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(self.proj, "LTE_SwitchToCmdMode")

    def init_inspect(self, state):
        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["USART0"].in_region_read,
            action=self.MEMORY_REGIONS["USART0"].post_read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["USART0"].in_region_write,
            action=self.MEMORY_REGIONS["USART0"].post_write,
        )

        # FIXME: Hooking functions can cause all the instructions used within them to be replaced, which may override the checks for interrupt points (such as before reading a global variable). For example, if hook Delay here, the call to read msTicks (a global variable) within it will be overridden. As long as there is an interrupt that could potentially alter msTicks, there is a risk of missing the validation in that path.
        self.proj.hook_symbol("Delay", Delay())

    def init_input(self, state):
        usartn_status = utils.load(
            state, self.MEMORY_REGIONS["USART0"].start + USART.USARTn_STATUS.OFFSET
        )
        new_usartn_status = utils.replace_bit(
            usartn_status,
            USART.USARTn_STATUS.TXBL,
            utils.generate_symbolic(state, f"{__name__}_TXBL", size=1),
        )
        utils.store(
            state,
            self.MEMORY_REGIONS["USART0"].start + USART.USARTn_STATUS.OFFSET,
            new_usartn_status,
        )

    def final(self, simgr):
        # --- Spec (Part 2) ---
        for state in simgr.found:
            delta_time = state.globals.get("delay", 0) - state.globals.get(
                "last_tx_time", 0
            )

            state.project.verification.verify(
                state, "escape_sequence (spec 3)", extra_constraints=[delta_time < 1000]
            )
