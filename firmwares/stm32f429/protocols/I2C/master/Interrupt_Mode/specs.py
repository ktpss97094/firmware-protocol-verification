"""
I2C Master Clock Stretching Spec

Precondition: SB, ADDR, ADD10, STOPF, BTF, TxE, RxNE, ITEVFEN, ITBUFEN symbolic
1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
2. write DR 前，若 TxE bit 為 0 且 BTF bit 為 0 且 SB bit 非必為 1 且 ADD10 非必為 1，則違反
3. Precondition: Size > 0
    set STOP bit 前，若 BTF bit 為 0，則違反

Symbolic Variables:
    SR2 (TRA)
    SR1 (SB, ADD10, ADDR, TxE, BTF)
"""

from enum import IntEnum

import angr
import archinfo
import avatar2

from project import config, utils
from project.types import BaseSpecs, MemoryRegion, MMIOMemoryRegion


class I2C(MMIOMemoryRegion):
    CR1_OFFSET = 0x00
    CR2_OFFSET = 0x04
    DR_OFFSET = 0x10
    SR1_OFFSET = 0x14
    SR2_OFFSET = 0x18

    CR1_STOP_MASK = 1 << 9
    CR1_START_MASK = 1 << 8

    CR2_ITEVTEN_MASK = 1 << 9

    SR1_AF_MASK = 1 << 10
    SR1_TXE_MASK = 1 << 7
    SR1_ADD10_MASK = 1 << 3
    SR1_BTF_MASK = 1 << 2
    SR1_ADDR_MASK = 1 << 1
    SR1_SB_MASK = 1 << 0

    SR2_TRA_MASK = 1 << 2
    SR2_BUSY_MASK = 1 << 1

    def read(self, state, offset):
        match offset:
            case self.SR1_OFFSET:
                # --- Side-Effects ---
                state.globals[f"{self.name}_SR1_read"] = True

            case self.SR2_OFFSET:
                # --- Spec 1 ---
                if state.globals.get(
                    f"{self.name}_SR1_read", False
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        utils.load(state, self.start + self.SR1_OFFSET)[1] == 0
                    ]
                ):
                    print("Found a violation path")
                    state.globals["violation"] = True

                # --- Side-Effects ---
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    utils.clear_bits(
                        state, self.start + self.SR1_OFFSET, I2C.SR1_ADDR_MASK
                    )

            case self.DR_OFFSET:
                # --- Side-Effects ---
                # (BTF) Cleared by software by either a read or write in the DR register
                utils.clear_bits(state, self.start + self.SR1_OFFSET, I2C.SR1_BTF_MASK)

    def write(self, state, offset, value):
        sr1 = utils.load(state, self.start + self.SR1_OFFSET)

        match offset:
            case self.CR1_OFFSET:
                # --- Spec 3 ---
                if not state.solver.satisfiable(
                    extra_constraints=[value[9] == 0]
                ) and state.solver.satisfiable(extra_constraints=[sr1[2] == 0]):
                    print("Found a violation path")
                    state.globals["violation"] = True

                # --- Side-Effects ---
                # set START bit 時進入 address phase
                if not state.solver.satisfiable(extra_constraints=[value[8] == 0]):
                    state.globals["is_address_phase"] = True

                    # (SB) Set when a Start condition generated
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    utils.set_symbolic(
                        state,
                        self.start + self.SR1_OFFSET,
                        I2C.SR1_SB_MASK | I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                        f"{self.name}_{self.SR1_OFFSET:#x}_SB/TxE/BTF",
                    )

                    # (TRA) It is also cleared by hardware after ..., repeated Start condition
                    utils.set_symbolic(
                        state,
                        self.start + self.SR2_OFFSET,
                        I2C.SR2_TRA_MASK,
                        f"{self.name}_{self.SR2_OFFSET:#x}_TRA",
                    )

                # set STOP bit
                if not state.solver.satisfiable(extra_constraints=[value[9] == 0]):
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    utils.set_symbolic(
                        state,
                        self.start + self.SR1_OFFSET,
                        I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                        f"{self.name}_{self.SR1_OFFSET:#x}_TxE/BTF",
                    )

                    # (TRA) It is also cleared by hardware after detection of Stop condition
                    utils.set_symbolic(
                        state,
                        self.start + self.SR2_OFFSET,
                        I2C.SR2_TRA_MASK,
                        f"{self.name}_{self.SR2_OFFSET:#x}_TRA",
                    )

            case self.DR_OFFSET:
                # --- Spec 2 ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        sr1[7] == 0,
                        sr1[2] == 0,
                        sr1[0] != 1,
                        sr1[3] != 1,
                    ]
                ):
                    print("Found a violation path")
                    state.globals["violation"] = True

                # --- Side-Effects ---
                if state.globals.get("is_address_phase", False):
                    # 10-bit addressing 的 addressing phase 會 write 兩次 DR。第一次 write (header) 時是 11110xxx
                    if not state.solver.satisfiable(
                        extra_constraints=[(value & 0xF8) != 0xF0]
                    ):
                        state.globals["is_10bit"] = True
                    else:
                        state.globals["is_address_phase"] = False

                        # (TRA) This bit is set depending on the R/W bit of the address byte, at the end of total address phase
                        if not state.solver.satisfiable(
                            extra_constraints=[(value & 1) != 0]
                        ):
                            utils.set_bits(
                                state, self.start + self.SR2_OFFSET, I2C.SR2_TRA_MASK
                            )
                        elif not state.solver.satisfiable(
                            extra_constraints=[(value & 1) != 1]
                        ):
                            utils.clear_bits(
                                state, self.start + self.SR2_OFFSET, I2C.SR2_TRA_MASK
                            )

                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either a read or write in the DR register
                utils.clear_bits(
                    state,
                    self.start + self.SR1_OFFSET,
                    I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                )

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    utils.clear_bits(
                        state, self.start + self.SR1_OFFSET, I2C.SR1_SB_MASK
                    )

                    if state.globals.get("is_10bit", False) and not state.globals.get(
                        "is_address_phase", False
                    ):
                        # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                        utils.clear_bits(
                            state, self.start + self.SR1_OFFSET, I2C.SR1_ADD10_MASK
                        )

                if state.globals.get("is_10bit", False) and state.globals.get(
                    "is_address_phase", False
                ):
                    # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                    utils.set_symbolic(
                        state,
                        self.start + self.SR1_OFFSET,
                        I2C.SR1_ADD10_MASK,
                        f"{self.name}_{self.SR1_OFFSET:#x}_ADD10",
                    )


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/stm32f429/build/protocols/I2C/master/Interrupt_Mode/stm32f4xx-hal-driver/firmware.elf"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Renode ---
    USE_RENODE = True

    # --- Constants ---
    class HAL_StatusTypeDef(IntEnum):
        HAL_OK = 0x00
        HAL_ERROR = 0x01
        HAL_BUSY = 0x02
        HAL_TIMEOUT = 0x03

    def _define_specs(self):
        self.MEMORY_REGIONS = {
            "RAM": MemoryRegion(start=0x20000000, size=0x30000, name="RAM"),
            "CCMRAM": MemoryRegion(start=0x10000000, size=0x10000, name="CCMRAM"),
            "FLASH": MemoryRegion(
                start=0x08000000, size=0x200000, name="FLASH", transfer=False
            ),
            "VECTOR_TABLE_ALIAS": MemoryRegion(
                start=0x00000000,
                size=0x400,
                name="VECTOR_TABLE_ALIAS",
                physical_addr=0x08000000,
            ),
            "I2C1": I2C(start=0x40005400, size=0x400, name="I2C1"),
            "DMA1": MMIOMemoryRegion(start=0x40026000, size=0x400, name="DMA1"),
        }

        self.SYMBOLIC_MASKS = {
            0x40005414: 0b00000000000000000000000000001011,
            0x40005418: 0b00000000000000000000000000000100,
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj, "I2C1_EV_IRQHandler", is_variable=False
        )
        self.END_ADDRS = [
            0xFFFFFFF1,
            0xFFFFFFF9,
            0xFFFFFFFD,
        ]  # ARMv7-M Architecture Reference Manual §B1.5.8 Exception return behavior
        # self.DEBUG_FUNC_ADDR = utils.get_symbol_addr(self.proj, "SYMBOL_FUNCTION", is_variable=False)

    def init_inspect(self, state):
        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_read,
            action=self.MEMORY_REGIONS["I2C1"].read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_write,
            action=self.MEMORY_REGIONS["I2C1"].write,
        )

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )
