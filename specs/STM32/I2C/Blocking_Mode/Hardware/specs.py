"""
I2C Master Clock Stretching Spec

1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
2. write DR 前，若 TxE bit 為 0 且 BTF bit 為 0 且 SB bit 非必為 1 且 ADD10 非必為 1，則違反
3. Precondition: Size > 0
    set STOP bit 前，若 BTF bit 為 0 且回傳 HAL_OK，則違反

Symbolic Variables:
    SR2 (BUSY)
    uwTick
    SR1 (SB, ADD10, AF, ADDR, TxE, BTF)
    CR1 STOP
"""

import angr
import claripy
import avatar2
import archinfo
from angr.sim_type import SimTypeInt
from enum import IntEnum
from project.types import (
    MemoryRegion,
    MMIOMemoryRegion,
    VariableMemoryRegion,
    BaseSpecs,
)
from project import utils, config


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
        sr1 = utils.load(state, self.start + I2C.SR1_OFFSET)
        sr2 = utils.load(state, self.start + I2C.SR2_OFFSET)

        match offset:
            case I2C.SR1_OFFSET:
                # --- Side-Effects ---
                state.globals[f"{self.name}_SR1_read"] = True

                new_sr1 = sr1
                new_sr2 = sr2
                if sr1[1].symbolic:
                    """
                    當 ADDR 變成 symbolic (表示可能是 0/1) 後，將新的 ADDR 記憶體值設定成:
                        * 舊值是 0 => 新值是 symbolic variable
                        * 舊值是 1 => 新值是 concrete 1
                    """
                    new_sym = utils.generate_symbolic(
                        state,
                        I2C.SR1_ADDR_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_ADDR",
                    )
                    new_sr1 = (new_sr1 & ~I2C.SR1_ADDR_MASK) | claripy.If(
                        sr1[1] == 0, new_sym, I2C.SR1_ADDR_MASK
                    )
                if sr1[0].symbolic:
                    new_sym = utils.generate_symbolic(
                        state,
                        I2C.SR1_SB_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_SB",
                    )
                    new_sr1 = (new_sr1 & ~I2C.SR1_SB_MASK) | claripy.If(
                        sr1[0] == 0, new_sym, I2C.SR1_SB_MASK
                    )
                    # (BUSY) Set by hardware on detection of SDA or SCL low
                    new_sr2 = (new_sr2 & ~I2C.SR2_BUSY_MASK) | claripy.If(
                        new_sr1[0] == 1,
                        I2C.SR2_BUSY_MASK,
                        sr2 & I2C.SR2_BUSY_MASK,
                    )
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = (
                        new_sr1 & ~(I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK)
                    ) & claripy.If(
                        new_sr1[0] == 1,
                        ~(I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK),
                        claripy.BVV(0xFFFFFFFF, state.arch.bits),
                    )
                if sr1[3].symbolic:
                    new_sym = utils.generate_symbolic(
                        state,
                        I2C.SR1_ADD10_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_ADD10",
                    )
                    new_sr1 = (new_sr1 & ~I2C.SR1_ADD10_MASK) | claripy.If(
                        sr1[3] == 0, new_sym, I2C.SR1_ADD10_MASK
                    )
                if sr1[10].symbolic:
                    new_sym = utils.generate_symbolic(
                        state,
                        I2C.SR1_AF_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_AF",
                    )
                    new_sr1 = (new_sr1 & ~I2C.SR1_AF_MASK) | claripy.If(
                        sr1[10] == 0, new_sym, I2C.SR1_AF_MASK
                    )
                if sr1[7].symbolic:
                    new_sym = utils.generate_symbolic(
                        state,
                        I2C.SR1_TXE_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_TxE",
                    )
                    new_sr1 = (new_sr1 & ~I2C.SR1_TXE_MASK) | claripy.If(
                        sr1[7] == 0, new_sym, I2C.SR1_TXE_MASK
                    )
                if sr1[2].symbolic:
                    new_sym = utils.generate_symbolic(
                        state,
                        I2C.SR1_BTF_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_BTF",
                    )
                    new_sr1 = (new_sr1 & ~I2C.SR1_BTF_MASK) | claripy.If(
                        sr1[2] == 0, new_sym, I2C.SR1_BTF_MASK
                    )
                utils.store(state, self.start + I2C.SR1_OFFSET, new_sr1)
                utils.store(state, self.start + I2C.SR2_OFFSET, new_sr2)

            case I2C.SR2_OFFSET:
                # --- Spec 1 ---
                if state.globals.get(
                    f"{self.name}_SR1_read", False
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        utils.load(state, self.start + I2C.SR1_OFFSET)[1] == 0
                    ]
                ):
                    print("Found a violation path")
                    state.globals["violation"] = True

                # --- Side-Effects ---
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    utils.clear_bits(
                        state, self.start + I2C.SR1_OFFSET, I2C.SR1_ADDR_MASK
                    )

            case I2C.DR_OFFSET:
                # --- Side-Effects ---
                # (BTF) Cleared by software by either a read or write in the DR register
                utils.clear_bits(state, self.start + I2C.SR1_OFFSET, I2C.SR1_BTF_MASK)

    def write(self, state, offset, value):
        sr1 = utils.load(state, self.start + I2C.SR1_OFFSET)
        sr2 = utils.load(state, self.start + I2C.SR2_OFFSET)

        match offset:
            case I2C.CR1_OFFSET:
                # --- Spec 3 (Part 1) ---
                if not state.solver.satisfiable(
                    extra_constraints=[value[9] == 0]
                ) and state.solver.satisfiable(extra_constraints=[sr1[2] == 0]):
                    state.globals["spec3_violation_pending"] = True

                # --- Side-Effects ---
                # set START bit 時進入 address phase
                if not state.solver.satisfiable(extra_constraints=[value[8] == 0]):
                    state.globals["is_address_phase"] = True

                    # (SB) Set when a Start condition generated
                    utils.set_symbolic(
                        state,
                        self.start + I2C.SR1_OFFSET,
                        I2C.SR1_SB_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_SB",
                    )

                # set STOP bit
                if not state.solver.satisfiable(extra_constraints=[value[9] == 0]):
                    # (STOP) cleared by hardware when a Stop condition is detected
                    utils.set_symbolic(
                        state,
                        self.start + I2C.CR1_OFFSET,
                        I2C.CR1_STOP_MASK,
                        f"{self.name}_{I2C.CR1_OFFSET:#x}_STOP",
                    )
                    new_cr1 = utils.load(state, self.start + I2C.CR1_OFFSET)
                    new_sr1 = sr1
                    new_sr2 = sr2
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = (
                        new_sr1 & ~(I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK)
                    ) & claripy.If(
                        new_cr1[9] == 0,
                        ~(I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK),
                        claripy.BVV(0xFFFFFFFF, state.arch.bits),
                    )
                    # (BUSY) cleared by hardware on detection of a Stop condition
                    new_sr2 = (new_sr2 & ~I2C.SR2_BUSY_MASK) & claripy.If(
                        new_cr1[9] == 0,
                        ~I2C.SR2_BUSY_MASK,
                        claripy.BVV(0xFFFFFFFF, state.arch.bits),
                    )
                    utils.store(state, self.start + I2C.SR1_OFFSET, new_sr1)
                    utils.store(state, self.start + I2C.SR2_OFFSET, new_sr2)

            case I2C.DR_OFFSET:
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

                        # (ADDR) For 10-bit addressing, the bit is set after the ACK of the 2nd byte. For 7-bit addressing, the bit is set after the ACK of the byte
                        utils.set_symbolic(
                            state,
                            self.start + I2C.SR1_OFFSET,
                            I2C.SR1_ADDR_MASK,
                            f"{self.name}_{I2C.SR1_OFFSET:#x}_ADDR",
                        )
                else:
                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_TxE = utils.set_symbolic(
                        state,
                        self.start + I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_TxE",
                    )

                    # (BTF) Set ... In transmission when a new byte should be sent and DR has not been written yet (TxE=1)
                    new_sr1 = sr1
                    new_sr1 = (new_sr1 & ~I2C.SR1_BTF_MASK) | claripy.If(
                        new_TxE == 1,
                        I2C.SR1_BTF_MASK,
                        claripy.BVV(0x00000000, state.arch.bits),
                    )
                    utils.store(state, self.start + I2C.SR1_OFFSET, new_sr1)

                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either a read or write in the DR register
                utils.clear_bits(
                    state,
                    self.start + I2C.SR1_OFFSET,
                    I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                )

                # (AF) Set by hardware when no acknowledge is returned
                utils.set_symbolic(
                    state,
                    self.start + I2C.SR1_OFFSET,
                    I2C.SR1_AF_MASK,
                    f"{self.name}_{I2C.SR1_OFFSET:#x}_AF",
                )

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    utils.clear_bits(
                        state, self.start + I2C.SR1_OFFSET, I2C.SR1_SB_MASK
                    )

                    if state.globals.get("is_10bit", False) and not state.globals.get(
                        "is_address_phase", False
                    ):
                        # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                        utils.clear_bits(
                            state, self.start + I2C.SR1_OFFSET, I2C.SR1_ADD10_MASK
                        )

                if state.globals.get("is_10bit", False) and state.globals.get(
                    "is_address_phase", False
                ):
                    # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                    utils.set_symbolic(
                        state,
                        self.start + I2C.SR1_OFFSET,
                        I2C.SR1_ADD10_MASK,
                        f"{self.name}_{I2C.SR1_OFFSET:#x}_ADD10",
                    )


class SysTickVariable(VariableMemoryRegion):
    def read(self, state, offset):
        origin_val = utils.load(state, self.start + offset)

        # new_val = utils.generate_symbolic(
        #     state, self.symbolic_masks.get(self.start + offset, 0), self.name
        # )
        # state.add_constraints(
        #     claripy.Or(new_val == origin_val, new_val == origin_val + 25 + 1)
        # )
        delta = 1

        new_val = origin_val + delta

        utils.store(state, self.start + offset, new_val)
        state.inspect.mem_read_expr = new_val


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/STM32/I2C/Blocking_Mode/Hardware/HAL/build/clockstretching.elf"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Renode ---
    USE_RENODE = False

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
            "SysTickVariable": SysTickVariable(
                start=utils.get_symbol_addr(self.proj, "uwTick", is_variable=True),
                size=0x4,
                name="SysTickVariable",
            ),
        }

        self.SYMBOLIC_MASKS = {
            0x40005414: 0b00000000000000000000010010001111,
            0x40005418: 0b00000000000000000000000000000010,
            self.MEMORY_REGIONS[
                "SysTickVariable"
            ].start: 0b11111111111111111111111111111111,
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj,
            "HAL_I2C_Master_Transmit",
            is_variable=False,
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
            condition=self.MEMORY_REGIONS["I2C1"].in_region_read,
            action=self.MEMORY_REGIONS["I2C1"].read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_write,
            action=self.MEMORY_REGIONS["I2C1"].write,
        )

        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["SysTickVariable"].in_region_read,
            action=self.MEMORY_REGIONS["SysTickVariable"].read,
        )

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )

    def precondition(self, state):
        # utils.set_func_args_symbolic(self.proj, state, 5, {3: (0, 3)})

        return True

    def postcondition(self, simgr):
        # [Spec 3 (Part 2)]
        for state in simgr.found:
            return_val = state.solver.eval(
                self.proj.factory.cc().return_val(SimTypeInt()).get_value(state)
            )

            if return_val == self.HAL_StatusTypeDef.HAL_OK and state.globals.get(
                "spec3_violation_pending", False
            ):
                print("Found a violation path")
                simgr.stashes["violated"].append(state)
