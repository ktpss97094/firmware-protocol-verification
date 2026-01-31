"""
I2C Master Clock Stretching Spec

1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
2. write DR 前，若 TxE bit 為 0 且 SB bit 非必為 1 且 ADD10 非必為 1，則違反
    * SB bit 必為 1 或 ADD10 必為 1 時表示 address phase，TxE 不會 set
3. Precondition: Size > 0
    set STOP bit 前，若 BTF bit 為 0 且回傳 HAL_OK，則違反
        * Size == 0 時只會送 address，BTF 不會 set
        * HAL_OK: 不考慮 acknowledge failure、timeout 等造成的 set STOP bit

Symbolic Variables:
    SR2 (BUSY)
    uwTick
    SR1 (SB, ADD10, AF, ADDR, TxE, BTF)
    CR1 STOP
"""

import angr
import archinfo
import avatar2
import claripy
from angr.sim_type import (
    SimStruct,
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
    SimTypeShort,
)

from project import config, utils
from project.types import (
    BaseSpecs,
    MemoryRegion,
    MMIOMemoryRegion,
    VariableMemoryRegion,
)


class I2C(MMIOMemoryRegion):
    class CR1:
        OFFSET = 0x00

        STOP = 9
        START = 8

    class CR2:
        OFFSET = 0x04

        ITEVTEN = 9

    class DR:
        OFFSET = 0x10

    class SR1:
        OFFSET = 0x14

        AF = 10
        TXE = 7
        ADD10 = 3
        BTF = 2
        ADDR = 1
        SB = 0

    class SR2:
        OFFSET = 0x18

        TRA = 2
        BUSY = 1

    def read(self, state, offset):
        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)
        sr2 = utils.load(state, self.start + I2C.SR2.OFFSET)
        new_sr1 = sr1
        new_sr2 = sr2

        match offset:
            case I2C.SR1.OFFSET:
                # --- Side-Effects ---
                state.globals[f"{self.name}_SR1_read"] = True

                if sr1[I2C.SR1.ADDR].symbolic:
                    """
                    當 ADDR 變成 symbolic (表示可能是 0/1) 後，將新的 ADDR 記憶體值設定成:
                        * 舊值是 0 => 新值是 symbolic variable
                        * 舊值是 1 => 新值不變
                    """
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.ADDR,
                        claripy.If(
                            sr1[I2C.SR1.ADDR] == 1,
                            sr1[I2C.SR1.ADDR],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_ADDR", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.SB].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.SB,
                        claripy.If(
                            sr1[I2C.SR1.SB] == 1,
                            sr1[I2C.SR1.SB],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_SB", size=1
                            ),
                        ),
                    )

                    # (BUSY) Set by hardware on detection of SDA or SCL low
                    # new_sr2 = utils.replace_bit(
                    #     new_sr2,
                    #     I2C.SR2.BUSY,
                    #     claripy.If(new_sr1[I2C.SR1.SB] == 1, 1, sr2[I2C.SR2.BUSY]),
                    # )
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.TXE,
                        claripy.If(new_sr1[I2C.SR1.SB] == 1, 0, sr1[I2C.SR1.TXE]),
                    )
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(new_sr1[I2C.SR1.SB] == 1, 0, sr1[I2C.SR1.BTF]),
                    )
                if sr1[I2C.SR1.ADD10].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.ADD10,
                        claripy.If(
                            sr1[I2C.SR1.ADD10] == 1,
                            sr1[I2C.SR1.ADD10],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_ADD10", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.AF].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.AF,
                        claripy.If(
                            sr1[I2C.SR1.AF] == 1,
                            sr1[I2C.SR1.AF],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_AF", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.TXE].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.TXE,
                        claripy.If(
                            sr1[I2C.SR1.TXE] == 1,
                            sr1[I2C.SR1.TXE],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_TxE", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.BTF].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(
                            sr1[I2C.SR1.BTF] == 1,
                            sr1[I2C.SR1.BTF],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_BTF", size=1
                            ),
                        ),
                    )

            case I2C.SR2.OFFSET:
                # --- Spec 1 ---
                if state.globals.get(
                    f"{self.name}_SR1_read", False
                ) and state.solver.satisfiable(extra_constraints=[sr1[1] == 0]):
                    print(f"Spec 1 violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True

                # --- Side-Effects ---
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.ADDR)
                    # clear ADDR 時結束 address phase
                    state.globals["is_address_phase"] = False

                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_sr1 = utils.set_bits(new_sr1, I2C.SR1.TXE)

                # if sr2[I2C.SR2.BUSY].symbolic:
                #     new_sr2 = utils.symbolic_bit(
                #         state,
                #         new_sr2,
                #         I2C.SR2.BUSY,
                #         f"{self.name}_{I2C.SR2.OFFSET:#x}_BUSY",
                #     )

            case I2C.DR.OFFSET:
                # --- Side-Effects ---
                # (BTF) Cleared by software by either a read or write in the DR register
                new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.BTF)

        utils.store(state, self.start + I2C.SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.SR2.OFFSET, new_sr2)

    def write(self, state, offset, value):
        cr1 = utils.load(state, self.start + I2C.CR1.OFFSET)
        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)
        sr2 = utils.load(state, self.start + I2C.SR2.OFFSET)
        new_cr1 = cr1
        new_sr1 = sr1
        new_sr2 = sr2

        match offset:
            case I2C.CR1.OFFSET:
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
                    new_sr1 = utils.symbolic_bit(
                        state,
                        new_sr1,
                        I2C.SR1.SB,
                        f"{self.name}_{I2C.SR1.OFFSET:#x}_SB",
                    )

                # set STOP bit
                if not state.solver.satisfiable(extra_constraints=[value[9] == 0]):
                    # (STOP) cleared by hardware when a Stop condition is detected
                    new_cr1 = utils.symbolic_bit(
                        state,
                        new_cr1,
                        I2C.CR1.STOP,
                        f"{self.name}_{I2C.CR1.OFFSET:#x}_STOP",
                    )

                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.TXE,
                        claripy.If(new_cr1[I2C.CR1.STOP] == 0, 0, sr1[I2C.SR1.TXE]),
                    )
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(new_cr1[I2C.CR1.STOP] == 0, 0, sr1[I2C.SR1.BTF]),
                    )
                    # (BUSY) cleared by hardware on detection of a Stop condition
                    # new_sr2 = utils.replace_bit(
                    #     new_sr2,
                    #     I2C.SR2.BUSY,
                    #     claripy.If(new_cr1[I2C.CR1.STOP] == 0, 0, sr2[I2C.SR2.BUSY]),
                    # )

            case I2C.DR.OFFSET:
                # --- Spec 2 ---
                if state.solver.satisfiable(
                    extra_constraints=[sr1[7] == 0, sr1[0] != 1, sr1[3] != 1]
                ):
                    print(f"Spec 2 violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True

                # --- Side-Effects ---
                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either a read or write in the DR register
                new_sr1 = utils.clear_bits(new_sr1, [I2C.SR1.TXE, I2C.SR1.BTF])

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.SB)

                # (AF) Set by hardware when no acknowledge is returned
                new_sr1 = utils.symbolic_bit(
                    state, new_sr1, I2C.SR1.AF, f"{self.name}_{I2C.SR1.OFFSET:#x}_AF"
                )

                if state.globals.get("is_address_phase", False):
                    # 10-bit addressing 的 addressing phase 會 write 兩次 DR。第一次 write (header) 時是 11110xxx
                    if not state.solver.satisfiable(
                        extra_constraints=[(value & 0xF8) != 0xF0]
                    ):
                        state.globals["is_10bit"] = True

                        # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                        new_sr1 = utils.symbolic_bit(
                            state,
                            new_sr1,
                            I2C.SR1.ADD10,
                            f"{self.name}_{I2C.SR1.OFFSET:#x}_ADD10",
                        )
                    else:
                        if state.globals.get("is_10bit", False) and state.globals.get(
                            f"{self.name}_SR1_read", False
                        ):
                            state.globals[f"{self.name}_SR1_read"] = False

                            # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                            new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.ADD10)

                        # (ADDR) For 10-bit addressing, the bit is set after the ACK of the 2nd byte. For 7-bit addressing, the bit is set after the ACK of the byte
                        new_sr1 = utils.symbolic_bit(
                            state,
                            new_sr1,
                            I2C.SR1.ADDR,
                            f"{self.name}_{I2C.SR1.OFFSET:#x}_ADDR",
                        )
                else:
                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_sr1 = utils.symbolic_bit(
                        state,
                        new_sr1,
                        I2C.SR1.TXE,
                        f"{self.name}_{I2C.SR1.OFFSET:#x}_TxE",
                    )

                    # (BTF) Set ... In transmission when a new byte should be sent and DR has not been written yet (TxE=1)
                    # 只有 TxE 是 1 時，BTF 才可能是 1
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(
                            new_sr1[I2C.SR1.TXE] == 0,
                            new_sr1[I2C.SR1.BTF],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_BTF", size=1
                            ),
                        ),
                    )

        utils.store(state, self.start + I2C.CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.SR2.OFFSET, new_sr2)


class SysTickVariable(VariableMemoryRegion):
    def read(self, state, offset):
        origin_val = utils.load(state, self.start + offset)

        # new_val = utils.generate_symbolic(
        #     state, self.name, mask=self.symbolic_masks.get(self.start + offset, 0)
        # )
        # state.add_constraints(new_val > origin_val)
        delta = 1

        new_val = origin_val + delta

        utils.store(state, self.start + offset, new_val)


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
    class HAL_StatusTypeDef:
        """
        .. warning::
            不要繼承 IntEnum，因為 claripy 可能因為還沒支援 Bit Vector 與 IntEnum 的值比較，故會與 integer 行為有差異
        """

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
            self.proj, "HAL_I2C_Master_Transmit", is_variable=False
        )
        self.END_ADDRS = [
            utils.get_symbol_addr(
                self.proj, "END_SYMBOLIC_EXECUTION", is_variable=False
            )
        ]
        # self.DEBUG_FUNC_ADDR = utils.get_symbol_addr(self.proj, "SYMBOL_FUNCTION", is_variable=False)

        self.API_PROTOTYPE = SimTypeFunction(
            args=[
                SimTypePointer(SimStruct({}, name="I2C_HandleTypeDef")),
                SimTypeShort(signed=False),
                SimTypePointer(SimTypeChar(signed=False)),
                SimTypeShort(signed=False),
                SimTypeInt(signed=False),
            ],
            returnty=SimTypeInt(signed=False),
        )

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
            when=angr.BP_BEFORE,
            condition=self.MEMORY_REGIONS["SysTickVariable"].in_region_read,
            action=self.MEMORY_REGIONS["SysTickVariable"].read,
        )

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )

    def precondition(self, state):
        # utils.set_func_args_symbolic(state, self.API_PROTOTYPE, {3: (0, 3)})

        # utils.store(
        #     state,
        #     self.MEMORY_REGIONS["I2C1"].start + I2C.SR2.OFFSET,
        #     utils.symbolic_bit(
        #         state,
        #         utils.load(state, self.MEMORY_REGIONS["I2C1"].start + I2C.SR2.OFFSET),
        #         I2C.SR2.BUSY,
        #         f"I2C1_{I2C.SR2.OFFSET:#x}_BUSY",
        #     ),
        # )

        return True

    def postcondition(self, simgr):
        # [Spec 3 (Part 2)]
        for state in simgr.found:
            if state.globals.get("spec3_violation_pending", False):
                ret = utils.get_func_ret(state, self.API_PROTOTYPE)

                if state.solver.satisfiable(
                    extra_constraints=[
                        ret == Specs.HAL_StatusTypeDef.HAL_OK,
                        self.API_ARGS[3] > 0,
                    ]
                ):
                    print("Spec 3 violation")
                    simgr.stashes["violated"].append(state)
