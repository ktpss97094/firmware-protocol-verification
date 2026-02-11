"""
每次 read 都回傳一個完整的 symbolic，可解析出可到達 Spec trigger 的路徑的所有 branch 會使用的硬體會改變的變數

可解析出: SB, AF, ADDR, TxE, BTF, uwTick
"""

import angr
import archinfo
import avatar2
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

        match offset:
            case I2C.SR1.OFFSET:
                utils.store(
                    state,
                    self.start + I2C.SR1.OFFSET,
                    utils.generate_symbolic(state, f"{self.name}_SR1"),
                )

            case I2C.SR2.OFFSET:
                # --- Spec 1 ---
                if state.globals.get(
                    f"{self.name}_SR1_read", False
                ) and state.solver.satisfiable(extra_constraints=[sr1[1] == 0]):
                    print(state.solver.constraints)

                utils.store(
                    state,
                    self.start + I2C.SR2.OFFSET,
                    utils.generate_symbolic(state, f"{self.name}_SR2"),
                )

    def write(self, state, offset, value):
        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)

        match offset:
            case I2C.CR1.OFFSET:
                # --- Spec 3 (Part 1) ---
                if not state.solver.satisfiable(
                    extra_constraints=[value[9] == 0]
                ) and state.solver.satisfiable(extra_constraints=[sr1[2] == 0]):
                    print(state.solver.constraints)

            case I2C.DR.OFFSET:
                # --- Spec 2 ---
                if state.solver.satisfiable(
                    extra_constraints=[sr1[7] == 0, sr1[0] != 1, sr1[3] != 1]
                ):
                    print(state.solver.constraints)


class SysTickVariable(VariableMemoryRegion):
    def read(self, state, offset):
        utils.store(
            state, self.start + offset, utils.generate_symbolic(state, self.name)
        )


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/STM32F429/build/protocols/I2C/master/Blocking_Mode/Hardware/stm32f4xx-hal-driver/firmware.elf"
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
