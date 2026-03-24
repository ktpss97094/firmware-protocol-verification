"""
read_back_verification
blocking mode API 不會檢查 ARLO，interrupt/DMA mode 會檢查
1. Trigger: write DR
    Condition: ARLO 為 0
2. Trigger: write STOP
    Condition: ARLO 為 0
3. Trigger: write START
    Condition: ARLO 為 0

ARLO set 之後 MSL 會自動 clear

Symbolic:
uwTick
SR1 (SB, ADD10 (10-bit 時), AF, ADDR, TxE, BTF)
CR1 STOP

Interrupt:
ITEVFEN, (ITBUFEN), ITERREN
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
from project.cores.cortex_m.systick import SysTickVariable
from project.peripherals.stm32f4.i2c import I2C as STM32F4_I2C
from project.types import BaseSpecs, MemoryRegion


class I2C(STM32F4_I2C):
    def pre_read(self, state, offset):
        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)

        match offset:
            case I2C.SR2.OFFSET:
                # --- Spec 1 ---
                if state.globals.get(
                    f"{self.name}_SR1_read", False
                ) and state.solver.satisfiable(extra_constraints=[sr1[1] == 0]):
                    print(f"Spec 1 violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True

    def pre_write(self, state, offset, value):
        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)

        match offset:
            case I2C.CR1.OFFSET:
                # --- Spec 3 (Part 1) ---
                if not state.solver.satisfiable(
                    extra_constraints=[value[9] == 0]
                ) and state.solver.satisfiable(extra_constraints=[sr1[2] == 0]):
                    state.globals["spec3_violation_pending"] = True

            case I2C.DR.OFFSET:
                # --- Spec 2 ---
                if state.solver.satisfiable(
                    extra_constraints=[sr1[7] == 0, sr1[0] != 1, sr1[3] != 1]
                ):
                    print(f"Spec 2 violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/stm32f429/build/protocols/I2C/master/Blocking_Mode/Hardware/stm32f4xx-hal-driver/firmware.elf"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Renode ---
    USE_RENODE = False

    # --- Constants ---
    """
    Warning:
        不要繼承 IntEnum，因為 claripy 可能因為還沒支援 Bit Vector 與 IntEnum 的值比較，故會與 integer 行為有差異
    """

    class HAL_StatusTypeDef:
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

    def init_input(self, state):
        # utils.set_func_args_symbolic(state, self.API_PROTOTYPE, {3: (0, 3)})
        pass

    def final(self, simgr):
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
