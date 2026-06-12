r"""
read_back_verification
1. Trigger: write CR1
    Condition: value[START] = 1 \implies (MSL = 1 \implies ARLO = 0)
2. Trigger: write DR
    Condition: MSL = 1 \implies ARLO = 0
3. Trigger: write CR1
    Condition: value[STOP] = 1 \implies (MSL = 1 \implies ARLO = 0)
"""

from enum import Enum, auto

import angr
import archinfo
import avatar2
import claripy
from angr.sim_type import (
    SimTypeChar,
    SimTypeFunction,
    SimTypeInt,
    SimTypePointer,
    SimTypeShort,
)

from project import config, utils
from project.cores.arm.cortex_m.systick import SysTickVariable
from project.peripherals.stm32f4.dma import DMA
from project.peripherals.stm32f4.i2c import I2C as STM32F4_I2C
from project.types import BaseSpecs, MemoryRegion, MMIOMemoryRegion, VerificationManager


class STM32F4XX_HAL(Enum):
    BLOCKING = auto()
    INTERRUPT = auto()
    DMA = auto()


class OPENCM3(Enum):
    BLOCKING = auto()


type FirmwareMode = STM32F4XX_HAL | OPENCM3
MODE: FirmwareMode = STM32F4XX_HAL.BLOCKING


class I2C(STM32F4_I2C):
    def pre_write(self, state):
        _, offset, value = super().pre_write(state)

        sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        sr2 = utils.load(state, self.start + I2C.I2C_SR2.OFFSET)

        match offset:
            case I2C.I2C_CR1.OFFSET:
                # --- Spec 1 ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        value[I2C.I2C_CR1.START.bit] == 1,
                        sr2[I2C.I2C_SR2.MSL.bit] == 1,
                        sr1[I2C.I2C_SR1.ARLO.bit] == 1,
                    ]
                ):
                    VerificationManager.violation(
                        state, "read_back_verification (spec 1)"
                    )

                # --- Spec 3 ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        value[I2C.I2C_CR1.STOP.bit] == 1,
                        sr2[I2C.I2C_SR2.MSL.bit] == 1,
                        sr1[I2C.I2C_SR1.ARLO.bit] == 1,
                    ]
                ):
                    VerificationManager.violation(
                        state, "read_back_verification (spec 3)"
                    )

            case I2C.I2C_DR.OFFSET:
                # --- Spec 2 ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        sr2[I2C.I2C_SR2.MSL.bit] == 1,
                        sr1[I2C.I2C_SR1.ARLO.bit] == 1,
                    ]
                ):
                    VerificationManager.violation(
                        state, "read_back_verification (spec 2)"
                    )

        return _, offset, value


class Specs(BaseSpecs):
    # --- Paths ---
    match MODE:
        case STM32F4XX_HAL.BLOCKING:
            FIRMWARE_PATH = str(
                config.PROJECT_ROOT
                / "firmwares/stm32f429/build/protocols/I2C/master/Blocking_Mode/Hardware/stm32f4xx-hal-driver/firmware.elf"
            )
        case STM32F4XX_HAL.INTERRUPT:
            FIRMWARE_PATH = str(
                config.PROJECT_ROOT
                / "firmwares/stm32f429/build/protocols/I2C/master/Interrupt_Mode/stm32f4xx-hal-driver/firmware.elf"
            )
        case STM32F4XX_HAL.DMA:
            FIRMWARE_PATH = str(
                config.PROJECT_ROOT
                / "firmwares/stm32f429/build/protocols/I2C/master/DMA_Mode/stm32f4xx-hal-driver/firmware.elf"
            )
        case OPENCM3.BLOCKING:
            FIRMWARE_PATH = str(
                config.PROJECT_ROOT
                / "firmwares/stm32f429/build/protocols/I2C/master/Blocking_Mode/Hardware/libopencm3/firmware.elf"
            )
    OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Parameters ---
    match MODE:
        case STM32F4XX_HAL():
            BOUND_LOOPS = {
                # BLOCKING
                0x800AF79: 2,
                0x800B0BD: 2,
                0x800B181: 2,
                0x800B211: 2,
                # INTERRUPT
                0x8005E09: 0,
                # DMA
                0x80063B9: 0,
            }

        case OPENCM3():
            BOUND_LOOPS = {
                # BLOCKING
                0x8000453: 0,
                0x8000461: 0,
                0x8000485: 0,
                0x8000497: 0,
            }

    def _define_specs(self):
        self.MEMORY_REGIONS = {
            "RAM": MemoryRegion(start=0x20000000, size=0x30000, spec=self, name="RAM"),
            "CCMRAM": MemoryRegion(
                start=0x10000000, size=0x10000, spec=self, name="CCMRAM"
            ),
            "FLASH": MemoryRegion(
                start=0x08000000, size=0x200000, spec=self, name="FLASH", transfer=False
            ),
            "VECTOR_TABLE_ALIAS": MemoryRegion(
                start=0x00000000,
                size=0x400,
                spec=self,
                name="VECTOR_TABLE_ALIAS",
                physical_addr=0x08000000,
            ),
            "I2C1": I2C(start=0x40005400, size=0x400, spec=self, name="I2C1"),
            "NVIC": MMIOMemoryRegion(
                start=0xE000E100, size=0xC00, spec=self, name="NVIC"
            ),
            "DMA1": DMA(start=0x40026000, size=0x400, spec=self, name="DMA1"),
        }
        match MODE:
            case STM32F4XX_HAL():
                self.MEMORY_REGIONS["SysTickVariable"] = SysTickVariable(
                    start=utils.get_symbol_addr(self.proj, "uwTick", is_variable=True),
                    size=0x4,
                    spec=self,
                    name="SysTickVariable",
                )

        match MODE:
            case STM32F4XX_HAL.BLOCKING:
                self.BEGIN_ADDR = utils.get_symbol_addr(
                    self.proj, "HAL_I2C_Master_Transmit", is_variable=False
                )
            case STM32F4XX_HAL.INTERRUPT:
                self.BEGIN_ADDR = utils.get_symbol_addr(
                    self.proj, "HAL_I2C_Master_Transmit_IT", is_variable=False
                )
            case STM32F4XX_HAL.DMA:
                self.BEGIN_ADDR = utils.get_symbol_addr(
                    self.proj, "HAL_I2C_Master_Transmit_DMA", is_variable=False
                )
            case OPENCM3.BLOCKING:
                self.BEGIN_ADDR = utils.get_symbol_addr(
                    self.proj, "i2c_transfer7", is_variable=False
                )

        match MODE:
            case STM32F4XX_HAL():
                I2C_InitTypeDef = angr.types.parse_type("""
                    struct I2C_InitTypeDef {
                        uint32_t ClockSpeed;
                        uint32_t DutyCycle;
                        uint32_t OwnAddress1;
                        uint32_t AddressingMode;
                    }
                    """)
                angr.types.register_types(I2C_InitTypeDef)
                I2C_HandleTypeDef = angr.types.parse_type("""
                    struct I2C_HandleTypeDef {
                        void *Instance;
                        struct I2C_InitTypeDef Init;
                    }
                    """)
                angr.types.register_types(I2C_HandleTypeDef)
                match MODE:
                    case STM32F4XX_HAL.BLOCKING:
                        self.API_PROTOTYPE = SimTypeFunction(
                            args=[
                                SimTypePointer(I2C_HandleTypeDef),
                                SimTypeShort(signed=False),
                                SimTypePointer(SimTypeChar(signed=False)),
                                SimTypeShort(signed=False),
                                SimTypeInt(signed=False),
                            ],
                            returnty=SimTypeInt(signed=False),
                        )
                    case STM32F4XX_HAL.INTERRUPT | STM32F4XX_HAL.DMA:
                        self.API_PROTOTYPE = SimTypeFunction(
                            args=[
                                SimTypePointer(I2C_HandleTypeDef),
                                SimTypeShort(signed=False),
                                SimTypePointer(SimTypeChar(signed=False)),
                                SimTypeShort(signed=False),
                            ],
                            returnty=SimTypeInt(signed=False),
                        )

            case OPENCM3():
                self.API_PROTOTYPE = SimTypeFunction(
                    args=[
                        SimTypeInt(signed=False),
                        SimTypeShort(signed=False),
                        SimTypePointer(SimTypeChar(signed=False)),
                        SimTypeInt(signed=False),
                        SimTypePointer(SimTypeChar(signed=False)),
                        SimTypeInt(signed=False),
                    ],
                    returnty=None,
                )

        self.END_ADDRS = [
            utils.convert_thumb_mode(
                self.proj,
                utils.get_symbol_addr(
                    self.proj, "END_SYMBOLIC_EXECUTION", is_variable=False
                ),
            )
            # utils.get_symbol_addr(
            #     self.proj, "DEBUG_SYMBOLIC_EXECUTION", is_variable=False
            # ),
        ]
        # self.DEBUG_FUNC_ADDR = utils.get_symbol_addr(
        #     self.proj, "SYMBOL_FUNCTION", is_variable=False
        # )

    def init_inspect(self, state: angr.SimState):
        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_read,
            action=self.MEMORY_REGIONS["I2C1"].post_read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_write,
            action=self.MEMORY_REGIONS["I2C1"].pre_write,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_write,
            action=self.MEMORY_REGIONS["I2C1"].post_write,
        )

        match MODE:
            case STM32F4XX_HAL():
                state.inspect.b(
                    "mem_read",
                    when=angr.BP_BEFORE,
                    condition=self.MEMORY_REGIONS["SysTickVariable"].in_region_read,
                    action=self.MEMORY_REGIONS["SysTickVariable"].post_read,
                )

        # state.inspect.b(
        #     "instruction", instruction=self.DEBUG_FUNC_ADDR, action=utils.stop_and_debug
        # )

    def init_input(self, state):
        match MODE:
            case STM32F4XX_HAL():
                size_range = (0, 3)
            case OPENCM3():
                size_range = (0, 1)
                # receive size: (0, 2)

        # addressing mode symbolic
        match MODE:
            case STM32F4XX_HAL():
                addressing_mode = state.mem[
                    self.API_ARGS[0]
                ].struct.I2C_HandleTypeDef.Init.AddressingMode
                addressing_mode.store(
                    claripy.BVS("AddressingMode", addressing_mode.resolved.length)
                )

        # address, size symbolic
        utils.set_func_args_symbolic(
            state, self.API_PROTOTYPE, {1: None, 3: size_range}
        )

        # data symbolic
        element_size_bits = self.API_PROTOTYPE.args[2].pts_to.size
        element_size_bytes = element_size_bits // 8
        for idx in range(*size_range):
            utils.store(
                state,
                self.API_ARGS[2] + (idx * element_size_bytes),
                claripy.BVS(f"data[{idx}]", element_size_bits),
                size=element_size_bytes,
            )

        # timeout symbolic
        match MODE:
            case STM32F4XX_HAL.BLOCKING:
                utils.set_func_args_symbolic(state, self.API_PROTOTYPE, {4: None})
