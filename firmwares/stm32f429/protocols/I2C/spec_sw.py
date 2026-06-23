r"""
read_back_verification
1. Trigger: write ODR
    Condition: value[ODRy] (SDA) = 0 \implies arbitration_lost = 0
2. Trigger: write BSRR
    Condition: (value[BSy] (SDA) = 0 \land value[BRy] (SDA) = 1) \implies arbitration_lost = 0
> I2C specification §3.1.8: The first time a controller tries to send a HIGH, but detects that the SDA level is LOW, the controller knows that it has lost the arbitration and turns off its SDA output driver.
3. Trigger: write ODR
    Condition: value[ODRy] (SCL) = 0 \implies arbitration_lost_byte_end = 0
4. Trigger: write BSRR
    Condition: (value[BSy] (SCL) = 0 \land value[BRy] (SCL) = 1) \implies arbitration_lost_byte_end = 0
> I2C specification §3.1.8: A controller that loses the arbitration can generate clock pulses until the end of the byte in which it loses the arbitration and must restart its transaction when the bus is free.

clock_stretching
1. Trigger: write ODR
    Condition: value[ODRy] (SCL) = 0 \implies wait_state = 0
2. Trigger: write BSRR
    Condition: (value[BSy] (SCL) = 0 \land value[BRy] (SCL) = 1) \implies wait_state = 0
"""

import angr
import archinfo
import avatar2
import claripy
from angr.sim_type import SimTypeBool, SimTypeChar, SimTypeFunction, SimTypePointer

from project import config, utils
from project.cores.arm.cortex_m.dwt import DWT
from project.peripherals.stm32f4.gpio import GPIO as STM32F4_GPIO
from project.protocols.i2c import I2CBus
from project.types import BaseSpecs, MemoryRegion, VerificationManager


class GPIO(STM32F4_GPIO):
    """
    透過 specification 定義 SCL/SDA 在 firmware 中是使用哪個 pin
    """

    def pre_write(self, state):
        _, offset, value = super().pre_write(state)

        match offset:
            case GPIO.GPIO_ODR.OFFSET:
                violation_name = "read_back_verification (spec 1)"
                if VerificationManager.should_check(
                    violation_name
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.And(
                            value[GPIO.GPIO_ODR.ODR15.bit] == 0,
                            state.i2c_bus.arbitration_lost,
                        )
                    ]
                ):
                    VerificationManager.violation(state, violation_name)

                violation_name = "read_back_verification (spec 3)"
                if VerificationManager.should_check(
                    violation_name
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.And(
                            value[GPIO.GPIO_ODR.ODR13.bit] == 0,
                            state.i2c_bus.arbitration_lost_byte_end,
                        )
                    ]
                ):
                    VerificationManager.violation(state, violation_name)

                violation_name = "clock_stretching (spec 1)"
                if VerificationManager.should_check(
                    violation_name
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.And(
                            value[GPIO.GPIO_ODR.ODR13.bit] == 0,
                            state.i2c_bus.wait_state,
                        )
                    ]
                ):
                    VerificationManager.violation(state, violation_name)

            case GPIO.GPIO_BSRR.OFFSET:
                violation_name = "read_back_verification (spec 2)"
                if VerificationManager.should_check(
                    violation_name
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.And(
                            value[GPIO.GPIO_BSRR.BS15.bit] == 0,
                            value[GPIO.GPIO_BSRR.BR15.bit] == 1,
                        ),
                        state.i2c_bus.arbitration_lost,
                    ]
                ):
                    VerificationManager.violation(state, violation_name)

                violation_name = "read_back_verification (spec 4)"
                if VerificationManager.should_check(
                    violation_name
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.And(
                            value[GPIO.GPIO_BSRR.BS13.bit] == 0,
                            value[GPIO.GPIO_BSRR.BR13.bit] == 1,
                        ),
                        state.i2c_bus.arbitration_lost_byte_end,
                    ]
                ):
                    VerificationManager.violation(state, violation_name)

                violation_name = "clock_stretching (spec 2)"
                if VerificationManager.should_check(
                    violation_name
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.And(
                            value[GPIO.GPIO_BSRR.BS13.bit] == 0,
                            value[GPIO.GPIO_BSRR.BR13.bit] == 1,
                        ),
                        state.i2c_bus.wait_state,
                    ]
                ):
                    VerificationManager.violation(state, violation_name)

        return _, offset, value

    def post_read(self, state):
        _, offset, readout_value = super().post_read(state)

        match offset:
            case GPIO.GPIO_IDR.OFFSET:
                state.i2c_bus.wait_state = claripy.If(
                    claripy.And(
                        state.i2c_bus.wait_state,
                        readout_value[GPIO.GPIO_IDR.IDR13.bit] == 1,
                    ),
                    claripy.false(),
                    state.i2c_bus.wait_state,
                )

        return _, offset, readout_value

    def post_write(self, state):
        _, offset, value = super().post_write(state)

        odr = utils.load(state, self.start + GPIO.GPIO_ODR.OFFSET)
        scl_out = odr[GPIO.GPIO_ODR.ODR13.bit]
        sda_out = odr[GPIO.GPIO_ODR.ODR15.bit]

        match offset:
            case GPIO.GPIO_BSRR.OFFSET | GPIO.GPIO_ODR.OFFSET:
                idr = self.get_idr(state)

                is_rising_edge = claripy.And(
                    state.i2c_bus.prev_scl_out == 0, scl_out == 1
                )
                is_falling_edge = claripy.And(
                    state.i2c_bus.prev_scl_out == 1, scl_out == 0
                )
                is_start_condition = claripy.And(
                    scl_out == 1, state.i2c_bus.prev_sda_out == 1, sda_out == 0
                )
                is_stop_condition = claripy.And(
                    scl_out == 1, state.i2c_bus.prev_sda_out == 0, sda_out == 1
                )

                state.i2c_bus.bit_count = claripy.If(
                    is_start_condition,
                    claripy.BVV(0, 4),
                    claripy.If(
                        is_rising_edge,
                        (state.i2c_bus.bit_count + 1) % 9,
                        state.i2c_bus.bit_count,
                    ),
                )

                state.i2c_bus.arbitration_lost = claripy.If(
                    is_stop_condition,
                    claripy.false(),
                    claripy.If(
                        is_rising_edge,
                        claripy.Or(
                            state.i2c_bus.arbitration_lost,
                            claripy.And(
                                sda_out == 1, idr[GPIO.GPIO_IDR.IDR15.bit] == 0
                            ),  # 當前 SDA 輸出 1，但實際讀到的是 0
                        ),
                        state.i2c_bus.arbitration_lost,
                    ),
                )

                state.i2c_bus.wait_state = claripy.If(
                    claripy.And(
                        is_rising_edge, idr[GPIO.GPIO_IDR.IDR13.bit] == 0
                    ),  # 已經 rising edge (controller SCL 輸出 1) 了，但卻讀到 0
                    claripy.true(),
                    state.i2c_bus.wait_state,
                )

                state.i2c_bus.arbitration_lost_byte_end = claripy.If(
                    is_stop_condition,
                    claripy.false(),
                    claripy.If(
                        is_falling_edge,
                        claripy.Or(
                            state.i2c_bus.arbitration_lost_byte_end,
                            claripy.And(
                                state.i2c_bus.arbitration_lost,
                                state.i2c_bus.bit_count == 0,
                            ),
                        ),
                        state.i2c_bus.arbitration_lost_byte_end,
                    ),
                )

                state.i2c_bus.prev_scl_out = scl_out
                state.i2c_bus.prev_sda_out = sda_out

        return _, offset, value


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/stm32f429/build/protocols/I2C/master/Blocking_Mode/Software/stm32_bitbang_i2c/firmware.elf"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Parameters ---
    BOUND_LOOPS = {0x80008CF: 0}

    # --- Constants ---

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
            "GPIOC": GPIO(start=0x40020800, size=0x400, spec=self, name="GPIOC"),
            "DWT": DWT(start=0xE0001000, size=0x1000, spec=self, name="DWT"),
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj, "I2C_transmit", is_variable=False
        )

        self.API_PROTOTYPE = SimTypeFunction(
            args=[
                SimTypeChar(signed=False),
                SimTypePointer(SimTypeChar(signed=False)),
                SimTypeChar(signed=False),
            ],
            returnty=SimTypeBool(),
        )

    def init_inspect(self, state: angr.SimState):
        state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            condition=self.MEMORY_REGIONS["GPIOC"].in_region_write,
            action=self.MEMORY_REGIONS["GPIOC"].pre_write,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["GPIOC"].in_region_write,
            action=self.MEMORY_REGIONS["GPIOC"].post_write,
        )

        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["DWT"].in_region_read,
            action=self.MEMORY_REGIONS["DWT"].post_read,
        )

    def init_input(self, state):
        size_range = (0, 2)

        # address, size symbolic
        utils.set_func_args_symbolic(
            state, self.API_PROTOTYPE, {0: None, 2: size_range}
        )

        # data symbolic
        element_size_bits = self.API_PROTOTYPE.args[1].pts_to.size
        element_size_bytes = element_size_bits // 8
        for idx in range(*size_range):
            utils.store(
                state,
                self.API_ARGS[1] + (idx * element_size_bytes),
                claripy.BVS(f"data[{idx}]", element_size_bits),
                size=element_size_bytes,
            )

        I2CBus.register_default("i2c_bus")
