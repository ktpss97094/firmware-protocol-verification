r"""
read_back_verification
1. Trigger: write BSRR
    Condition: value[BRy] (SDA) = 1 \implies arbitration_lost = 0
    > I2C specification §3.1.8: The first time a controller tries to send a HIGH, but detects that the SDA level is LOW, the controller knows that it has lost the arbitration and turns off its SDA output driver.
2. Trigger write BSRR
    Condition: value[BRy] (SCL) = 1 \implies arbitration_lost_byte_end = 0
    > I2C specification §3.1.8: A controller that loses the arbitration can generate clock pulses until the end of the byte in which it loses the arbitration and must restart its transaction when the bus is free.
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
from project.types import BaseSpecs, MemoryRegion, Violation


class GPIO(STM32F4_GPIO):
    """
    透過 specification 定義 SCL/SDA 在 firmware 中是使用哪個 pin
    """

    def pre_write(self, state):
        _, offset, value = super().pre_write(state)

        match offset:
            case GPIO.GPIO_BSRR.OFFSET:
                # --- Spec 1 ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        value[GPIO.GPIO_BSRR.BR15.bit] == 1,
                        state.i2c_bus.arbitration_lost,
                    ]
                ):
                    raise Violation("read_back_verification (spec 1)")

                # --- Spec 2 ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        value[GPIO.GPIO_BSRR.BR13.bit] == 1,
                        state.i2c_bus.arbitration_lost_byte_end,
                    ]
                ):
                    raise Violation("read_back_verification (spec 2)")

        return _, offset, value

    def post_write(self, state):
        _, offset, value = super().post_write(state)

        odr = utils.load(state, self.start + GPIO.GPIO_ODR.OFFSET)
        scl_out = odr[GPIO.GPIO_ODR.ODR13.bit]
        sda_out = odr[GPIO.GPIO_ODR.ODR15.bit]

        match offset:
            case GPIO.GPIO_BSRR.OFFSET:
                idr = self.get_idr(state)

                is_rising_edge = claripy.And(
                    state.i2c_bus.prev_scl_out == 0, scl_out == 1
                )
                state.i2c_bus.bit_count = claripy.If(
                    is_rising_edge,
                    (state.i2c_bus.bit_count + 1) % 9,
                    state.i2c_bus.bit_count,
                )
                state.i2c_bus.arbitration_lost = claripy.If(
                    is_rising_edge,
                    claripy.Or(
                        state.i2c_bus.arbitration_lost,
                        claripy.And(
                            sda_out == 1, idr[GPIO.GPIO_IDR.IDR15.bit] == 0
                        ),  # 先前 SDA 輸出 1，但實際讀到的是 0
                    ),
                    state.i2c_bus.arbitration_lost,
                )

                state.i2c_bus.arbitration_lost_byte_end = claripy.If(
                    is_rising_edge,
                    claripy.Or(
                        state.i2c_bus.arbitration_lost_byte_end,
                        claripy.And(
                            state.i2c_bus.arbitration_lost, state.i2c_bus.bit_count == 0
                        ),
                    ),
                    state.i2c_bus.arbitration_lost_byte_end,
                )

                state.i2c_bus.prev_scl_out = scl_out

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
    BOUND_LOOPS = {0x80008E7: 0}

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

        self.END_ADDRS = [
            utils.convert_thumb_mode(
                self.proj,
                utils.get_symbol_addr(
                    self.proj, "END_SYMBOLIC_EXECUTION", is_variable=False
                ),
            )
        ]

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
