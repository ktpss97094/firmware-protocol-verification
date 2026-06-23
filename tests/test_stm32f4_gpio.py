import unittest
from types import SimpleNamespace

import angr
import archinfo
import claripy

from firmwares.stm32f429.protocols.I2C.spec_sw import GPIO as SoftwareI2CGPIO
from project.peripherals.stm32f4.gpio import GPIO, Globals
from project.protocols.i2c import I2CBus


class STM32F4GPIOTest(unittest.TestCase):
    def setUp(self):
        self.arch = archinfo.ArchARMCortexM()
        project = angr.load_shellcode(b"\x00\xbf", arch=self.arch)
        self.state = project.factory.blank_state()
        spec = SimpleNamespace(ANGR_ARCH=self.arch)
        self.gpio = GPIO(start=0x40020800, size=0x400, spec=spec, name="GPIOC")

        moder = (1 << (13 * 2)) | (1 << (15 * 2))
        otyper = (1 << 13) | (1 << 15)
        odr = (1 << 13) | (1 << 15)
        for offset, value in (
            (GPIO.GPIO_MODER.OFFSET, moder),
            (GPIO.GPIO_OTYPER.OFFSET, otyper),
            (GPIO.GPIO_PUPDR.OFFSET, 0),
            (GPIO.GPIO_IDR.OFFSET, 0),
            (GPIO.GPIO_ODR.OFFSET, odr),
            (GPIO.GPIO_BSRR.OFFSET, 0),
        ):
            self.state.memory.store(
                self.gpio.start + offset,
                claripy.BVV(value, 32),
                endness=self.arch.memory_endness,
            )

    def test_bsrr_write_value_is_cleared_after_post_write(self):
        self.gpio.set_handlers(cpu=None, state=self.state, cfg=None, specs=None)
        self.state.inspect.mem_write_address = claripy.BVV(
            self.gpio.start + GPIO.GPIO_BSRR.OFFSET, self.arch.bits
        )
        self.state.inspect.mem_write_expr = claripy.BVV(1 << (13 + 16), 32)
        self.state.inspect.mem_write_length = 4
        self.state.inspect.mem_write_condition = None
        self.state.inspect.mem_write_endness = self.arch.memory_endness

        self.gpio.pre_write(self.state)
        self.assertIsNotNone(self.state.GPIOC_globals.bsrr_write_value)

        self.gpio.post_write(self.state)
        self.assertIsNone(self.state.GPIOC_globals.bsrr_write_value)

        odr = self.state.memory.load(
            self.gpio.start + GPIO.GPIO_ODR.OFFSET,
            self.arch.bytes,
            endness=self.arch.memory_endness,
        )
        bsrr = self.state.memory.load(
            self.gpio.start + GPIO.GPIO_BSRR.OFFSET,
            self.arch.bytes,
            endness=self.arch.memory_endness,
        )
        self.assertEqual(0, self.state.solver.eval(odr[GPIO.GPIO_ODR.ODR13.bit]))
        self.assertEqual(0, self.state.solver.eval(bsrr))

    def test_bsrr_upper_halfword_write_resets_odr_bit(self):
        self.gpio.set_handlers(cpu=None, state=self.state, cfg=None, specs=None)
        self.state.inspect.mem_write_address = claripy.BVV(
            self.gpio.start + GPIO.GPIO_BSRR.OFFSET + 2, self.arch.bits
        )
        self.state.inspect.mem_write_expr = claripy.BVV(1 << GPIO.GPIO_ODR.ODR13.bit, 16)
        self.state.inspect.mem_write_length = 2
        self.state.inspect.mem_write_condition = None
        self.state.inspect.mem_write_endness = self.arch.memory_endness

        self.gpio.pre_write(self.state)
        self.gpio.post_write(self.state)

        odr = self.state.memory.load(
            self.gpio.start + GPIO.GPIO_ODR.OFFSET,
            self.arch.bytes,
            endness=self.arch.memory_endness,
        )
        bsrr = self.state.memory.load(
            self.gpio.start + GPIO.GPIO_BSRR.OFFSET,
            self.arch.bytes,
            endness=self.arch.memory_endness,
        )
        self.assertEqual(0, self.state.solver.eval(odr[GPIO.GPIO_ODR.ODR13.bit]))
        self.assertEqual(0, self.state.solver.eval(bsrr))

    def test_idr_read_returns_fresh_transaction_value(self):
        self.state.memory.store(
            self.gpio.start + GPIO.GPIO_OTYPER.OFFSET,
            claripy.BVV(0, 32),
            endness=self.arch.memory_endness,
        )
        self.state.memory.store(
            self.gpio.start + GPIO.GPIO_ODR.OFFSET,
            claripy.BVV(1 << GPIO.GPIO_ODR.ODR13.bit, 32),
            endness=self.arch.memory_endness,
        )
        self.state.inspect.mem_read_address = claripy.BVV(
            self.gpio.start + GPIO.GPIO_IDR.OFFSET, self.arch.bits
        )
        self.state.inspect.mem_read_expr = self.state.memory.load(
            self.gpio.start + GPIO.GPIO_IDR.OFFSET,
            self.arch.bytes,
            endness=self.arch.memory_endness,
        )

        _, _, value = self.gpio.post_read(self.state)
        stored_idr = self.state.memory.load(
            self.gpio.start + GPIO.GPIO_IDR.OFFSET,
            self.arch.bytes,
            endness=self.arch.memory_endness,
        )

        self.assertEqual(1, self.state.solver.eval(value[GPIO.GPIO_IDR.IDR13.bit]))
        self.assertEqual(1, self.state.solver.eval(stored_idr[GPIO.GPIO_IDR.IDR13.bit]))
        self.assertEqual(0, self.state.solver.eval(value[GPIO.GPIO_IDR.IDR15.bit]))

    def test_software_i2c_bsrr_post_write_keeps_bus_flags_as_bool_asts(self):
        gpio = SoftwareI2CGPIO(
            start=self.gpio.start,
            size=self.gpio.size,
            spec=self.gpio.spec,
            name=self.gpio.name,
        )
        self.state.register_plugin("GPIOC_globals", Globals())
        self.state.register_plugin("i2c_bus", I2CBus())

        for _ in range(2):
            self.state.inspect.mem_write_address = claripy.BVV(
                gpio.start + GPIO.GPIO_BSRR.OFFSET, self.arch.bits
            )
            self.state.inspect.mem_write_expr = claripy.BVV(
                1 << GPIO.GPIO_BSRR.BS13.bit, 32
            )
            self.state.inspect.mem_write_length = 4
            self.state.inspect.mem_write_condition = None
            self.state.inspect.mem_write_endness = self.arch.memory_endness

            gpio.pre_write(self.state)
            self.state.memory.store(
                gpio.start + GPIO.GPIO_BSRR.OFFSET,
                self.state.inspect.mem_write_expr,
                size=self.arch.bytes,
                endness=self.arch.memory_endness,
                inspect=False,
            )
            gpio.post_write(self.state)

            self.assertIsInstance(
                self.state.i2c_bus.arbitration_lost, claripy.ast.bool.Bool
            )
            self.assertIsInstance(
                self.state.i2c_bus.arbitration_lost_byte_end,
                claripy.ast.bool.Bool,
            )
            self.assertIsInstance(self.state.i2c_bus.wait_state, claripy.ast.bool.Bool)


if __name__ == "__main__":
    unittest.main()
