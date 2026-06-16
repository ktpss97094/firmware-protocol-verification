import unittest
from types import SimpleNamespace

import angr
import archinfo
import claripy

from project.peripherals.stm32f4.gpio import GPIO


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
        self.state.inspect.mem_write_expr = claripy.BVV(1 << 13, 32)
        self.state.inspect.mem_write_length = 4
        self.state.inspect.mem_write_condition = None
        self.state.inspect.mem_write_endness = self.arch.memory_endness

        self.gpio.pre_write(self.state)
        self.assertIsNotNone(self.state.GPIOC_globals.bsrr_write_value)

        self.gpio.post_write(self.state)
        self.assertIsNone(self.state.GPIOC_globals.bsrr_write_value)


if __name__ == "__main__":
    unittest.main()
