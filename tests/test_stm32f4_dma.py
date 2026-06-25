import unittest
from types import SimpleNamespace

import angr
import archinfo
import claripy

from project import utils
from project.peripherals.stm32f4.dma import DMA
from project.peripherals.stm32f4.i2c import I2C


class STM32F4DMATest(unittest.TestCase):
    def setUp(self):
        self.arch = archinfo.ArchARMCortexM()
        project = angr.load_shellcode(b"\x00\xbf", arch=self.arch)
        self.state = project.factory.blank_state()
        spec = SimpleNamespace(ANGR_ARCH=self.arch)
        self.dma = DMA(
            start=0x40026000,
            size=0x400,
            spec=spec,
            name="DMA1",
        )
        self.handler = object.__new__(DMA._DMAHandler)
        self.handler.dma = self.dma

        self.source = 0x20000000
        self.destination = 0x40005410
        self.handler.specs = SimpleNamespace(
            MEMORY_REGIONS={"I2C1": SimpleNamespace(start=0x40005400)}
        )
        for offset, value in (
            (
                DMA.DMA_S6CR.OFFSET,
                (1 << DMA.DMA_S6CR.CHSEL.bit)
                | (DMA.DMA_MEMORY_TO_PERIPH << DMA.DMA_S6CR.DIR.bit)
                | (1 << DMA.DMA_S6CR.MINC.bit)
                | (1 << DMA.DMA_S6CR.TCIE.bit)
                | (1 << DMA.DMA_S6CR.EN.bit),
            ),
            (DMA.DMA_S6NDTR.OFFSET, 2),
            (DMA.DMA_S6M0AR.OFFSET, self.source),
            (DMA.DMA_S6PAR.OFFSET, self.destination),
            (DMA.DMA_HISR.OFFSET, 0),
            (DMA.DMA_HIFCR.OFFSET, 0),
        ):
            utils.store(self.state, self.dma.start + offset, claripy.BVV(value, 32))
        utils.store(
            self.state,
            self.source,
            claripy.BVV(0x2211, 16),
            size=2,
        )
        utils.store(
            self.state,
            self.handler.specs.MEMORY_REGIONS["I2C1"].start + I2C.I2C_CR2.OFFSET,
            claripy.BVV(1 << I2C.I2C_CR2.DMAEN.bit, 32),
        )
        utils.store(
            self.state,
            self.handler.specs.MEMORY_REGIONS["I2C1"].start + I2C.I2C_SR1.OFFSET,
            claripy.BVV(1 << I2C.I2C_SR1.TXE.bit, 32),
        )

    def test_transfer_complete_only_after_last_item(self):
        self.handler.trigger_event(self.state)

        ndtr = utils.load(
            self.state, self.dma.start + DMA.DMA_S6NDTR.OFFSET
        )
        cr = utils.load(self.state, self.dma.start + DMA.DMA_S6CR.OFFSET)
        hisr = utils.load(self.state, self.dma.start + DMA.DMA_HISR.OFFSET)
        self.assertEqual(1, self.state.solver.eval(ndtr))
        self.assertEqual(1, self.state.solver.eval(cr[DMA.DMA_S6CR.EN.bit]))
        self.assertEqual(0, self.state.solver.eval(hisr[DMA.DMA_HISR.TCIF6.bit]))
        self.assertEqual(
            0x11,
            self.state.solver.eval(
                utils.load(self.state, self.destination, size=1)
            ),
        )

        self.handler.trigger_event(self.state)

        ndtr = utils.load(
            self.state, self.dma.start + DMA.DMA_S6NDTR.OFFSET
        )
        cr = utils.load(self.state, self.dma.start + DMA.DMA_S6CR.OFFSET)
        hisr = utils.load(self.state, self.dma.start + DMA.DMA_HISR.OFFSET)
        self.assertEqual(0, self.state.solver.eval(ndtr))
        self.assertEqual(0, self.state.solver.eval(cr[DMA.DMA_S6CR.EN.bit]))
        self.assertEqual(1, self.state.solver.eval(hisr[DMA.DMA_HISR.TCIF6.bit]))
        self.assertEqual(
            0x22,
            self.state.solver.eval(
                utils.load(self.state, self.destination, size=1)
            ),
        )

    def test_hifcr_write_clears_hisr_flag(self):
        utils.store(
            self.state,
            self.dma.start + DMA.DMA_HISR.OFFSET,
            claripy.BVV(1 << DMA.DMA_HISR.TCIF6.bit, 32),
        )
        self.state.inspect.mem_write_address = claripy.BVV(
            self.dma.start + DMA.DMA_HIFCR.OFFSET,
            self.arch.bits,
        )
        self.state.inspect.mem_write_expr = claripy.BVV(
            1 << DMA.DMA_HIFCR.CTCIF6.bit, 32
        )
        self.state.inspect.mem_write_length = 4
        self.state.inspect.mem_write_condition = None
        self.state.inspect.mem_write_endness = self.arch.memory_endness

        self.dma.pre_write(self.state)
        self.dma.post_write(self.state)

        hisr = utils.load(self.state, self.dma.start + DMA.DMA_HISR.OFFSET)
        self.assertEqual(0, self.state.solver.eval(hisr))

    def test_mmio_masks_support_subword_accesses(self):
        masked = self.dma.mask_pre_write(
            DMA.DMA_S6CR.OFFSET,
            claripy.BVV(0, 8),
            claripy.BVV(1 << DMA.DMA_S6CR.EN.bit, 8),
        )

        self.assertEqual(1, self.state.solver.eval(masked))

    def test_i2c_tx_dma_request_requires_i2c_dr_destination(self):
        self.assertEqual(1, len(self.handler.get_eligible_events(self.state)))

        utils.store(
            self.state,
            self.dma.start + DMA.DMA_S6PAR.OFFSET,
            claripy.BVV(0x40000000, 32),
        )

        self.assertEqual([], self.handler.get_eligible_events(self.state))

    def test_i2c_tx_dma_request_requires_memory_to_peripheral_direction(self):
        cr = utils.load(self.state, self.dma.start + DMA.DMA_S6CR.OFFSET)
        cr = cr & ~(DMA.DMA_S6CR.DIR.mask)
        utils.store(self.state, self.dma.start + DMA.DMA_S6CR.OFFSET, cr)

        self.assertEqual([], self.handler.get_eligible_events(self.state))

    def test_i2c_buffer_event_irqs_are_gated_by_dmaen(self):
        i2c = I2C(
            start=self.handler.specs.MEMORY_REGIONS["I2C1"].start,
            size=0x400,
            spec=SimpleNamespace(ANGR_ARCH=self.arch),
            name="I2C1",
        )
        dmaen = claripy.BVS("dmaen", 1)
        cr2 = (1 << I2C.I2C_CR2.ITEVTEN.bit) | (1 << I2C.I2C_CR2.ITBUFEN.bit)
        cr2 = utils.replace_bit(
            claripy.BVV(cr2, self.arch.bits), I2C.I2C_CR2.DMAEN.bit, dmaen
        )
        sr1 = (
            (1 << I2C.I2C_SR1.BTF.bit)
            | (1 << I2C.I2C_SR1.TXE.bit)
            | (1 << I2C.I2C_SR1.RXNE.bit)
        )
        utils.store(self.state, i2c.start + I2C.I2C_CR2.OFFSET, cr2)
        utils.store(self.state, i2c.start + I2C.I2C_SR1.OFFSET, claripy.BVV(sr1, 32))

        event_irq_conditions = [
            condition
            for condition, metadata in i2c.get_pending_irqs(self.state)
            if metadata["irq"] == I2C.IRQ_NUMBERS[0]
        ]

        self.assertEqual(3, len(event_irq_conditions))
        for condition in event_irq_conditions:
            self.assertFalse(
                self.state.solver.satisfiable(
                    extra_constraints=[condition, dmaen == claripy.BVV(1, 1)]
                )
            )
            self.assertTrue(
                self.state.solver.satisfiable(
                    extra_constraints=[condition, dmaen == claripy.BVV(0, 1)]
                )
            )


if __name__ == "__main__":
    unittest.main()
