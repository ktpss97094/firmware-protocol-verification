import unittest
from types import SimpleNamespace

import angr
import archinfo
import claripy

from project import utils
from project.peripherals.stm32f4.dma import DMA


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
        for offset, value in (
            (
                DMA.DMA_S6CR.OFFSET,
                (1 << DMA.DMA_S6CR.CHSEL.bit)
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


if __name__ == "__main__":
    unittest.main()
