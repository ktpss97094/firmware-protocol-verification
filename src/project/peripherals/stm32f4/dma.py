from functools import cache

import angr
import claripy

from project import utils
from project.cores.base import BaseDMA
from project.peripherals.stm32f4.i2c import I2C
from project.types import (
    AccessType,
    BaseRegister,
    BitsField,
    BPConfig,
    EventForkHandler,
)


class DMA(BaseDMA):
    IRQ_NUMBERS = [11, 12, 13, 14, 15, 16, 17]  # DMA1_Stream0 to DMA1_Stream6

    class DMA_HISR(BaseRegister):
        OFFSET = 0x04

        TCIF6 = BitsField(
            21, AccessType.R, 0
        )  # Stream 6 transfer complete interrupt flag
        HTIF6 = BitsField(20, AccessType.R, 0)  # Stream 6 half transfer interrupt flag
        TEIF6 = BitsField(19, AccessType.R, 0)  # Stream 6 transfer error interrupt flag
        DMEIF6 = BitsField(
            18, AccessType.R, 0
        )  # Stream 6 direct mode error interrupt flag
        FEIF6 = BitsField(16, AccessType.R, 0)  # Stream 6 FIFO error interrupt flag

    class DMA_S6CR(BaseRegister):
        OFFSET = 0x10 + 0x18 * 6

        CHSEL = BitsField(25, AccessType.RW, 0, size=3)  # Channel selection
        DBM = BitsField(18, AccessType.RW, 0)  # Double buffer mode
        PINCOS = BitsField(15, AccessType.RW, 0)  # Peripheral increment offset size
        MSIZE = BitsField(13, AccessType.RW, 0, size=2)  # Memory data size
        PSIZE = BitsField(11, AccessType.RW, 0, size=2)  # Peripheral data size
        MINC = BitsField(10, AccessType.RW, 0)  # Memory increment mode
        PINC = BitsField(9, AccessType.RW, 0)  # Peripheral increment mode
        TCIE = BitsField(4, AccessType.RW, 0)  # TC (transfer complete) interrupt enable
        HTIE = BitsField(3, AccessType.RW, 0)  # HT (half transfer) interrupt enable
        TEIE = BitsField(2, AccessType.RW, 0)  # TE (transfer error) interrupt enable
        DMEIE = BitsField(
            1, AccessType.RW, 0
        )  # DME (direct mode error) interrupt enable
        EN = BitsField(0, AccessType.RW, 0)  # Stream enable

    class DMA_S6NDTR(BaseRegister):
        OFFSET = 0x14 + 0x18 * 6

        NDT = BitsField(
            0, AccessType.RW, 0, size=16
        )  # Number of data items to transfer

    class DMA_S6PAR(BaseRegister):
        OFFSET = 0x18 + 0x18 * 6

        PAR = BitsField(0, AccessType.RW, 0, size=32)  # Peripheral address

    class DMA_S6M0AR(BaseRegister):
        OFFSET = 0x1C + 0x18 * 6

        M0A = BitsField(0, AccessType.RW, 0, size=32)  # Memory 0 address

    class DMA_S6M1AR(BaseRegister):
        OFFSET = 0x20 + 0x18 * 6

        M1A = BitsField(0, AccessType.RW, 0, size=32)  # Memory 1 address

    class DMA_S6FCR(BaseRegister):
        OFFSET = 0x24 + 0x18 * 6

        FEIE = BitsField(7, AccessType.RW, 0)  # FE (FIFO error) interrupt enable

    def get_pending_irqs(self, state):
        s6cr = utils.load(state, self.start + DMA.DMA_S6CR.OFFSET)
        s6fcr = utils.load(state, self.start + DMA.DMA_S6FCR.OFFSET)
        events_to_check = []
        output = []

        if state.solver.is_true(s6cr[DMA.DMA_S6CR.HTIE.bit] == 1):
            events_to_check.extend(
                [(DMA.DMA_HISR.OFFSET, DMA.DMA_HISR.HTIF6.bit, self.IRQ_NUMBERS[6])]
            )

        if state.solver.is_true(s6cr[DMA.DMA_S6CR.TCIE.bit] == 1):
            events_to_check.extend(
                [(DMA.DMA_HISR.OFFSET, DMA.DMA_HISR.TCIF6.bit, self.IRQ_NUMBERS[6])]
            )

        if state.solver.is_true(s6cr[DMA.DMA_S6CR.TEIE.bit] == 1):
            events_to_check.extend(
                [(DMA.DMA_HISR.OFFSET, DMA.DMA_HISR.TEIF6.bit, self.IRQ_NUMBERS[6])]
            )

        if state.solver.is_true(s6fcr[DMA.DMA_S6FCR.FEIE.bit] == 1):
            events_to_check.extend(
                [(DMA.DMA_HISR.OFFSET, DMA.DMA_HISR.FEIF6.bit, self.IRQ_NUMBERS[6])]
            )

        if state.solver.is_true(s6cr[DMA.DMA_S6CR.DMEIE.bit] == 1):
            events_to_check.extend(
                [(DMA.DMA_HISR.OFFSET, DMA.DMA_HISR.DMEIF6.bit, self.IRQ_NUMBERS[6])]
            )

        for event_offset, event_bit, irq_num in events_to_check:
            event_val = utils.load(state, self.start + event_offset)[event_bit]
            trigger_cond = event_val == 1

            if state.solver.satisfiable(extra_constraints=[trigger_cond]):
                output.append((trigger_cond, {"irq": irq_num}))

        return output

    class _DMAHandler(EventForkHandler):
        def __init__(self, cpu, state, cfg, specs, dma):
            self.cpu = cpu
            self.specs = specs
            self.dma = dma

            for ckpt in self.get_checkpoints():
                ckpt.apply_to(state, handler=self)

        @cache
        def get_checkpoints(self):
            ckpts = set()

            # end addresses
            ckpts.update(self.cpu.get_end_addrs_ckpts(self.specs.END_ADDRS))

            # DMA synchronize instructions
            ckpts.update(self.cpu.get_dma_synchronize_instruction_checkpoints())

            # memory regions
            ckpts.add(
                BPConfig(
                    "mem_read", when=angr.BP_BEFORE, condition=self._bp_cond_mem_read
                )
            )
            ckpts.add(
                BPConfig(
                    "mem_write", when=angr.BP_BEFORE, condition=self._bp_cond_mem_write
                )
            )

            return ckpts

        def get_eligible_events(self, state):
            s6cr = utils.load(state, self.dma.start + DMA.DMA_S6CR.OFFSET)
            s6ndtr = utils.load(state, self.dma.start + DMA.DMA_S6NDTR.OFFSET)
            events_to_check = []
            output = []

            # channel select
            match state.solver.eval(
                s6cr[
                    DMA.DMA_S6CR.CHSEL.bit
                    + DMA.DMA_S6CR.CHSEL.size
                    - 1 : DMA.DMA_S6CR.CHSEL.bit
                ]
            ):
                case 1:  # I2C1_TX
                    i2c1_cr2 = utils.load(
                        state,
                        self.specs.MEMORY_REGIONS["I2C1"].start + I2C.I2C_CR2.OFFSET,
                    )

                    if state.solver.is_true(
                        claripy.And(
                            i2c1_cr2[I2C.I2C_CR2.DMAEN.bit] == 1,
                            s6cr[DMA.DMA_S6CR.EN.bit] == 1,
                            s6ndtr[
                                DMA.DMA_S6NDTR.NDT.bit
                                + DMA.DMA_S6NDTR.NDT.size
                                - 1 : DMA.DMA_S6NDTR.NDT.bit
                            ]
                            > 0,
                        )
                    ):
                        events_to_check.extend(
                            [
                                (
                                    self.specs.MEMORY_REGIONS["I2C1"].start
                                    + I2C.I2C_SR1.OFFSET,
                                    I2C.I2C_SR1.TXE.bit,
                                )
                            ]
                        )

            for event_addr, event_bit in events_to_check:
                event_val = utils.load(state, event_addr)[event_bit]
                trigger_cond = event_val == 1

                if state.solver.satisfiable(extra_constraints=[trigger_cond]):
                    output.append((trigger_cond, {}))

            return output

        def trigger_event(self, state):
            s6m0ar = utils.load(state, self.dma.start + DMA.DMA_S6M0AR.OFFSET)
            s6par = utils.load(state, self.dma.start + DMA.DMA_S6PAR.OFFSET)
            s6ndtr = utils.load(state, self.dma.start + DMA.DMA_S6NDTR.OFFSET)
            hisr = utils.load(state, self.dma.start + DMA.DMA_HISR.OFFSET)
            data = utils.load(
                state,
                s6m0ar[
                    DMA.DMA_S6M0AR.M0A.bit
                    + DMA.DMA_S6M0AR.M0A.size
                    - 1 : DMA.DMA_S6M0AR.M0A.bit
                ],
            )

            print(f"Perform DMA transfer | pc: {state.regs.pc}")
            state.memory.store(
                s6par[
                    DMA.DMA_S6PAR.PAR.bit
                    + DMA.DMA_S6PAR.PAR.size
                    - 1 : DMA.DMA_S6PAR.PAR.bit
                ],
                data,
            )
            utils.store(state, self.dma.start + DMA.DMA_S6NDTR.OFFSET, s6ndtr - 1)
            utils.store(
                state,
                self.dma.start + DMA.DMA_HISR.OFFSET,
                utils.replace_bit(hisr, DMA.DMA_HISR.TCIF6.bit, 1),
            )

        def _bp_cond_mem_op(self, state, addr):
            # 1. DMA MMIO
            if self.dma.in_region(addr):
                return True

            # 2. DMA source/destination region
            regions = []
            s6cr = utils.load(state, self.dma.start + DMA.DMA_S6CR.OFFSET)
            s6ndtr = utils.load(state, self.dma.start + DMA.DMA_S6NDTR.OFFSET)
            s6m0ar = utils.load(state, self.dma.start + DMA.DMA_S6M0AR.OFFSET)
            s6m1ar = utils.load(state, self.dma.start + DMA.DMA_S6M1AR.OFFSET)
            s6par = utils.load(state, self.dma.start + DMA.DMA_S6PAR.OFFSET)
            ndt = s6ndtr[
                DMA.DMA_S6NDTR.NDT.bit
                + DMA.DMA_S6NDTR.NDT.size
                - 1 : DMA.DMA_S6NDTR.NDT.bit
            ]
            msize_val = (
                1
                << s6cr[
                    DMA.DMA_S6CR.MSIZE.bit
                    + DMA.DMA_S6CR.MSIZE.size
                    - 1 : DMA.DMA_S6CR.MSIZE.bit
                ]
            )
            psize_val = (
                1
                << s6cr[
                    DMA.DMA_S6CR.PSIZE.bit
                    + DMA.DMA_S6CR.PSIZE.size
                    - 1 : DMA.DMA_S6CR.PSIZE.bit
                ]
            )

            if state.solver.is_true(s6cr[DMA.DMA_S6CR.EN.bit] == 1):
                if state.solver.is_true(s6cr[DMA.DMA_S6CR.MINC.bit] == 1):
                    regions.append((s6m0ar, ndt * psize_val))

                    if state.solver.is_true(s6cr[DMA.DMA_S6CR.DBM.bit] == 1):
                        regions.append((s6m1ar, ndt * psize_val))
                else:
                    regions.append((s6m0ar, msize_val))

                    if state.solver.is_true(s6cr[DMA.DMA_S6CR.DBM.bit] == 1):
                        regions.append((s6m1ar, msize_val))

            if state.solver.is_true(s6cr[DMA.DMA_S6CR.EN.bit] == 1):
                if state.solver.is_true(s6cr[DMA.DMA_S6CR.PINC.bit] == 1):
                    if state.solver.is_true(s6cr[DMA.DMA_S6CR.PINCOS.bit] == 1):
                        regions.append((s6par, ndt * 4))
                    else:
                        regions.append((s6par, ndt * psize_val))
                else:
                    regions.append((s6par, psize_val))

            for start, size in regions:
                if start <= addr < start + size:
                    return True

            return False

        def _bp_cond_mem_read(self, state):
            return self._bp_cond_mem_op(
                state, state.solver.eval(state.inspect.mem_read_address)
            )

        def _bp_cond_mem_write(self, state):
            return self._bp_cond_mem_op(
                state, state.solver.eval(state.inspect.mem_write_address)
            )

    def set_handlers(self, cpu, state, cfg, specs):
        self.dma_handler = DMA._DMAHandler(
            cpu=cpu, state=state, cfg=cfg, specs=specs, dma=self
        )
