from dataclasses import dataclass
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
    DMA1_STREAM0_IRQ = 11
    DMA_MEMORY_TO_PERIPH = 1
    DMA1_STREAM6_IRQ = 17

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

    class DMA_HIFCR(BaseRegister):
        OFFSET = 0x0C

        CTCIF6 = BitsField(21, AccessType.W, 0)
        CHTIF6 = BitsField(20, AccessType.W, 0)
        CTEIF6 = BitsField(19, AccessType.W, 0)
        CDMEIF6 = BitsField(18, AccessType.W, 0)
        CFEIF6 = BitsField(16, AccessType.W, 0)

    class DMA_S6CR(BaseRegister):
        OFFSET = 0x10 + 0x18 * 6

        CHSEL = BitsField(25, AccessType.RW, 0, size=3)  # Channel selection
        DBM = BitsField(18, AccessType.RW, 0)  # Double buffer mode
        PINCOS = BitsField(15, AccessType.RW, 0)  # Peripheral increment offset size
        MSIZE = BitsField(13, AccessType.RW, 0, size=2)  # Memory data size
        PSIZE = BitsField(11, AccessType.RW, 0, size=2)  # Peripheral data size
        MINC = BitsField(10, AccessType.RW, 0)  # Memory increment mode
        PINC = BitsField(9, AccessType.RW, 0)  # Peripheral increment mode
        CIRC = BitsField(8, AccessType.RW, 0)  # Circular mode
        DIR = BitsField(6, AccessType.RW, 0, size=2)  # Data transfer direction
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

    def post_read(self, state):
        _, offset, readout_value = super().post_read(state)
        state.inspect.mem_read_expr = self.mask_post_read(offset, readout_value)
        return _, offset, state.inspect.mem_read_expr

    def post_write(self, state):
        addr, offset, value = super().post_write(state)

        match offset:
            case DMA.DMA_HIFCR.OFFSET:
                transaction = DMATransaction.begin(self, state)
                transaction.event_hifcr_write(value)
                transaction.commit()

        return addr, offset, value

    def get_pending_irqs(self, state):
        s6cr = utils.load(state, self.start + DMA.DMA_S6CR.OFFSET)
        s6fcr = utils.load(state, self.start + DMA.DMA_S6FCR.OFFSET)
        events_to_check = []
        output = []

        events_to_check.extend(
            [
                (
                    s6cr[DMA.DMA_S6CR.HTIE.bit] == 1,
                    DMA.DMA_HISR.OFFSET,
                    DMA.DMA_HISR.HTIF6.bit,
                    DMA.DMA1_STREAM6_IRQ,
                ),
                (
                    s6cr[DMA.DMA_S6CR.TCIE.bit] == 1,
                    DMA.DMA_HISR.OFFSET,
                    DMA.DMA_HISR.TCIF6.bit,
                    DMA.DMA1_STREAM6_IRQ,
                ),
                (
                    s6cr[DMA.DMA_S6CR.TEIE.bit] == 1,
                    DMA.DMA_HISR.OFFSET,
                    DMA.DMA_HISR.TEIF6.bit,
                    DMA.DMA1_STREAM6_IRQ,
                ),
                (
                    s6fcr[DMA.DMA_S6FCR.FEIE.bit] == 1,
                    DMA.DMA_HISR.OFFSET,
                    DMA.DMA_HISR.FEIF6.bit,
                    DMA.DMA1_STREAM6_IRQ,
                ),
                (
                    s6cr[DMA.DMA_S6CR.DMEIE.bit] == 1,
                    DMA.DMA_HISR.OFFSET,
                    DMA.DMA_HISR.DMEIF6.bit,
                    DMA.DMA1_STREAM6_IRQ,
                ),
            ]
        )

        for enable_cond, event_offset, event_bit, irq_num in events_to_check:
            event_val = utils.load(state, self.start + event_offset)[event_bit]
            trigger_cond = claripy.And(enable_cond, event_val == 1)

            if state.solver.satisfiable(extra_constraints=[trigger_cond]):
                output.append((trigger_cond, {"irq": irq_num}))

        return output

    class _DMAHandler(EventForkHandler):
        NO_EVENT_CONSTRAINS_STATE = False

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
            s6par = utils.load(state, self.dma.start + DMA.DMA_S6PAR.OFFSET)
            i2c1_cr2 = utils.load(
                state, self.specs.MEMORY_REGIONS["I2C1"].start + I2C.I2C_CR2.OFFSET
            )
            i2c1_sr1 = utils.load(
                state, self.specs.MEMORY_REGIONS["I2C1"].start + I2C.I2C_SR1.OFFSET
            )
            i2c1_dr_addr = (
                self.specs.MEMORY_REGIONS["I2C1"].start + I2C.I2C_DR.OFFSET
            )
            channel = s6cr[
                DMA.DMA_S6CR.CHSEL.bit
                + DMA.DMA_S6CR.CHSEL.size
                - 1 : DMA.DMA_S6CR.CHSEL.bit
            ]
            direction = s6cr[
                DMA.DMA_S6CR.DIR.bit
                + DMA.DMA_S6CR.DIR.size
                - 1 : DMA.DMA_S6CR.DIR.bit
            ]
            msize = s6cr[
                DMA.DMA_S6CR.MSIZE.bit
                + DMA.DMA_S6CR.MSIZE.size
                - 1 : DMA.DMA_S6CR.MSIZE.bit
            ]
            psize = s6cr[
                DMA.DMA_S6CR.PSIZE.bit
                + DMA.DMA_S6CR.PSIZE.size
                - 1 : DMA.DMA_S6CR.PSIZE.bit
            ]
            ndt = s6ndtr[
                DMA.DMA_S6NDTR.NDT.bit
                + DMA.DMA_S6NDTR.NDT.size
                - 1 : DMA.DMA_S6NDTR.NDT.bit
            ]
            par = s6par[
                DMA.DMA_S6PAR.PAR.bit
                + DMA.DMA_S6PAR.PAR.size
                - 1 : DMA.DMA_S6PAR.PAR.bit
            ]
            trigger_cond = claripy.And(
                channel == 1,  # I2C1_TX
                direction == DMA.DMA_MEMORY_TO_PERIPH,
                par == i2c1_dr_addr,
                msize == 0,
                psize == 0,
                i2c1_cr2[I2C.I2C_CR2.DMAEN.bit] == 1,
                s6cr[DMA.DMA_S6CR.EN.bit] == 1,
                ndt > 0,
                i2c1_sr1[I2C.I2C_SR1.TXE.bit] == 1,
            )

            if state.solver.satisfiable(extra_constraints=[trigger_cond]):
                return [(trigger_cond, {})]
            return []

        def trigger_event(self, state):
            s6cr = utils.load(state, self.dma.start + DMA.DMA_S6CR.OFFSET)
            s6m0ar = utils.load(state, self.dma.start + DMA.DMA_S6M0AR.OFFSET)
            s6par = utils.load(state, self.dma.start + DMA.DMA_S6PAR.OFFSET)
            s6ndtr = utils.load(state, self.dma.start + DMA.DMA_S6NDTR.OFFSET)
            hisr = utils.load(state, self.dma.start + DMA.DMA_HISR.OFFSET)
            ndt = s6ndtr[
                DMA.DMA_S6NDTR.NDT.bit
                + DMA.DMA_S6NDTR.NDT.size
                - 1 : DMA.DMA_S6NDTR.NDT.bit
            ]
            msize_code = s6cr[
                DMA.DMA_S6CR.MSIZE.bit
                + DMA.DMA_S6CR.MSIZE.size
                - 1 : DMA.DMA_S6CR.MSIZE.bit
            ]
            psize_code = s6cr[
                DMA.DMA_S6CR.PSIZE.bit
                + DMA.DMA_S6CR.PSIZE.size
                - 1 : DMA.DMA_S6CR.PSIZE.bit
            ]
            msize_bytes = 1 << state.solver.eval_one(msize_code)
            psize_bytes = 1 << state.solver.eval_one(psize_code)
            data = utils.load(
                state,
                s6m0ar[
                    DMA.DMA_S6M0AR.M0A.bit
                    + DMA.DMA_S6M0AR.M0A.size
                    - 1 : DMA.DMA_S6M0AR.M0A.bit
                ],
                size=msize_bytes,
            )
            if data.size() > psize_bytes * 8:
                data = data[psize_bytes * 8 - 1 : 0]
            elif data.size() < psize_bytes * 8:
                data = data.zero_extend(psize_bytes * 8 - data.size())

            next_ndt = ndt - 1
            transfer_complete = next_ndt == 0
            state.memory.store(
                s6par[
                    DMA.DMA_S6PAR.PAR.bit
                    + DMA.DMA_S6PAR.PAR.size
                    - 1 : DMA.DMA_S6PAR.PAR.bit
                ],
                data,
                size=psize_bytes,
                endness=state.arch.memory_endness,
            )

            new_s6ndtr = claripy.Concat(
                s6ndtr[
                    state.arch.bits - 1 : DMA.DMA_S6NDTR.NDT.bit
                    + DMA.DMA_S6NDTR.NDT.size
                ],
                next_ndt,
            )
            utils.store(state, self.dma.start + DMA.DMA_S6NDTR.OFFSET, new_s6ndtr)

            new_s6m0ar = claripy.If(
                s6cr[DMA.DMA_S6CR.MINC.bit] == 1, s6m0ar + msize_bytes, s6m0ar
            )
            new_s6par = claripy.If(
                s6cr[DMA.DMA_S6CR.PINC.bit] == 1, s6par + psize_bytes, s6par
            )
            utils.store(state, self.dma.start + DMA.DMA_S6M0AR.OFFSET, new_s6m0ar)
            utils.store(state, self.dma.start + DMA.DMA_S6PAR.OFFSET, new_s6par)

            new_s6cr = utils.replace_bit(
                s6cr,
                DMA.DMA_S6CR.EN.bit,
                claripy.If(
                    claripy.And(transfer_complete, s6cr[DMA.DMA_S6CR.CIRC.bit] == 0),
                    claripy.BVV(0, 1),
                    s6cr[DMA.DMA_S6CR.EN.bit],
                ),
            )
            utils.store(state, self.dma.start + DMA.DMA_S6CR.OFFSET, new_s6cr)

            utils.store(
                state,
                self.dma.start + DMA.DMA_HISR.OFFSET,
                utils.replace_bit(
                    hisr,
                    DMA.DMA_HISR.TCIF6.bit,
                    claripy.If(
                        transfer_complete,
                        claripy.BVV(1, 1),
                        hisr[DMA.DMA_HISR.TCIF6.bit],
                    ),
                ),
            )

        def _bp_cond_mem_op(self, state, addr):
            # 1. DMA MMIO
            if self.dma.in_region(state.solver.eval(addr)):
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

            ndt = ndt.zero_extend(state.arch.bits - ndt.size())
            msize_val = msize_val.zero_extend(state.arch.bits - msize_val.size())
            psize_val = psize_val.zero_extend(state.arch.bits - psize_val.size())

            if state.solver.is_true(s6cr[DMA.DMA_S6CR.EN.bit] == 1):
                if state.solver.is_true(s6cr[DMA.DMA_S6CR.MINC.bit] == 1):
                    regions.append((s6m0ar, ndt * msize_val))

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
                if state.solver.satisfiable(
                    extra_constraints=[start <= addr, addr < start + size]
                ):
                    return True

            return False

        def _bp_cond_mem_read(self, state):
            return self._bp_cond_mem_op(state, state.inspect.mem_read_address)

        def _bp_cond_mem_write(self, state):
            return self._bp_cond_mem_op(state, state.inspect.mem_write_address)

    def set_handlers(self, cpu, state, cfg, specs):
        self.dma_handler = DMA._DMAHandler(
            cpu=cpu, state=state, cfg=cfg, specs=specs, dma=self
        )


@dataclass
class DMARegisterState:
    hisr: object


class DMATransaction:
    HIFCR_CLEAR_MASK = (
        DMA.DMA_HIFCR.CTCIF6.mask
        | DMA.DMA_HIFCR.CHTIF6.mask
        | DMA.DMA_HIFCR.CTEIF6.mask
        | DMA.DMA_HIFCR.CDMEIF6.mask
        | DMA.DMA_HIFCR.CFEIF6.mask
    )

    def __init__(self, dma, state, old, new):
        self.dma = dma
        self.state = state
        self.old = old
        self.new = new

    @classmethod
    def begin(cls, dma, state):
        snapshot = DMARegisterState(
            hisr=utils.load(state, dma.start + DMA.DMA_HISR.OFFSET)
        )
        working = DMARegisterState(hisr=snapshot.hisr)
        return cls(dma, state, snapshot, working)

    def commit(self):
        utils.store(self.state, self.dma.start + DMA.DMA_HISR.OFFSET, self.new.hisr)

    def event_hifcr_write(self, value):
        clear_mask = value & self.HIFCR_CLEAR_MASK
        self.new.hisr = self.new.hisr & ~clear_mask
