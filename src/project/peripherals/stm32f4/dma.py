from collections import defaultdict

from project import utils
from project.peripherals.stm32f4.i2c import I2C
from project.types import AccessType, BaseRegister, BitsField, MMIOMemoryRegion


class DMA(MMIOMemoryRegion):
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

    class DMA_S6FCR(BaseRegister):
        OFFSET = 0x24 + 0x18 * 6

        FEIE = BitsField(7, AccessType.RW, 0)  # FE (FIFO error) interrupt enable

    def pre_inst(self, state):
        super().pre_inst(state)

        s6cr = utils.load(state, self.start + DMA.DMA_S6CR.OFFSET)

        # channel select
        match state.solver.eval(
            s6cr[
                DMA.DMA_S6CR.CHSEL.bit
                + DMA.DMA_S6CR.CHSEL.size
                - 1 : DMA.DMA_S6CR.CHSEL.bit
            ]
        ):
            case 1:  # I2C1_TX
                i2c1_sr1 = utils.load(
                    state, self.spec.MEMORY_REGIONS["I2C1"].start + I2C.I2C_SR1.OFFSET
                )
                s6m0ar = utils.load(state, self.start + DMA.DMA_S6M0AR.OFFSET)
                s6par = utils.load(state, self.start + DMA.DMA_S6PAR.OFFSET)
                data = utils.load(
                    state,
                    s6m0ar[
                        DMA.DMA_S6M0AR.M0A.bit
                        + DMA.DMA_S6M0AR.M0A.size
                        - 1 : DMA.DMA_S6M0AR.M0A.bit
                    ],
                )
                state.memory.store(
                    s6par[
                        DMA.DMA_S6PAR.PAR.bit
                        + DMA.DMA_S6PAR.PAR.size
                        - 1 : DMA.DMA_S6PAR.PAR.bit
                    ],
                    data,
                    condition=i2c1_sr1[I2C.I2C_SR1.TXE.bit] == 1,
                )

    def get_pending_irqs(self, state):
        s6cr = utils.load(state, self.start + DMA.DMA_S6CR.OFFSET)
        s6fcr = utils.load(state, self.start + DMA.DMA_S6FCR.OFFSET)
        events_to_check = []
        output = defaultdict(list)

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
                output[irq_num].append(trigger_cond)

        return output
