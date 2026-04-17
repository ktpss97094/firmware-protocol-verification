from collections import defaultdict

import claripy

from project import utils
from project.types import AccessType, BaseRegister, BitsField, MMIOMemoryRegion


class I2C(MMIOMemoryRegion):
    IRQ_NUMBERS = [31, 32]  # I2C1_EV, I2C1_ER

    class I2C_CR1(BaseRegister):
        OFFSET = 0x00

        STOP = BitsField(9, AccessType.RW, 0)
        START = BitsField(8, AccessType.RW, 0)
        NOSTRETCH = BitsField(7, AccessType.RW, 0)
        PE = BitsField(0, AccessType.RW, 0)

        @classmethod
        def update_STOP(cls, i2c, state, cr1, sr1, sr2, force=False):
            if force or not state.solver.unique(cr1[cls.STOP.bit]):
                # if force or cr1[cls.STOP.bit].symbolic:
                # (STOP) cleared by hardware when a Stop condition is detected
                cr1 = utils.replace_bit(
                    cr1,
                    cls.STOP.bit,
                    claripy.If(
                        cr1[cls.STOP.bit] == 0,
                        cr1[cls.STOP.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_STOP", size=1),
                    ),
                )

                # (TxE) Cleared ... or by hardware after ... or a stop condition
                sr1 = utils.replace_bit(
                    sr1,
                    I2C.I2C_SR1.TXE.bit,
                    claripy.If(
                        cr1[cls.STOP.bit] == 0,
                        claripy.BVV(0, 1),
                        sr1[I2C.I2C_SR1.TXE.bit],
                    ),
                )

                # (BTF) Cleared ... or by hardware after ... or a stop condition in transmission
                sr1 = utils.replace_bit(
                    sr1,
                    I2C.I2C_SR1.BTF.bit,
                    claripy.If(
                        claripy.And(
                            cr1[cls.STOP.bit] == 0, sr2[I2C.I2C_SR2.TRA.bit] == 1
                        ),
                        claripy.BVV(0, 1),
                        sr1[I2C.I2C_SR1.BTF.bit],
                    ),
                )

            return cr1, sr1

    class I2C_CR2(BaseRegister):
        OFFSET = 0x04

        ITBUFEN = BitsField(10, AccessType.RW, 0)
        ITEVTEN = BitsField(9, AccessType.RW, 0)
        ITERREN = BitsField(8, AccessType.RW, 0)

    class I2C_DR(BaseRegister):
        OFFSET = 0x10

        DR = BitsField(0, AccessType.RW, 0, size=8)

    class I2C_SR1(BaseRegister):
        OFFSET = 0x14

        SMBALERT = BitsField(15, AccessType.RC_W0, 0)
        TIMEOUT = BitsField(14, AccessType.RC_W0, 0)
        PECERR = BitsField(12, AccessType.RC_W0, 0)
        OVR = BitsField(11, AccessType.RC_W0, 0)
        AF = BitsField(10, AccessType.RC_W0, 0)
        ARLO = BitsField(9, AccessType.RC_W0, 0)
        BERR = BitsField(8, AccessType.RC_W0, 0)
        TXE = BitsField(7, AccessType.R, 0)
        RXNE = BitsField(6, AccessType.R, 0)
        STOPF = BitsField(4, AccessType.R, 0)
        ADD10 = BitsField(3, AccessType.R, 0)
        BTF = BitsField(2, AccessType.R, 0)
        ADDR = BitsField(1, AccessType.R, 0)
        SB = BitsField(0, AccessType.R, 0)

        @classmethod
        def update_AF(cls, i2c, state, sr1, cr1, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.AF.bit]):
                # if force or sr1[cls.AF.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.AF.bit] == 1,
                        sr1[cls.AF.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_AF", size=1),
                    )
                # (AF) Cleared ... or by hardware when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.AF.bit, value)

                # (ARLO) Set by hardware when the interface loses the arbitration of the bus to another master
                sr1 = utils.replace_bit(
                    sr1,
                    cls.ARLO.bit,
                    claripy.If(
                        sr1[cls.AF.bit] == 1, claripy.BVV(0, 1), sr1[cls.ARLO.bit]
                    ),
                )

            return sr1

        @classmethod
        def update_ARLO(cls, i2c, state, sr1, cr1, sr2, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.ARLO.bit]):
                # if force or sr1[cls.ARLO.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.ARLO.bit] == 1,
                        sr1[cls.ARLO.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_ARLO", size=1),
                    )
                # (ARLO) Cleared ... or by hardware when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.ARLO.bit, value)

                # (TRA) It is also cleared by hardware after ..., loss of bus arbitration (ARLO=1)
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.TRA.bit,
                    claripy.If(
                        sr1[cls.ARLO.bit] == 1,
                        claripy.BVV(0, 1),
                        sr2[I2C.I2C_SR2.TRA.bit],
                    ),
                )

            return sr1, sr2

        @classmethod
        def update_TXE(cls, i2c, state, sr1, cr1, sr2, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.TXE.bit]):
                # if force or sr1[cls.TXE.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.TXE.bit] == 1,
                        sr1[cls.TXE.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_TXE", size=1),
                    )
                # (TxE) Cleared ... or when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.TXE.bit, value)

                # (BTF) Set by hardware when NOSTRETCH=0 and: ... In transmission when a new byte should be sent and DR has not been written yet (TxE=1)
                # 只有 TxE 是 1 時，BTF 才可能是 1
                sr1 = utils.replace_bit(
                    sr1,
                    cls.BTF.bit,
                    claripy.If(
                        claripy.Or(
                            cr1[I2C.I2C_CR1.NOSTRETCH.bit] == 1,
                            claripy.And(
                                sr2[I2C.I2C_SR2.TRA.bit] == 1, sr1[cls.TXE.bit] == 0
                            ),
                            claripy.And(
                                sr2[I2C.I2C_SR2.TRA.bit] == 0, sr1[cls.RXNE.bit] == 0
                            ),
                        ),
                        claripy.BVV(0, 1),
                        sr1[cls.BTF.bit],
                    ),
                )

                # (AF) Set by hardware when no acknowledge is returned
                sr1 = utils.replace_bit(
                    sr1,
                    cls.AF.bit,
                    claripy.If(
                        sr1[cls.TXE.bit] == 1, claripy.BVV(0, 1), sr1[cls.AF.bit]
                    ),
                )

                # (ARLO) Set by hardware when the interface loses the arbitration of the bus to another master
                sr1 = utils.replace_bit(
                    sr1,
                    cls.ARLO.bit,
                    claripy.If(
                        sr1[cls.TXE.bit] == 1, claripy.BVV(0, 1), sr1[cls.ARLO.bit]
                    ),
                )

            return sr1

        @classmethod
        def update_STOPF():
            pass

            # TODO: (TxE) Cleared ... or by hardware after ... a stop condition

            # TODO: (AF) Set by hardware when no acknowledge is returned
            # sr1 = utils.replace_bit(
            #     sr1,
            #     cls.AF.bit,
            #     claripy.If(
            #         sr1[cls.STOPF.bit] == 1, claripy.BVV(0, 1), sr1[cls.AF.bit]
            #     ),
            # )

            # TODO: (TRA) It is also cleared by hardware after detection of Stop condition (STOPF=1)
            # sr2 = utils.replace_bit(
            #     sr2,
            #     I2C.I2C_SR2.TRA.bit,
            #     claripy.If(
            #         sr1[cls.STOPF.bit] == 1, claripy.BVV(0, 1), sr2[I2C.I2C_SR2.TRA.bit]
            #     ),
            # )

        @classmethod
        def update_ADD10(cls, i2c, state, sr1, cr1, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.ADD10.bit]):
                # if force or sr1[cls.ADD10.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.ADD10.bit] == 1,
                        sr1[cls.ADD10.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_ADD10", size=1),
                    )
                # (ADD10) Cleared ... or by hardware when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.ADD10.bit, value)

                # (AF) Set by hardware when no acknowledge is returned
                sr1 = utils.replace_bit(
                    sr1,
                    cls.AF.bit,
                    claripy.If(
                        sr1[cls.ADD10.bit] == 1, claripy.BVV(0, 1), sr1[cls.AF.bit]
                    ),
                )

                # (ARLO) Set by hardware when the interface loses the arbitration of the bus to another master
                sr1 = utils.replace_bit(
                    sr1,
                    cls.ARLO.bit,
                    claripy.If(
                        sr1[cls.ADD10.bit] == 1, claripy.BVV(0, 1), sr1[cls.ARLO.bit]
                    ),
                )

            return sr1

        @classmethod
        def update_BTF(cls, i2c, state, sr1, cr1, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.BTF.bit]):
                # if force or sr1[cls.BTF.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.BTF.bit] == 1,
                        sr1[cls.BTF.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_BTF", size=1),
                    )
                # (BTF) Cleared ... or when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.BTF.bit, value)

                # (AF) Set by hardware when no acknowledge is returned
                sr1 = utils.replace_bit(
                    sr1,
                    cls.AF.bit,
                    claripy.If(
                        sr1[cls.BTF.bit] == 1, claripy.BVV(0, 1), sr1[cls.AF.bit]
                    ),
                )

                # (ARLO) Set by hardware when the interface loses the arbitration of the bus to another master
                sr1 = utils.replace_bit(
                    sr1,
                    cls.ARLO.bit,
                    claripy.If(
                        sr1[cls.BTF.bit] == 1, claripy.BVV(0, 1), sr1[cls.ARLO.bit]
                    ),
                )

            return sr1

        @classmethod
        def update_ADDR(cls, i2c, state, sr1, cr1, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.ADDR.bit]):
                # if force or sr1[cls.ADDR.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.ADDR.bit] == 1,
                        sr1[cls.ADDR.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_ADDR", size=1),
                    )
                # (ADDR) This bit is cleared ... or by hardware when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.ADDR.bit, value)

                # (AF) Set by hardware when no acknowledge is returned
                sr1 = utils.replace_bit(
                    sr1,
                    cls.AF.bit,
                    claripy.If(
                        sr1[cls.ADDR.bit] == 1, claripy.BVV(0, 1), sr1[cls.AF.bit]
                    ),
                )

                # (ARLO) Set by hardware when the interface loses the arbitration of the bus to another master
                sr1 = utils.replace_bit(
                    sr1,
                    cls.ARLO.bit,
                    claripy.If(
                        sr1[cls.ADDR.bit] == 1, claripy.BVV(0, 1), sr1[cls.ARLO.bit]
                    ),
                )

            return sr1

        @classmethod
        def update_SB(cls, i2c, state, sr1, cr1, sr2, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.SB.bit]):
                # if force or sr1[cls.SB.bit].symbolic:
                if value is None:
                    value = claripy.If(
                        sr1[cls.SB.bit] == 1,
                        sr1[cls.SB.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_SB", size=1),
                    )
                # (SB) Cleared ... or by hardware when PE=0
                value = claripy.If(
                    cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                )
                sr1 = utils.replace_bit(sr1, cls.SB.bit, value)

                # (START) This bit is ... and cleared by hardware when start is sent or PE=0
                cr1 = utils.replace_bit(
                    cr1,
                    I2C.I2C_CR1.START.bit,
                    claripy.If(
                        claripy.Or(sr1[cls.SB.bit] == 1, cr1[I2C.I2C_CR1.PE.bit] == 0),
                        claripy.BVV(0, 1),
                        cr1[
                            I2C.I2C_CR1.START.bit
                        ],  # START 不是隨時可能變的，是 SB set 後才會 clear，所以不用 generate symbolic 也不用設定 sticky 1
                    ),
                )

                # (TxE) Cleared ... or by hardware after a start ... condition
                sr1 = utils.replace_bit(
                    sr1,
                    cls.TXE.bit,
                    claripy.If(
                        sr1[cls.SB.bit] == 1, claripy.BVV(0, 1), sr1[cls.TXE.bit]
                    ),
                )

                # (BTF) Cleared ... or by hardware after a start ... condition in transmission
                sr1 = utils.replace_bit(
                    sr1,
                    cls.BTF.bit,
                    claripy.If(
                        sr1[cls.SB.bit] == 1, claripy.BVV(0, 1), sr1[cls.BTF.bit]
                    ),
                )

                # (TRA) It is also cleared by hardware after ..., repeated Start condition
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.TRA.bit,
                    claripy.If(
                        sr1[cls.SB.bit] == 1,
                        claripy.BVV(0, 1),
                        sr2[I2C.I2C_SR2.TRA.bit],
                    ),
                )

            return sr1, cr1, sr2

    class I2C_SR2(BaseRegister):
        OFFSET = 0x18

        TRA = BitsField(2, AccessType.R, 0)

    def pre_write(self, state):
        addr, offset, value = super().pre_write(state)

        orig_value = utils.load(state, addr)

        state.inspect.mem_write_expr = self.mask_pre_write(offset, orig_value, value)

        return addr, offset, state.inspect.mem_write_expr

    def post_read(self, state):
        _, offset, readout_value = super().post_read(state)

        new_cr1 = utils.load(state, self.start + I2C.I2C_CR1.OFFSET)
        new_sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        new_sr2 = utils.load(state, self.start + I2C.I2C_SR2.OFFSET)

        match offset:
            case I2C.I2C_SR1.OFFSET:
                state.globals[f"{self.name}_SR1_read"] = True

                # 目前寫的方式下，ARLO 需要比 AF 早 update，因為 update_AF 會新增 claripy.If(AF == 1, 0, ARLO)。如果 update_AF 先執行，update_ARLO 會被蓋過
                new_sr1, new_sr2 = I2C.I2C_SR1.update_ARLO(
                    self, state, new_sr1, new_cr1, new_sr2
                )
                # 目前寫的方式下，AF 需要比 ADD10, ADDR, TxE, BTF 等早 update，因為這些 bit 的 update function 會新增 claripy.If(bit == 1, 0, AF)。如果 update_* 先執行，update_AF 會被蓋過
                new_sr1 = I2C.I2C_SR1.update_AF(self, state, new_sr1, new_cr1)
                new_sr1 = I2C.I2C_SR1.update_ADD10(self, state, new_sr1, new_cr1)
                new_sr1 = I2C.I2C_SR1.update_ADDR(self, state, new_sr1, new_cr1)
                # 目前寫的方式下，TXE 需要比 SB 早 update，因為 update_SB 會新增 claripy.If(SB == 1, 0, TxE)。如果 update_SB 先執行，update_TXE 會被蓋過
                new_sr1 = I2C.I2C_SR1.update_BTF(self, state, new_sr1, new_cr1)
                new_sr1 = I2C.I2C_SR1.update_TXE(self, state, new_sr1, new_cr1, new_sr2)
                new_sr1, new_cr1, new_sr2 = I2C.I2C_SR1.update_SB(
                    self, state, new_sr1, new_cr1, new_sr2
                )

            case I2C.I2C_SR2.OFFSET:
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    new_sr1 = I2C.I2C_SR1.update_ADDR(
                        self, state, new_sr1, new_cr1, force=True, value=0
                    )
                    # clear ADDR 時結束 address phase
                    state.globals["is_address_phase"] = False

                    # (TRA) This bit is set depending on the R/W bit of the address byte, at the end of total address phase
                    new_sr2 = utils.replace_bit(
                        new_sr2, I2C.I2C_SR2.TRA.bit, ~state.globals["R/W"]
                    )

                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    if state.solver.is_true(new_sr2[I2C.I2C_SR2.TRA.bit] == 1):
                        new_sr1 = I2C.I2C_SR1.update_TXE(
                            self, state, new_sr1, new_cr1, new_sr2, force=True, value=1
                        )

            case I2C.I2C_DR.OFFSET:
                # (BTF) Cleared by software by either a read ... in the DR register
                new_sr1 = I2C.I2C_SR1.update_BTF(
                    self, state, new_sr1, new_cr1, force=True, value=0
                )

        utils.store(state, self.start + I2C.I2C_CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.I2C_SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.I2C_SR2.OFFSET, new_sr2)

        state.inspect.mem_read_expr = self.mask_post_read(offset, readout_value)

    def post_write(self, state):
        _, offset, value = super().post_write(state)

        new_cr1 = utils.load(state, self.start + I2C.I2C_CR1.OFFSET)
        new_sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        new_sr2 = utils.load(state, self.start + I2C.I2C_SR2.OFFSET)

        match offset:
            case I2C.I2C_CR1.OFFSET:
                # set START bit 時進入 address phase
                if state.solver.is_true(value[I2C.I2C_CR1.START.bit] == 1):
                    state.globals["is_address_phase"] = True

                    # (SB) Set when a Start condition generated
                    new_sr1, new_cr1, new_sr2 = I2C.I2C_SR1.update_SB(
                        self, state, new_sr1, new_cr1, new_sr2, force=True
                    )

                # set STOP bit
                if state.solver.is_true(value[I2C.I2C_CR1.STOP.bit] == 1):
                    new_cr1, new_sr1 = I2C.I2C_CR1.update_STOP(
                        self, state, new_cr1, new_sr1, new_sr2, force=True
                    )

            case I2C.I2C_DR.OFFSET:
                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either ... or write in the DR register
                # 目前寫的方式下，BTF 需要比 TXE 早 update，因為 update_TXE 會新增 claripy.If(TXE == 0, 0, BTF)。如果 update_TXE 先執行，update_BTF 會被蓋過
                new_sr1 = I2C.I2C_SR1.update_BTF(
                    self, state, new_sr1, new_cr1, force=True, value=0
                )
                new_sr1 = I2C.I2C_SR1.update_TXE(
                    self, state, new_sr1, new_cr1, new_sr2, force=True, value=0
                )

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    new_sr1, new_cr1, new_sr2 = I2C.I2C_SR1.update_SB(
                        self, state, new_sr1, new_cr1, new_sr2, force=True, value=0
                    )

                # 目前寫的方式下，ARLO 需要比 AF 早 update，因為 update_AF 會新增 claripy.If(AF == 1, 0, ARLO)。如果 update_AF 先執行，update_ARLO 會被蓋過
                new_sr1, new_sr2 = I2C.I2C_SR1.update_ARLO(
                    self, state, new_sr1, new_cr1, new_sr2, force=True
                )
                # 目前寫的方式下，AF 需要比 ADD10, ADDR, TxE, BTF 等早 update，因為這些 bit 的 update function 會新增 claripy.If(bit == 1, 0, AF)。如果 update_* 先執行，update_AF 會被蓋過
                new_sr1 = I2C.I2C_SR1.update_AF(
                    self, state, new_sr1, new_cr1, force=True
                )
                if state.globals.get("is_address_phase", False):
                    # 10-bit addressing 的 addressing phase 會 write 兩次 DR。第一次 write (header) 時是 11110XXY (Y 為 R/W)
                    if not state.solver.satisfiable(
                        extra_constraints=[(value & 0xF8) != 0xF0]
                    ):
                        state.globals["is_10bit"] = True

                        # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                        new_sr1 = I2C.I2C_SR1.update_ADD10(
                            self, state, new_sr1, new_cr1, force=True
                        )
                    else:
                        if state.globals.get("is_10bit", False) and state.globals.get(
                            f"{self.name}_SR1_read", False
                        ):
                            state.globals[f"{self.name}_SR1_read"] = False

                            # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                            new_sr1 = I2C.I2C_SR1.update_ADD10(
                                self, state, new_sr1, new_cr1, force=True, value=0
                            )

                        # (ADDR) For 10-bit addressing, the bit is set after the ACK of the 2nd byte. For 7-bit addressing, the bit is set after the ACK of the byte
                        new_sr1 = I2C.I2C_SR1.update_ADDR(
                            self, state, new_sr1, new_cr1, force=True
                        )

                    state.globals["R/W"] = value[0]
                else:
                    # 目前寫的方式下，BTF 需要比 TXE 早 update，因為 update_TXE 會新增 claripy.If(TXE == 0, 0, BTF)。如果 update_TXE 先執行，update_BTF 會被蓋過
                    new_sr1 = I2C.I2C_SR1.update_BTF(
                        self, state, new_sr1, new_cr1, force=True
                    )
                    new_sr1 = I2C.I2C_SR1.update_TXE(
                        self, state, new_sr1, new_cr1, new_sr2, force=True
                    )

        utils.store(state, self.start + I2C.I2C_CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.I2C_SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.I2C_SR2.OFFSET, new_sr2)

    def get_pending_irqs(self, state):
        cr2 = utils.load(state, self.start + I2C.I2C_CR2.OFFSET)
        events_to_check = []
        output = defaultdict(list)

        if state.solver.is_true(cr2[I2C.I2C_CR2.ITEVTEN.bit] == 1):
            events_to_check.extend(
                [
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.SB.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.ADDR.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.ADD10.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.BTF.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.STOPF.bit, self.IRQ_NUMBERS[0]),
                ]
            )

            if state.solver.is_true(cr2[I2C.I2C_CR2.ITBUFEN.bit] == 1):
                events_to_check.extend(
                    [
                        (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.TXE.bit, self.IRQ_NUMBERS[0]),
                        (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.RXNE.bit, self.IRQ_NUMBERS[0]),
                    ]
                )

        if state.solver.is_true(cr2[I2C.I2C_CR2.ITERREN.bit] == 1):
            events_to_check.extend(
                [
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.BERR.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.ARLO.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.AF.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.OVR.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.PECERR.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.TIMEOUT.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.SMBALERT.bit, self.IRQ_NUMBERS[1]),
                ]
            )

        for event_offset, event_bit, irq_num in events_to_check:
            event_val = utils.load(state, self.start + event_offset)[event_bit]
            trigger_cond = event_val == 1

            if state.solver.satisfiable(extra_constraints=[trigger_cond]):
                output[irq_num].append((event_val, trigger_cond))

        return output
