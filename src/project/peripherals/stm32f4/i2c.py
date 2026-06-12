import claripy
from angr.errors import SimMergeError
from angr.state_plugins.plugin import SimStatePlugin

from project import utils
from project.types import AccessType, BaseRegister, BitsField, MMIOMemoryRegion


class Globals(SimStatePlugin):
    def __init__(self, is_address_phase=None, rw=None, sr1_read=None):
        super().__init__()

        self.is_address_phase = (
            claripy.false() if is_address_phase is None else is_address_phase
        )
        self.rw = rw
        self.sr1_read = False if sr1_read is None else sr1_read

    def copy(self, memo):
        o = super().copy(memo)

        o.is_address_phase = self.is_address_phase
        o.rw = self.rw
        o.sr1_read = self.sr1_read

        return o

    def merge(self, others, merge_conditions, common_ancestor=None):
        """
        回傳值表示 plugins 是否有被 merge，並不是 state 是否有被 merge。只有 raise SimMergeError 時才表示 state 不被 merge
        """

        # 如果 plugin 內部沒有更深層的物件需要合併，可以直接忽略 common_ancestor
        del common_ancestor

        if any(
            not utils.same_ast(self.is_address_phase, other.is_address_phase)
            or self.sr1_read != other.sr1_read
            for other in others
        ):
            raise SimMergeError(
                "Cannot merge STM32F4 I2C globals (is_address_phase or sr1_read)"
            )

        all_others_rw_none = all(other.rw is None for other in others)
        # 所有的 rw 都是 None: plugins 沒有被合併
        if self.rw is None and all_others_rw_none:
            return False
        # 其中一個 rw 是 None，另一個不是: 狀態不同，state 不合併
        if self.rw is None or all_others_rw_none:
            raise SimMergeError("Cannot merge STM32F4 I2C globals (rw)")

        # static analysis 時 merge_conditions 可以是 None，依照官方建議用 state.solver.union
        if merge_conditions is None:
            merged_rw = self.state.solver.union(
                [self.rw] + [other.rw for other in others]
            )
        else:
            # merge_conditions[0] 是 self 的
            # 由於 merge 特性 (有共同 ancestor)，merge_conditions[0] | merge_conditions[1] | ... = True，所以如果 merge_conditions[1] | ... 是 False 的話，那 merge_condition[0] 一定為 True，而這個路徑代表的值就是 self.rw
            merged_rw = claripy.ite_cases(
                zip(merge_conditions[1:], [other.rw for other in others]), self.rw
            )

        changed = not utils.same_ast(self.rw, merged_rw)
        self.rw = merged_rw
        return changed


class I2C(MMIOMemoryRegion):
    IRQ_NUMBERS = [31, 32]  # I2C1_EV, I2C1_ER

    # TODO: PE bit

    class I2C_CR1(BaseRegister):
        OFFSET = 0x00

        STOP = BitsField(9, AccessType.RW, 0)
        START = BitsField(8, AccessType.RW, 0)
        NOSTRETCH = BitsField(7, AccessType.RW, 0)
        PE = BitsField(0, AccessType.RW, 0)

        @classmethod
        def update_STOP(cls, i2c, state, cr1, sr1, sr2, force=False):
            if force or not state.solver.unique(cr1[cls.STOP.bit]):
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

                # (MSL) Cleared by hardware after detecting a Stop condition
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.MSL.bit,
                    claripy.If(
                        cr1[cls.STOP.bit] == 0,
                        claripy.BVV(0, 1),
                        sr2[I2C.I2C_SR2.MSL.bit],
                    ),
                )

                # (BUSY) cleared by hardware on detection of a Stop condition
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.BUSY.bit,
                    claripy.If(
                        cr1[cls.STOP.bit] == 0,
                        claripy.BVV(0, 1),
                        sr2[I2C.I2C_SR2.BUSY.bit],
                    ),
                )

            return cr1, sr1, sr2

    class I2C_CR2(BaseRegister):
        OFFSET = 0x04

        DMAEN = BitsField(11, AccessType.RW, 0)
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
                if value is None:
                    value = claripy.If(
                        sr1[cls.AF.bit] == 1,
                        sr1[cls.AF.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_AF", size=1),
                    )
                # (AF) Cleared ... or by hardware when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
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
                if value is None:
                    value = claripy.If(
                        sr1[cls.ARLO.bit] == 1,
                        sr1[cls.ARLO.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_ARLO", size=1),
                    )
                # (ARLO) Cleared ... or by hardware when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
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

                # (MSL) Cleared by hardware after ... or a loss of arbitration (ARLO=1)
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.MSL.bit,
                    claripy.If(
                        sr1[cls.ARLO.bit] == 1,
                        claripy.BVV(0, 1),
                        sr2[I2C.I2C_SR2.MSL.bit],
                    ),
                )

                # (RxNE) RxNE is not set in case of ARLO event
                sr1 = utils.replace_bit(
                    sr1,
                    I2C.I2C_SR1.RXNE.bit,
                    claripy.If(
                        sr1[cls.ARLO.bit] == 1,
                        claripy.BVV(0, 1),
                        sr1[I2C.I2C_SR1.RXNE.bit],
                    ),
                )

            return sr1, sr2

        @classmethod
        def update_TXE(
            cls, i2c, state, sr1, cr1, sr2, globals, force=False, value=None
        ):
            if force or not state.solver.unique(sr1[cls.TXE.bit]):
                if value is None:
                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase ... TxE is not set if either a NACK is received
                    value = claripy.If(
                        claripy.And(
                            claripy.Not(globals.is_address_phase),
                            sr2[I2C.I2C_SR2.TRA.bit] == 1,
                            sr1[cls.AF.bit] == 0,
                        ),
                        claripy.If(
                            sr1[cls.TXE.bit] == 1,
                            sr1[cls.TXE.bit],
                            utils.generate_symbolic(state, f"{i2c.name}_TXE", size=1),
                        ),
                        claripy.BVV(0, 1),
                    )
                # (TxE) Cleared ... or when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
                sr1 = utils.replace_bit(sr1, cls.TXE.bit, value)

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
                if value is None:
                    value = claripy.If(
                        sr1[cls.ADD10.bit] == 1,
                        sr1[cls.ADD10.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_ADD10", size=1),
                    )
                # (ADD10) Cleared ... or by hardware when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
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
        def update_BTF(cls, i2c, state, sr1, cr1, sr2, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.BTF.bit]):
                if value is None:
                    # (BTF) Set by hardware when NOSTRETCH=0 and: ... In transmission when a new byte should be sent and DR has not been written yet (TxE=1) ... In reception when a new byte is received (including ACK pulse) and DR has not been read yet (RxNE=1) ... The BTF bit is not set after a NACK reception
                    # 只有 TxE 是 1 時，BTF 才可能是 1
                    value = claripy.If(
                        claripy.And(
                            cr1[I2C.I2C_CR1.NOSTRETCH.bit] == 0,
                            claripy.Or(
                                claripy.And(
                                    sr2[I2C.I2C_SR2.TRA.bit] == 1, sr1[cls.TXE.bit] == 1
                                ),
                                claripy.And(
                                    sr2[I2C.I2C_SR2.TRA.bit] == 0,
                                    sr1[cls.RXNE.bit] == 1,
                                ),
                            ),
                            sr1[cls.AF.bit] == 0,
                        ),
                        claripy.If(
                            sr1[cls.BTF.bit] == 1,
                            sr1[cls.BTF.bit],
                            utils.generate_symbolic(state, f"{i2c.name}_BTF", size=1),
                        ),
                        claripy.BVV(0, 1),
                    )
                # (BTF) Cleared ... or when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
                sr1 = utils.replace_bit(sr1, cls.BTF.bit, value)

            return sr1

        @classmethod
        def update_ADDR(
            cls, i2c, state, sr1, cr1, sr2, globals, force=False, value=None
        ):
            if force or not state.solver.unique(sr1[cls.ADDR.bit]):
                if value is None:
                    value = claripy.If(
                        sr1[cls.ADDR.bit] == 1,
                        sr1[cls.ADDR.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_ADDR", size=1),
                    )
                # (ADDR) This bit is cleared ... or by hardware when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
                sr1 = utils.replace_bit(sr1, cls.ADDR.bit, value)

                globals.is_address_phase = claripy.If(
                    sr1[cls.ADDR.bit] == 1, claripy.false(), globals.is_address_phase
                )

                # (TRA) This bit is set depending on the R/W bit of the address byte, at the end of total address phase
                if globals.rw is not None:
                    sr2 = utils.replace_bit(
                        sr2,
                        I2C.I2C_SR2.TRA.bit,
                        claripy.If(
                            sr1[cls.ADDR.bit] == 1,
                            ~globals.rw,
                            sr2[I2C.I2C_SR2.TRA.bit],
                        ),
                    )

                # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                sr1 = utils.replace_bit(
                    sr1,
                    cls.TXE.bit,
                    claripy.If(
                        claripy.And(
                            sr1[cls.ADDR.bit] == 1, sr2[I2C.I2C_SR2.TRA.bit] == 1
                        ),
                        claripy.BVV(1, 1),
                        sr1[cls.TXE.bit],
                    ),
                )
                sr1 = I2C.I2C_SR1.update_TXE(
                    i2c,
                    state,
                    sr1,
                    cr1,
                    sr2,
                    globals,
                    force=True,
                    value=sr1[cls.TXE.bit],
                )

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

            return sr1, sr2, globals

        @classmethod
        def update_SB(cls, i2c, state, sr1, cr1, sr2, force=False, value=None):
            if force or not state.solver.unique(sr1[cls.SB.bit]):
                if value is None:
                    value = claripy.If(
                        sr1[cls.SB.bit] == 1,
                        sr1[cls.SB.bit],
                        utils.generate_symbolic(state, f"{i2c.name}_SB", size=1),
                    )
                # (SB) Cleared ... or by hardware when PE=0
                # value = claripy.If(
                #     cr1[I2C.I2C_CR1.PE.bit] == 0, claripy.BVV(0, 1), value
                # )
                sr1 = utils.replace_bit(sr1, cls.SB.bit, value)

                # (START) This bit is ... and cleared by hardware when start is sent or PE=0
                cr1 = utils.replace_bit(
                    cr1,
                    I2C.I2C_CR1.START.bit,
                    claripy.If(
                        # claripy.Or(sr1[cls.SB.bit] == 1, cr1[I2C.I2C_CR1.PE.bit] == 0),
                        sr1[cls.SB.bit] == 1,
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

                # (MSL) Set by hardware as soon as the interface is in Master mode (SB=1)
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.MSL.bit,
                    claripy.If(
                        sr1[cls.SB.bit] == 1,
                        claripy.BVV(1, 1),
                        sr2[I2C.I2C_SR2.MSL.bit],
                    ),
                )

                # (BUSY) Set by hardware on detection of SDA or SCL low
                sr2 = utils.replace_bit(
                    sr2,
                    I2C.I2C_SR2.BUSY.bit,
                    claripy.If(
                        sr1[cls.SB.bit] == 1,
                        claripy.BVV(1, 1),
                        sr2[I2C.I2C_SR2.BUSY.bit],
                    ),
                )

            return sr1, cr1, sr2

    class I2C_SR2(BaseRegister):
        OFFSET = 0x18

        TRA = BitsField(2, AccessType.R, 0)
        BUSY = BitsField(1, AccessType.R, 0)
        MSL = BitsField(0, AccessType.R, 0)

    def post_read(self, state):
        _, offset, readout_value = super().post_read(state)

        globals = state.get_plugin(f"{self.name}_globals")
        new_cr1 = utils.load(state, self.start + I2C.I2C_CR1.OFFSET)
        new_sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        new_sr2 = utils.load(state, self.start + I2C.I2C_SR2.OFFSET)
        new_globals = state.get_plugin(f"{self.name}_globals").copy({})

        match offset:
            case I2C.I2C_SR1.OFFSET:
                new_globals.sr1_read = True

                # 目前寫的方式下，ARLO 需要比 AF 早 update，因為 update_AF 會新增 claripy.If(AF == 1, 0, ARLO)。如果 update_AF 先執行，update_ARLO 會被蓋過
                new_sr1, new_sr2 = I2C.I2C_SR1.update_ARLO(
                    self, state, new_sr1, new_cr1, new_sr2
                )
                # 目前寫的方式下，AF 需要比 ADD10, ADDR, TxE, BTF 等早 update，因為這些 bit 的 update function 會新增 claripy.If(bit == 1, 0, AF)。如果 update_* 先執行，update_AF 會被蓋過
                new_sr1 = I2C.I2C_SR1.update_AF(self, state, new_sr1, new_cr1)
                new_sr1 = I2C.I2C_SR1.update_ADD10(self, state, new_sr1, new_cr1)
                new_sr1, new_sr2, new_globals = I2C.I2C_SR1.update_ADDR(
                    self, state, new_sr1, new_cr1, new_sr2, new_globals
                )
                # 目前寫的方式下，TXE 需要比 SB 早 update，因為 update_SB 會新增 claripy.If(SB == 1, 0, TxE)。如果 update_SB 先執行，update_TXE 會被蓋過
                new_sr1 = I2C.I2C_SR1.update_TXE(
                    self, state, new_sr1, new_cr1, new_sr2, new_globals
                )
                new_sr1 = I2C.I2C_SR1.update_BTF(self, state, new_sr1, new_cr1, new_sr2)
                new_sr1, new_cr1, new_sr2 = I2C.I2C_SR1.update_SB(
                    self, state, new_sr1, new_cr1, new_sr2
                )

            case I2C.I2C_SR2.OFFSET:
                if globals.sr1_read:
                    new_globals.sr1_read = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    new_sr1, new_sr2, new_globals = I2C.I2C_SR1.update_ADDR(
                        self,
                        state,
                        new_sr1,
                        new_cr1,
                        new_sr2,
                        new_globals,
                        force=True,
                        value=0,
                    )

            case I2C.I2C_DR.OFFSET:
                # (BTF) Cleared by software by either a read ... in the DR register
                new_sr1 = I2C.I2C_SR1.update_BTF(
                    self, state, new_sr1, new_cr1, new_sr2, force=True, value=0
                )

        utils.store(state, self.start + I2C.I2C_CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.I2C_SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.I2C_SR2.OFFSET, new_sr2)
        state.register_plugin(f"{self.name}_globals", new_globals)

        state.inspect.mem_read_expr = self.mask_post_read(offset, readout_value)

        return _, offset, state.inspect.mem_read_expr

    def post_write(self, state):
        _, offset, value = super().post_write(state)

        globals = state.get_plugin(f"{self.name}_globals")
        new_cr1 = utils.load(state, self.start + I2C.I2C_CR1.OFFSET)
        new_sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        new_sr2 = utils.load(state, self.start + I2C.I2C_SR2.OFFSET)
        new_globals = state.get_plugin(f"{self.name}_globals").copy({})

        match offset:
            case I2C.I2C_CR1.OFFSET:
                # set START bit 時進入 address phase
                if state.solver.is_true(value[I2C.I2C_CR1.START.bit] == 1):
                    new_globals.is_address_phase = claripy.true()

                    # (SB) Set when a Start condition generated
                    new_sr1, new_cr1, new_sr2 = I2C.I2C_SR1.update_SB(
                        self, state, new_sr1, new_cr1, new_sr2, force=True
                    )

                # set STOP bit
                if state.solver.is_true(value[I2C.I2C_CR1.STOP.bit] == 1):
                    new_cr1, new_sr1, new_sr2 = I2C.I2C_CR1.update_STOP(
                        self, state, new_cr1, new_sr1, new_sr2, force=True
                    )

            case I2C.I2C_DR.OFFSET:
                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either ... or write in the DR register
                # 目前寫的方式下，TXE 需要比 BTF 早 update，因為 update_BTF 會使用到 TXE
                new_sr1 = I2C.I2C_SR1.update_TXE(
                    self,
                    state,
                    new_sr1,
                    new_cr1,
                    new_sr2,
                    new_globals,
                    force=True,
                    value=0,
                )
                new_sr1 = I2C.I2C_SR1.update_BTF(
                    self, state, new_sr1, new_cr1, new_sr2, force=True, value=0
                )

                if globals.sr1_read:
                    new_globals.sr1_read = False

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
                if not state.solver.satisfiable(
                    extra_constraints=[claripy.Not(new_globals.is_address_phase)]
                ):
                    if new_globals.rw is None:
                        # 10-bit addressing 的 addressing phase 會 write 兩次 DR。第一次 write (header) 時是 11110XXY (Y 為 R/W)
                        is_10bit = (value & 0xF8) == 0xF0
                        # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                        sr1_10bit = I2C.I2C_SR1.update_ADD10(
                            self, state, new_sr1, new_cr1, force=True
                        )
                        # (ADDR) For 7-bit addressing, the bit is set after the ACK of the byte
                        sr1_7bit, sr2_7bit, globals_7bit = I2C.I2C_SR1.update_ADDR(
                            self,
                            state,
                            new_sr1,
                            new_cr1,
                            new_sr2,
                            new_globals.copy({}),
                            force=True,
                        )
                        new_sr1 = claripy.If(is_10bit, sr1_10bit, sr1_7bit)
                        new_sr2 = claripy.If(is_10bit, new_sr2, sr2_7bit)
                        new_globals.is_address_phase = claripy.If(
                            is_10bit,
                            new_globals.is_address_phase,
                            globals_7bit.is_address_phase,
                        )

                        new_globals.rw = value[0]
                    else:
                        if globals.sr1_read:
                            new_globals.sr1_read = False

                            # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                            new_sr1 = I2C.I2C_SR1.update_ADD10(
                                self, state, new_sr1, new_cr1, force=True, value=0
                            )

                        # (ADDR) For 10-bit addressing, the bit is set after the ACK of the 2nd byte
                        new_sr1, new_sr2, new_globals = I2C.I2C_SR1.update_ADDR(
                            self,
                            state,
                            new_sr1,
                            new_cr1,
                            new_sr2,
                            new_globals,
                            force=True,
                        )
                else:
                    # 目前寫的方式下，TXE 需要比 BTF 早 update，因為 update_BTF 會使用到 TXE
                    new_sr1 = I2C.I2C_SR1.update_TXE(
                        self, state, new_sr1, new_cr1, new_sr2, new_globals, force=True
                    )
                    new_sr1 = I2C.I2C_SR1.update_BTF(
                        self, state, new_sr1, new_cr1, new_sr2, force=True
                    )

        utils.store(state, self.start + I2C.I2C_CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.I2C_SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.I2C_SR2.OFFSET, new_sr2)
        state.register_plugin(f"{self.name}_globals", new_globals)

        return _, offset, value

    def get_pending_irqs(self, state):
        cr2 = utils.load(state, self.start + I2C.I2C_CR2.OFFSET)
        events_to_check = []
        output = []

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
                output.append((trigger_cond, {"irq": irq_num}))

        return output

    def set_handlers(self, cpu, state, cfg, specs):
        Globals.register_default(f"{self.name}_globals")
