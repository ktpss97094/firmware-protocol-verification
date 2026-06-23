from __future__ import annotations

from dataclasses import dataclass

import claripy
from angr.errors import SimMergeError
from angr.state_plugins.plugin import SimStatePlugin

from project import utils
from project.types import (
    AccessEffects,
    AccessType,
    BaseRegister,
    BitsField,
    MemoryEffect,
    MMIOMemoryRegion,
    PluginEffect,
)


class Globals(SimStatePlugin):
    def __init__(self, is_address_phase=None, rw=None, sr1_read=None):
        super().__init__()

        self.is_address_phase = (
            claripy.false() if is_address_phase is None else is_address_phase
        )
        self.rw = (
            (claripy.false(), claripy.BVV(0, 1)) if rw is None else rw
        )  # (rw valid, rw value)
        self.sr1_read = claripy.false() if sr1_read is None else sr1_read

    def copy(self, memo):
        o = super().copy(memo)

        o.is_address_phase = self.is_address_phase
        o.rw = self.rw
        o.sr1_read = self.sr1_read

        return o

    def merge_key(self):
        return (self.is_address_phase.hash(), self.sr1_read.hash(), self.rw[0].hash())

    def merge(self, others, merge_conditions, common_ancestor=None):
        """
        回傳值表示 plugins 是否有被 merge，並不是 state 是否有被 merge。只有 raise SimMergeError 時才表示 state 不被 merge
        """

        # 如果 plugin 內部沒有更深層的物件需要合併，可以直接忽略 common_ancestor
        del common_ancestor

        if any(
            not utils.same_ast(self.is_address_phase, other.is_address_phase)
            or not utils.same_ast(self.sr1_read, other.sr1_read)
            for other in others
        ):
            raise SimMergeError(
                "Cannot merge STM32F4 I2C globals (is_address_phase or sr1_read)"
            )

        rw_valid, rw_value = self.rw
        if any(not utils.same_ast(rw_valid, other.rw[0]) for other in others):
            raise SimMergeError("Cannot merge STM32F4 I2C globals (rw)")

        # static analysis 時 merge_conditions 可以是 None，依照官方建議用 state.solver.union
        if merge_conditions is None:
            if all(utils.same_ast(rw_value, other.rw[1]) for other in others):
                merged_rw_value = rw_value
            else:
                raise SimMergeError(
                    "Cannot merge STM32F4 I2C globals (rw value without merge conditions)"
                )
        else:
            # merge_conditions[0] 是 self 的
            # 由於 merge 特性 (有共同 ancestor)，merge_conditions[0] | merge_conditions[1] | ... = True，所以如果 merge_conditions[1] | ... 是 False 的話，那 merge_condition[0] 一定為 True，而這個路徑代表的值就是 self.rw
            merged_rw_value = claripy.ite_cases(
                zip(merge_conditions[1:], [other.rw[1] for other in others]), rw_value
            )

        changed = not utils.same_ast(rw_value, merged_rw_value)
        self.rw = rw_valid, merged_rw_value
        return changed


def _bool_ast(value):
    if value is True:
        return claripy.true()
    if value is False or value is None:
        return claripy.false()
    return value


def _zero():
    return claripy.BVV(0, 1)


@dataclass
class I2CRegisterState:
    cr1: claripy.ast.BV
    sr1: claripy.ast.BV
    sr2: claripy.ast.BV
    globals: Globals


class I2C(MMIOMemoryRegion):
    IRQ_NUMBERS = [31, 32]  # I2C1_EV, I2C1_ER

    class I2C_CR1(BaseRegister):
        OFFSET = 0x00

        STOP = BitsField(9, AccessType.RW, 0)
        START = BitsField(8, AccessType.RW, 0)
        NOSTRETCH = BitsField(7, AccessType.RW, 0)
        PE = BitsField(0, AccessType.RW, 0)

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

    class I2C_SR2(BaseRegister):
        OFFSET = 0x18

        TRA = BitsField(2, AccessType.R, 0)
        BUSY = BitsField(1, AccessType.R, 0)
        MSL = BitsField(0, AccessType.R, 0)

    def get_access_effects(self, operation, address, size):
        effects = super().get_access_effects(operation, address, size)

        register_effects = {
            MemoryEffect("read", self.start + offset, self.spec.ANGR_ARCH.bytes)
            for offset in (I2C.I2C_CR1.OFFSET, I2C.I2C_SR1.OFFSET, I2C.I2C_SR2.OFFSET)
        }
        register_effects.update(
            MemoryEffect("write", self.start + offset, self.spec.ANGR_ARCH.bytes)
            for offset in (I2C.I2C_CR1.OFFSET, I2C.I2C_SR1.OFFSET, I2C.I2C_SR2.OFFSET)
        )
        plugin_name = f"{self.name}_globals"
        return effects.union(
            AccessEffects(
                memory=frozenset(register_effects),
                plugins=frozenset(
                    {
                        PluginEffect(
                            "read", plugin_name, ("is_address_phase", "rw", "sr1_read")
                        ),
                        PluginEffect(
                            "write", plugin_name, ("is_address_phase", "rw", "sr1_read")
                        ),
                    }
                ),
            )
        )

    def post_read(self, state):
        addr, offset, readout_value = super().post_read(self, state)
        transaction = I2CTransaction.begin(self, state)

        match offset:
            case I2C.I2C_SR1.OFFSET:
                transaction.event_sr1_read()
            case I2C.I2C_SR2.OFFSET:
                transaction.event_sr2_read()
            case I2C.I2C_DR.OFFSET:
                transaction.event_dr_read()

        transaction.finish().commit()
        state.inspect.mem_read_expr = self.mask_post_read(offset, readout_value)
        return addr, offset, state.inspect.mem_read_expr

    def post_write(self, state):
        addr, offset, value = super().post_write(self, state)
        transaction = I2CTransaction.begin(self, state)

        match offset:
            case I2C.I2C_CR1.OFFSET:
                transaction.event_cr1_write()
            case I2C.I2C_DR.OFFSET:
                transaction.event_dr_write(value)

        transaction.finish().commit()
        return addr, offset, value

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


class I2CTransaction:
    CR1_PE_CLEARED_BITS = (I2C.I2C_CR1.START.bit,)
    SR1_PE_CLEARED_BITS = (
        I2C.I2C_SR1.SMBALERT.bit,
        I2C.I2C_SR1.TIMEOUT.bit,
        I2C.I2C_SR1.PECERR.bit,
        I2C.I2C_SR1.OVR.bit,
        I2C.I2C_SR1.AF.bit,
        I2C.I2C_SR1.ARLO.bit,
        I2C.I2C_SR1.BERR.bit,
        I2C.I2C_SR1.TXE.bit,
        I2C.I2C_SR1.RXNE.bit,
        I2C.I2C_SR1.STOPF.bit,
        I2C.I2C_SR1.ADD10.bit,
        I2C.I2C_SR1.BTF.bit,
        I2C.I2C_SR1.ADDR.bit,
        I2C.I2C_SR1.SB.bit,
    )
    SR2_PE_CLEARED_BITS = (I2C.I2C_SR2.TRA.bit, I2C.I2C_SR2.MSL.bit)

    def __init__(self, i2c, state, old, new):
        self.i2c = i2c
        self.state = state
        self.old = old
        self.new = new

    @classmethod
    def begin(cls, i2c, state):
        globals_name = f"{i2c.name}_globals"
        globals_ = state.get_plugin(globals_name) or Globals()
        new_globals = globals_.copy({})
        cls._normalize_globals(new_globals)

        snapshot = I2CRegisterState(
            cr1=utils.load(state, i2c.start + I2C.I2C_CR1.OFFSET),
            sr1=utils.load(state, i2c.start + I2C.I2C_SR1.OFFSET),
            sr2=utils.load(state, i2c.start + I2C.I2C_SR2.OFFSET),
            globals=globals_,
        )
        working = I2CRegisterState(
            cr1=snapshot.cr1, sr1=snapshot.sr1, sr2=snapshot.sr2, globals=new_globals
        )
        return cls(i2c, state, snapshot, working)

    @staticmethod
    def _normalize_globals(globals_):
        globals_.is_address_phase = _bool_ast(globals_.is_address_phase)
        globals_.sr1_read = _bool_ast(globals_.sr1_read)

        rw = globals_.rw
        if not isinstance(rw, tuple):
            globals_.rw = (_bool_ast(rw), claripy.BVV(0, 1))
            return

        rw_valid, rw_value = rw
        if rw_value is None:
            rw_value = claripy.BVV(0, 1)
        globals_.rw = (_bool_ast(rw_valid), rw_value)

    def commit(self):
        utils.store(self.state, self.i2c.start + I2C.I2C_CR1.OFFSET, self.new.cr1)
        utils.store(self.state, self.i2c.start + I2C.I2C_SR1.OFFSET, self.new.sr1)
        utils.store(self.state, self.i2c.start + I2C.I2C_SR2.OFFSET, self.new.sr2)
        self.state.register_plugin(f"{self.i2c.name}_globals", self.new.globals)

    def _interface_enabled(self):
        return self.new.cr1[I2C.I2C_CR1.PE.bit] == 1

    def _pe_disabled_idle(self):
        return claripy.And(
            self.new.cr1[I2C.I2C_CR1.PE.bit] == 0,
            self.new.sr2[I2C.I2C_SR2.BUSY.bit] == 0,
        )

    def _fresh_bit(self, suffix):
        return utils.generate_symbolic(self.state, f"{self.i2c.name}_{suffix}", size=1)

    def _sticky_or_fresh_sr1_bit(self, bit, suffix):
        current = self.new.sr1[bit]
        return claripy.If(current == 1, current, self._fresh_bit(suffix))

    @staticmethod
    def _replace_bit_when(value, bit, new_bit, condition):
        return utils.replace_bit(value, bit, claripy.If(condition, new_bit, value[bit]))

    def _set_cr1_bit_when(self, bit, bit_value, condition):
        self.new.cr1 = self._replace_bit_when(
            self.new.cr1, bit, claripy.BVV(bit_value, 1), condition
        )

    def _set_sr1_bit_when(self, bit, bit_value, condition):
        self.new.sr1 = self._replace_bit_when(
            self.new.sr1, bit, claripy.BVV(bit_value, 1), condition
        )

    def _set_sr2_bit_when(self, bit, bit_value, condition):
        self.new.sr2 = self._replace_bit_when(
            self.new.sr2, bit, claripy.BVV(bit_value, 1), condition
        )

    def _assign_sr1_bit(self, bit, value):
        self.new.sr1 = utils.replace_bit(self.new.sr1, bit, value)

    def _assign_sr2_bit(self, bit, value):
        self.new.sr2 = utils.replace_bit(self.new.sr2, bit, value)

    def _clear_cr1_bits_when(self, bits, condition):
        for bit in bits:
            self._set_cr1_bit_when(bit, 0, condition)

    def _clear_sr1_bits_when(self, bits, condition):
        for bit in bits:
            self._set_sr1_bit_when(bit, 0, condition)

    def _clear_sr2_bits_when(self, bits, condition):
        for bit in bits:
            self._set_sr2_bit_when(bit, 0, condition)

    def apply_peripheral_disabled_idle(self):
        condition = self._pe_disabled_idle()

        self._clear_cr1_bits_when(self.CR1_PE_CLEARED_BITS, condition)
        self._clear_sr1_bits_when(self.SR1_PE_CLEARED_BITS, condition)
        self._clear_sr2_bits_when(self.SR2_PE_CLEARED_BITS, condition)

        self.new.globals.is_address_phase = claripy.If(
            condition, claripy.false(), self.new.globals.is_address_phase
        )
        rw_valid, rw_value = self.new.globals.rw
        self.new.globals.rw = (
            claripy.If(condition, claripy.false(), rw_valid),
            rw_value,
        )
        self.new.globals.sr1_read = claripy.If(
            condition, claripy.false(), self.new.globals.sr1_read
        )

    def finish(self):
        self.apply_peripheral_disabled_idle()
        return self

    def event_sr1_read(self):
        self.new.globals.sr1_read = claripy.true()

        self.event_arbitration_lost_may_occur()
        self.event_ack_failure_may_occur()
        self.event_add10_may_occur()
        self.event_address_phase_may_complete()
        self.event_tx_empty_refresh()
        self.event_byte_transfer_finished_refresh()
        self.event_start_generated()

    def event_sr2_read(self):
        sr1_read = _bool_ast(self.old.globals.sr1_read)
        self._set_sr1_bit_when(I2C.I2C_SR1.ADDR.bit, 0, sr1_read)
        self.new.globals.sr1_read = claripy.If(
            sr1_read, claripy.false(), self.new.globals.sr1_read
        )

    def event_dr_read(self):
        self._set_sr1_bit_when(I2C.I2C_SR1.BTF.bit, 0, claripy.true())
        self._set_sr1_bit_when(I2C.I2C_SR1.RXNE.bit, 0, claripy.true())

    def event_cr1_write(self):
        if self.state.solver.satisfiable(
            extra_constraints=[self.new.cr1[I2C.I2C_CR1.START.bit] == 1]
        ):
            self.event_start_generated()

        if self.state.solver.satisfiable(
            extra_constraints=[self.new.cr1[I2C.I2C_CR1.STOP.bit] == 1]
        ):
            self.event_stop_detected()

    def event_dr_write(self, value):
        self._set_sr1_bit_when(I2C.I2C_SR1.TXE.bit, 0, claripy.true())
        self._set_sr1_bit_when(I2C.I2C_SR1.BTF.bit, 0, claripy.true())

        sr1_read = _bool_ast(self.old.globals.sr1_read)
        self._set_sr1_bit_when(I2C.I2C_SR1.SB.bit, 0, sr1_read)
        self.new.globals.sr1_read = claripy.If(
            sr1_read, claripy.false(), self.new.globals.sr1_read
        )

        self.event_arbitration_lost_may_occur(force=True)
        self.event_ack_failure_may_occur(force=True)

        if self._address_phase_is_definitely_active():
            rw_valid, _ = self.new.globals.rw
            if not self.state.solver.satisfiable(extra_constraints=[rw_valid]):
                is_10bit_header = (value & 0xF8) == 0xF0
                self.event_add10_may_occur(condition=is_10bit_header, force=True)
                self.event_address_phase_may_complete(
                    condition=claripy.Not(is_10bit_header), force=True
                )
                self.new.globals.rw = (claripy.true(), value[0])
            else:
                self._set_sr1_bit_when(I2C.I2C_SR1.ADD10.bit, 0, sr1_read)
                self.event_address_phase_may_complete(force=True)
        else:
            self.event_tx_empty_refresh(force=True)
            self.event_byte_transfer_finished_refresh(force=True)

    def _address_phase_is_definitely_active(self):
        address_phase = _bool_ast(self.new.globals.is_address_phase)
        return not self.state.solver.satisfiable(
            extra_constraints=[claripy.Not(address_phase)]
        )

    def event_start_generated(self, condition=None):
        condition = claripy.true() if condition is None else condition
        can_generate = claripy.And(
            condition,
            self._interface_enabled(),
            self.new.cr1[I2C.I2C_CR1.START.bit] == 1,
        )
        next_sb = claripy.If(
            can_generate,
            self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.SB.bit, "SB"),
            self.new.sr1[I2C.I2C_SR1.SB.bit],
        )
        self._assign_sr1_bit(I2C.I2C_SR1.SB.bit, next_sb)

        start_sent = claripy.And(can_generate, next_sb == 1)
        self._set_cr1_bit_when(I2C.I2C_CR1.START.bit, 0, start_sent)
        self._set_sr1_bit_when(I2C.I2C_SR1.TXE.bit, 0, start_sent)
        self._set_sr1_bit_when(I2C.I2C_SR1.BTF.bit, 0, start_sent)
        self._set_sr2_bit_when(I2C.I2C_SR2.TRA.bit, 0, start_sent)
        self._set_sr2_bit_when(I2C.I2C_SR2.MSL.bit, 1, start_sent)
        self._set_sr2_bit_when(I2C.I2C_SR2.BUSY.bit, 1, start_sent)
        self.new.globals.is_address_phase = claripy.If(
            start_sent, claripy.true(), self.new.globals.is_address_phase
        )

    def event_stop_detected(self, condition=None):
        condition = claripy.true() if condition is None else condition
        can_detect = claripy.And(condition, self.new.cr1[I2C.I2C_CR1.STOP.bit] == 1)
        next_stop = claripy.If(
            can_detect, self._fresh_bit("STOP"), self.new.cr1[I2C.I2C_CR1.STOP.bit]
        )
        self.new.cr1 = utils.replace_bit(self.new.cr1, I2C.I2C_CR1.STOP.bit, next_stop)

        stop_detected = claripy.And(can_detect, next_stop == 0)
        self._set_sr1_bit_when(I2C.I2C_SR1.TXE.bit, 0, stop_detected)
        self._set_sr1_bit_when(
            I2C.I2C_SR1.BTF.bit,
            0,
            claripy.And(stop_detected, self.new.sr2[I2C.I2C_SR2.TRA.bit] == 1),
        )
        self._set_sr2_bit_when(I2C.I2C_SR2.MSL.bit, 0, stop_detected)
        self._set_sr2_bit_when(I2C.I2C_SR2.BUSY.bit, 0, stop_detected)
        self.new.globals.is_address_phase = claripy.If(
            stop_detected, claripy.false(), self.new.globals.is_address_phase
        )

    def event_arbitration_lost_may_occur(self, condition=None, force=False):
        condition = claripy.true() if condition is None else condition
        should_refresh = claripy.And(condition, self._interface_enabled())
        if force or not self.state.solver.unique(self.new.sr1[I2C.I2C_SR1.ARLO.bit]):
            next_arlo = claripy.If(
                should_refresh,
                self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.ARLO.bit, "ARLO"),
                self.new.sr1[I2C.I2C_SR1.ARLO.bit],
            )
            self._assign_sr1_bit(I2C.I2C_SR1.ARLO.bit, next_arlo)

        arlo = self.new.sr1[I2C.I2C_SR1.ARLO.bit] == 1
        self._set_sr2_bit_when(I2C.I2C_SR2.TRA.bit, 0, arlo)
        self._set_sr2_bit_when(I2C.I2C_SR2.MSL.bit, 0, arlo)
        self._set_sr1_bit_when(I2C.I2C_SR1.RXNE.bit, 0, arlo)

    def event_ack_failure_may_occur(self, condition=None, force=False):
        condition = claripy.true() if condition is None else condition
        should_refresh = claripy.And(condition, self._interface_enabled())
        if force or not self.state.solver.unique(self.new.sr1[I2C.I2C_SR1.AF.bit]):
            next_af = claripy.If(
                should_refresh,
                self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.AF.bit, "AF"),
                self.new.sr1[I2C.I2C_SR1.AF.bit],
            )
            self._assign_sr1_bit(I2C.I2C_SR1.AF.bit, next_af)

        af = self.new.sr1[I2C.I2C_SR1.AF.bit] == 1
        self._set_sr1_bit_when(I2C.I2C_SR1.ARLO.bit, 0, af)

    def event_add10_may_occur(self, condition=None, force=False):
        condition = claripy.true() if condition is None else condition
        should_refresh = claripy.And(condition, self._interface_enabled())
        if force or not self.state.solver.unique(self.new.sr1[I2C.I2C_SR1.ADD10.bit]):
            next_add10 = claripy.If(
                should_refresh,
                self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.ADD10.bit, "ADD10"),
                self.new.sr1[I2C.I2C_SR1.ADD10.bit],
            )
            self._assign_sr1_bit(I2C.I2C_SR1.ADD10.bit, next_add10)

        add10 = self.new.sr1[I2C.I2C_SR1.ADD10.bit] == 1
        self._set_sr1_bit_when(I2C.I2C_SR1.AF.bit, 0, add10)
        self._set_sr1_bit_when(I2C.I2C_SR1.ARLO.bit, 0, add10)

    def event_address_phase_may_complete(self, condition=None, force=False):
        condition = claripy.true() if condition is None else condition
        should_refresh = claripy.And(condition, self._interface_enabled())
        if force or not self.state.solver.unique(self.new.sr1[I2C.I2C_SR1.ADDR.bit]):
            next_addr = claripy.If(
                should_refresh,
                self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.ADDR.bit, "ADDR"),
                self.new.sr1[I2C.I2C_SR1.ADDR.bit],
            )
            self._assign_sr1_bit(I2C.I2C_SR1.ADDR.bit, next_addr)

        addr_set = self.new.sr1[I2C.I2C_SR1.ADDR.bit] == 1
        self.new.globals.is_address_phase = claripy.If(
            addr_set, claripy.false(), self.new.globals.is_address_phase
        )

        rw_valid, rw_value = self.new.globals.rw
        self._assign_sr2_bit(
            I2C.I2C_SR2.TRA.bit,
            claripy.If(
                claripy.And(addr_set, rw_valid),
                ~rw_value,
                self.new.sr2[I2C.I2C_SR2.TRA.bit],
            ),
        )
        self._set_sr1_bit_when(
            I2C.I2C_SR1.TXE.bit,
            1,
            claripy.And(addr_set, self.new.sr2[I2C.I2C_SR2.TRA.bit] == 1),
        )
        self._set_sr1_bit_when(I2C.I2C_SR1.AF.bit, 0, addr_set)
        self._set_sr1_bit_when(I2C.I2C_SR1.ARLO.bit, 0, addr_set)

    def event_tx_empty_refresh(self, condition=None, force=False):
        condition = claripy.true() if condition is None else condition
        should_refresh = claripy.And(condition, self._interface_enabled())
        eligible = claripy.And(
            should_refresh,
            claripy.Not(_bool_ast(self.new.globals.is_address_phase)),
            self.new.sr2[I2C.I2C_SR2.TRA.bit] == 1,
            self.new.sr1[I2C.I2C_SR1.AF.bit] == 0,
        )

        if force or not self.state.solver.unique(self.new.sr1[I2C.I2C_SR1.TXE.bit]):
            next_txe = claripy.If(
                eligible,
                self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.TXE.bit, "TXE"),
                claripy.If(should_refresh, _zero(), self.new.sr1[I2C.I2C_SR1.TXE.bit]),
            )
            self._assign_sr1_bit(I2C.I2C_SR1.TXE.bit, next_txe)

    def event_byte_transfer_finished_refresh(self, condition=None, force=False):
        condition = claripy.true() if condition is None else condition
        should_refresh = claripy.And(condition, self._interface_enabled())
        eligible = claripy.And(
            should_refresh,
            self.new.cr1[I2C.I2C_CR1.NOSTRETCH.bit] == 0,
            claripy.Or(
                claripy.And(
                    self.new.sr2[I2C.I2C_SR2.TRA.bit] == 1,
                    self.new.sr1[I2C.I2C_SR1.TXE.bit] == 1,
                ),
                claripy.And(
                    self.new.sr2[I2C.I2C_SR2.TRA.bit] == 0,
                    self.new.sr1[I2C.I2C_SR1.RXNE.bit] == 1,
                ),
            ),
            self.new.sr1[I2C.I2C_SR1.AF.bit] == 0,
        )

        if force or not self.state.solver.unique(self.new.sr1[I2C.I2C_SR1.BTF.bit]):
            next_btf = claripy.If(
                eligible,
                self._sticky_or_fresh_sr1_bit(I2C.I2C_SR1.BTF.bit, "BTF"),
                claripy.If(should_refresh, _zero(), self.new.sr1[I2C.I2C_SR1.BTF.bit]),
            )
            self._assign_sr1_bit(I2C.I2C_SR1.BTF.bit, next_btf)
