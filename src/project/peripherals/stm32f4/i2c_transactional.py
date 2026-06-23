from __future__ import annotations

from dataclasses import dataclass

import claripy

from project import utils
from project.peripherals.stm32f4.i2c import I2C, Globals
from project.types import MMIOMemoryRegion


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


class I2CTransaction:
    """
    One MMIO access against the I2C peripheral.

    The transaction owns a mutable register/plugin snapshot. Events update this
    snapshot, and lifecycle rules such as PE-disabled-idle cleanup observe the
    latest values produced by earlier events in the same access.
    """

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


class TransactionalI2C(I2C):
    def post_read(self, state):
        addr, offset, readout_value = MMIOMemoryRegion.post_read(self, state)
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
        addr, offset, value = MMIOMemoryRegion.post_write(self, state)
        transaction = I2CTransaction.begin(self, state)

        match offset:
            case I2C.I2C_CR1.OFFSET:
                transaction.event_cr1_write()
            case I2C.I2C_DR.OFFSET:
                transaction.event_dr_write(value)

        transaction.finish().commit()
        return addr, offset, value
