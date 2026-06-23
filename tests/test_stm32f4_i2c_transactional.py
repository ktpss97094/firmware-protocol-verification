from __future__ import annotations

import unittest
from types import SimpleNamespace

import angr
import claripy

from firmwares.stm32f429.protocols.I2C.spec_hw import Specs
from project.peripherals.stm32f4.i2c import Globals, I2C
from project.peripherals.stm32f4.i2c_transactional import TransactionalI2C


class TransactionalI2CModelTest(unittest.TestCase):
    def make_i2c_state(self):
        project = angr.load_shellcode(b"\x00", arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state()
        spec = SimpleNamespace(ANGR_ARCH=Specs.ANGR_ARCH)
        i2c = TransactionalI2C(start=0x40005400, size=0x400, spec=spec, name="I2C1")
        state.register_plugin("I2C1_globals", Globals())

        for offset in (
            I2C.I2C_CR1.OFFSET,
            I2C.I2C_DR.OFFSET,
            I2C.I2C_SR1.OFFSET,
            I2C.I2C_SR2.OFFSET,
        ):
            self.store_register(state, i2c, offset, 0)

        return state, i2c

    def store_register(self, state, i2c, offset, value):
        if isinstance(value, int):
            value = claripy.BVV(value, state.arch.bits)
        state.memory.store(
            i2c.start + offset,
            value,
            size=state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )

    def load_register(self, state, i2c, offset):
        return state.memory.load(
            i2c.start + offset,
            state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )

    def run_post_read(self, state, i2c, offset):
        state.inspect.mem_read_address = i2c.start + offset
        state.inspect.mem_read_expr = self.load_register(state, i2c, offset)
        return i2c.post_read(state)

    def run_write(self, state, i2c, offset, value):
        if isinstance(value, int):
            value = claripy.BVV(value, state.arch.bits)
        addr = i2c.start + offset
        state.inspect.mem_write_address = addr
        state.inspect.mem_write_length = state.arch.bytes
        state.inspect.mem_write_expr = value
        state.inspect.mem_write_condition = None
        state.inspect.mem_write_endness = state.arch.memory_endness

        i2c.pre_write(state)
        state.memory.store(
            addr,
            value,
            size=state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )
        state.inspect.mem_write_expr = value
        return i2c.post_write(state)

    def test_pe_disabled_idle_cr1_write_clears_status_and_globals(self):
        state, i2c = self.make_i2c_state()
        state.register_plugin(
            "I2C1_globals",
            Globals(
                is_address_phase=claripy.true(),
                rw=(claripy.true(), claripy.BVV(1, 1)),
                sr1_read=claripy.true(),
            ),
        )

        cr1 = (1 << I2C.I2C_CR1.PE.bit) | (1 << I2C.I2C_CR1.START.bit)
        sr1 = sum(
            1 << bit
            for bit in (
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
        )
        sr2 = (1 << I2C.I2C_SR2.TRA.bit) | (1 << I2C.I2C_SR2.MSL.bit)

        self.store_register(state, i2c, I2C.I2C_CR1.OFFSET, cr1)
        self.store_register(state, i2c, I2C.I2C_SR1.OFFSET, sr1)
        self.store_register(state, i2c, I2C.I2C_SR2.OFFSET, sr2)

        self.run_write(state, i2c, I2C.I2C_CR1.OFFSET, 0)

        stored_cr1 = self.load_register(state, i2c, I2C.I2C_CR1.OFFSET)
        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_sr2 = self.load_register(state, i2c, I2C.I2C_SR2.OFFSET)
        stored_globals = state.get_plugin("I2C1_globals")

        self.assertEqual(0, state.solver.eval(stored_cr1[I2C.I2C_CR1.PE.bit]))
        self.assertEqual(0, state.solver.eval(stored_cr1[I2C.I2C_CR1.START.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr1))
        self.assertEqual(0, state.solver.eval(stored_sr2[I2C.I2C_SR2.TRA.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr2[I2C.I2C_SR2.MSL.bit]))
        self.assertEqual(0, state.solver.eval(stored_globals.is_address_phase))
        self.assertEqual(0, state.solver.eval(stored_globals.rw[0]))
        self.assertEqual(0, state.solver.eval(stored_globals.sr1_read))

    def test_pe_disabled_idle_start_write_does_not_create_bus_activity(self):
        state, i2c = self.make_i2c_state()

        self.run_write(
            state,
            i2c,
            I2C.I2C_CR1.OFFSET,
            1 << I2C.I2C_CR1.START.bit,
        )

        stored_cr1 = self.load_register(state, i2c, I2C.I2C_CR1.OFFSET)
        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_sr2 = self.load_register(state, i2c, I2C.I2C_SR2.OFFSET)
        stored_globals = state.get_plugin("I2C1_globals")

        self.assertEqual(0, state.solver.eval(stored_cr1[I2C.I2C_CR1.START.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr1[I2C.I2C_SR1.SB.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr2[I2C.I2C_SR2.BUSY.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr2[I2C.I2C_SR2.MSL.bit]))
        self.assertEqual(0, state.solver.eval(stored_globals.is_address_phase))

    def test_pe_disabled_busy_keeps_flags_until_idle_transaction(self):
        state, i2c = self.make_i2c_state()

        cr1 = (1 << I2C.I2C_CR1.PE.bit) | (1 << I2C.I2C_CR1.START.bit)
        sr1 = (1 << I2C.I2C_SR1.TXE.bit) | (1 << I2C.I2C_SR1.SB.bit)
        sr2 = (
            (1 << I2C.I2C_SR2.TRA.bit)
            | (1 << I2C.I2C_SR2.BUSY.bit)
            | (1 << I2C.I2C_SR2.MSL.bit)
        )

        self.store_register(state, i2c, I2C.I2C_CR1.OFFSET, cr1)
        self.store_register(state, i2c, I2C.I2C_SR1.OFFSET, sr1)
        self.store_register(state, i2c, I2C.I2C_SR2.OFFSET, sr2)

        self.run_write(state, i2c, I2C.I2C_CR1.OFFSET, 0)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_sr2 = self.load_register(state, i2c, I2C.I2C_SR2.OFFSET)
        self.assertEqual(1, state.solver.eval(stored_sr1[I2C.I2C_SR1.TXE.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr1[I2C.I2C_SR1.SB.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr2[I2C.I2C_SR2.BUSY.bit]))

        self.store_register(
            state,
            i2c,
            I2C.I2C_SR2.OFFSET,
            (1 << I2C.I2C_SR2.TRA.bit) | (1 << I2C.I2C_SR2.MSL.bit),
        )
        self.run_write(state, i2c, I2C.I2C_CR1.OFFSET, 0)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_sr2 = self.load_register(state, i2c, I2C.I2C_SR2.OFFSET)
        self.assertEqual(0, state.solver.eval(stored_sr1))
        self.assertEqual(0, state.solver.eval(stored_sr2[I2C.I2C_SR2.TRA.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr2[I2C.I2C_SR2.MSL.bit]))

    def test_symbolic_sr1_read_controls_sr2_addr_clear(self):
        state, i2c = self.make_i2c_state()
        sr1_read = claripy.BoolS("sr1_read_for_sr2")
        state.register_plugin("I2C1_globals", Globals(sr1_read=sr1_read))

        self.store_register(
            state, i2c, I2C.I2C_CR1.OFFSET, 1 << I2C.I2C_CR1.PE.bit
        )
        self.store_register(
            state, i2c, I2C.I2C_SR1.OFFSET, 1 << I2C.I2C_SR1.ADDR.bit
        )

        self.run_post_read(state, i2c, I2C.I2C_SR2.OFFSET)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_globals = state.get_plugin("I2C1_globals")
        self.assertFalse(
            state.solver.satisfiable(
                extra_constraints=[sr1_read, stored_sr1[I2C.I2C_SR1.ADDR.bit] == 1]
            )
        )
        self.assertFalse(
            state.solver.satisfiable(
                extra_constraints=[sr1_read, stored_globals.sr1_read]
            )
        )
        self.assertTrue(
            state.solver.satisfiable(
                extra_constraints=[
                    claripy.Not(sr1_read),
                    stored_sr1[I2C.I2C_SR1.ADDR.bit] == 1,
                ]
            )
        )

    def test_symbolic_sr1_read_controls_dr_write_sb_clear(self):
        state, i2c = self.make_i2c_state()
        sr1_read = claripy.BoolS("sr1_read_for_dr")
        state.register_plugin("I2C1_globals", Globals(sr1_read=sr1_read))

        self.store_register(
            state, i2c, I2C.I2C_CR1.OFFSET, 1 << I2C.I2C_CR1.PE.bit
        )
        self.store_register(
            state, i2c, I2C.I2C_SR1.OFFSET, 1 << I2C.I2C_SR1.SB.bit
        )

        self.run_write(state, i2c, I2C.I2C_DR.OFFSET, 0x52)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_globals = state.get_plugin("I2C1_globals")
        self.assertFalse(
            state.solver.satisfiable(
                extra_constraints=[sr1_read, stored_sr1[I2C.I2C_SR1.SB.bit] == 1]
            )
        )
        self.assertFalse(
            state.solver.satisfiable(
                extra_constraints=[sr1_read, stored_globals.sr1_read]
            )
        )
        self.assertTrue(
            state.solver.satisfiable(
                extra_constraints=[
                    claripy.Not(sr1_read),
                    stored_sr1[I2C.I2C_SR1.SB.bit] == 1,
                ]
            )
        )

    def test_pe_disabled_sr1_read_clears_fresh_symbolic_events(self):
        state, i2c = self.make_i2c_state()
        symbolic_sr1 = claripy.BVS("symbolic_sr1_transactional", state.arch.bits)

        self.store_register(state, i2c, I2C.I2C_SR1.OFFSET, symbolic_sr1)

        self.run_post_read(state, i2c, I2C.I2C_SR1.OFFSET)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        for bit in (
            I2C.I2C_SR1.AF.bit,
            I2C.I2C_SR1.ARLO.bit,
            I2C.I2C_SR1.TXE.bit,
            I2C.I2C_SR1.ADD10.bit,
            I2C.I2C_SR1.BTF.bit,
            I2C.I2C_SR1.ADDR.bit,
            I2C.I2C_SR1.SB.bit,
        ):
            self.assertFalse(
                state.solver.satisfiable(extra_constraints=[stored_sr1[bit] == 1])
            )

    def test_post_write_reapplies_rc_w0_mask_before_transaction_events(self):
        state, i2c = self.make_i2c_state()

        self.store_register(
            state, i2c, I2C.I2C_CR1.OFFSET, 1 << I2C.I2C_CR1.PE.bit
        )
        sr1_addr = i2c.start + I2C.I2C_SR1.OFFSET
        old_sr1 = claripy.BVV(1 << I2C.I2C_SR1.AF.bit, state.arch.bits)
        raw_clear_af = claripy.BVV(
            (~(1 << I2C.I2C_SR1.AF.bit)) & 0xFFFFFFFF, state.arch.bits
        )
        state.memory.store(
            sr1_addr,
            old_sr1,
            size=state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )
        state.inspect.mem_write_address = sr1_addr
        state.inspect.mem_write_length = state.arch.bytes
        state.inspect.mem_write_expr = raw_clear_af
        state.inspect.mem_write_condition = None
        state.inspect.mem_write_endness = state.arch.memory_endness

        _, _, masked_value = i2c.pre_write(state)

        state.memory.store(
            sr1_addr,
            raw_clear_af,
            size=state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )
        state.inspect.mem_write_expr = raw_clear_af
        i2c.post_write(state)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        self.assertEqual(0, state.solver.eval(stored_sr1[I2C.I2C_SR1.AF.bit]))
        self.assertEqual(state.solver.eval(masked_value), state.solver.eval(stored_sr1))


if __name__ == "__main__":
    unittest.main()
