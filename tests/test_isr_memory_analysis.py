from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

import angr
import claripy

from firmwares.stm32f429.protocols.I2C.spec_hw import Specs
from project import utils
from project.analyses.isr_memory import Access, analyze_isr_memory
from project.cores.arm.cortex_m.cortex_m import CortexM
from project.cores.base import BaseCPU
from project.main import state_merge_key
from project.peripherals.stm32f4.i2c import I2C, Globals
from project.types import AccessEffects, EventForkHandler, MemoryEffect, PluginEffect

ROOT = Path(__file__).resolve().parents[1]
ELF = (
    ROOT
    / "firmwares/stm32f429/build/protocols/I2C/master/Interrupt_Mode"
    / "stm32f4xx-hal-driver/firmware.elf"
)


def state_with_vector_alias(project, specs):
    state = project.factory.blank_state()
    alias = specs.MEMORY_REGIONS["VECTOR_TABLE_ALIAS"]
    state.memory.store(
        alias.start,
        project.loader.memory.load(alias.physical_addr, alias.size),
        inspect=False,
    )
    return state


class ISRMemoryAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        specs = Specs(project)
        state = state_with_vector_alias(project, specs)
        cls.targets = specs.CPU.get_isr_targets(state, specs)
        cls.report = analyze_isr_memory(ELF, specs, isr_targets=cls.targets)

    def test_modeled_mmio_irqs_are_discovered_from_initial_state(self):
        raw_targets = {
            target.irq: (target.source, target.address) for target in self.targets
        }
        targets = {
            report.irq: (report.address, report.isr) for report in self.report.isrs
        }
        self.assertEqual((0xBC, 0x08000613), raw_targets[31])
        self.assertEqual((0xC0, 0x08000625), raw_targets[32])
        self.assertEqual({11, 12, 13, 14, 15, 16, 17, 31, 32}, set(targets))
        self.assertEqual((0x08000613, "I2C1_EV_IRQHandler"), targets[31])
        self.assertEqual((0x08000625, "I2C1_ER_IRQHandler"), targets[32])

    def test_main_stack_pointer_escape_is_recovered(self):
        facts = {(fact.cell.address, fact.value) for fact in self.report.pointer_facts}
        self.assertIn((0x2000059C, 0x40005400), facts)
        self.assertIn((0x200005C0, 0x2001FFF4), facts)

    def test_event_isr_resolves_expected_shared_regions(self):
        event = next(report for report in self.report.isrs if report.irq == 31)
        regions_by_start = {region.start: region for region in event.regions}
        self.assertIn(0x2000059C, regions_by_start)
        self.assertIn(0x2001FFF4, regions_by_start)
        for register in (0x40005400, 0x40005404, 0x40005410, 0x40005414, 0x40005418):
            self.assertIn(register, regions_by_start)
        self.assertEqual(("read", "write"), regions_by_start[0x2001FFF4].operations)
        self.assertIn(
            PluginEffect(
                "write", "I2C1_globals", ("is_address_phase", "rw", "sr1_read")
            ),
            event.effects.plugins,
        )
        self.assertIn(MemoryEffect("write", 0x40005414, 4), event.effects.memory)

    def test_error_isr_resolves_buffer_write_and_reports_incompleteness(self):
        error = next(report for report in self.report.isrs if report.irq == 32)
        regions = {region.start: region for region in error.regions}
        self.assertEqual(("write",), regions[0x2001FFF4].operations)
        self.assertTrue(error.unresolved_accesses)
        self.assertTrue(error.unresolved_calls)
        self.assertFalse(error.complete)
        self.assertFalse(self.report.complete)


class AccessEffectsTest(unittest.TestCase):
    def test_memory_conflicts_require_an_overlapping_write(self):
        read = AccessEffects.memory_access("read", 0x1000, 4)
        overlapping_read = AccessEffects.memory_access("read", 0x1002, 4)
        overlapping_write = AccessEffects.memory_access("write", 0x1002, 4)

        self.assertFalse(read.conflicts_with(overlapping_read))
        self.assertTrue(read.conflicts_with(overlapping_write))

    def test_plugin_fields_are_resources(self):
        read = AccessEffects(
            plugins=frozenset({PluginEffect("read", "I2C1_globals", ("sr1_read",))})
        )
        write_same = AccessEffects(
            plugins=frozenset({PluginEffect("write", "I2C1_globals", ("sr1_read",))})
        )
        write_other = AccessEffects(
            plugins=frozenset({PluginEffect("write", "I2C1_globals", ("rw",))})
        )

        self.assertTrue(read.conflicts_with(write_same))
        self.assertFalse(read.conflicts_with(write_other))

    def test_i2c_access_includes_modeled_memory_and_plugin_effects(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        specs = Specs(project)
        effects = specs.MEMORY_REGIONS["I2C1"].get_access_effects("read", 0x40005414, 4)

        self.assertIn(MemoryEffect("read", 0x40005414, 4), effects.memory)
        self.assertIn(MemoryEffect("write", 0x40005400, 4), effects.memory)
        self.assertIn(MemoryEffect("write", 0x40005414, 4), effects.memory)
        self.assertIn(MemoryEffect("write", 0x40005418, 4), effects.memory)
        self.assertIn(
            PluginEffect(
                "write", "I2C1_globals", ("is_address_phase", "rw", "sr1_read")
            ),
            effects.plugins,
        )

    def test_base_precomputes_shared_regions_from_i2c_side_effects(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        specs = Specs(project)
        state = project.factory.blank_state()
        i2c = specs.MEMORY_REGIONS["I2C1"]
        main_address = i2c.start + i2c.I2C_SR1.OFFSET
        isr_address = i2c.start + i2c.I2C_DR.OFFSET
        report = SimpleNamespace(
            initializer_accesses=[
                Access("read", 0x1000, 4, "main", address=main_address)
            ],
            initializer_unresolved_calls=[],
            isrs=[
                SimpleNamespace(
                    accesses=[
                        Access(
                            "read", 0x2000, 4, "I2C1_EV_IRQHandler", address=isr_address
                        )
                    ],
                    unresolved_calls=[],
                )
            ],
        )

        cpu = CortexM()
        cpu.get_isr_memory_report = lambda _project, _state, _specs: report
        shared_regions, _ = cpu._get_shared_access_regions_and_unresolved(
            project, state, specs
        )
        specs.get_access_effects = lambda *_args: self.fail(
            "runtime membership must not recompute access effects"
        )

        state.inspect.mem_read_address = main_address
        state.inspect.mem_read_length = 4
        self.assertTrue(
            cpu._inspect_access_in_regions(state, "read", shared_regions["read"])
        )

        state.inspect.mem_read_address = specs.MEMORY_REGIONS["RAM"].start
        self.assertFalse(
            cpu._inspect_access_in_regions(state, "read", shared_regions["read"])
        )

    def test_base_requires_cross_flow_write_for_shared_region(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        specs = Specs(project)
        address = specs.MEMORY_REGIONS["RAM"].start

        def report(isr_operation):
            return SimpleNamespace(
                initializer_accesses=[
                    Access("read", 0x1000, 4, "main", address=address)
                ],
                initializer_unresolved_calls=[],
                isrs=[
                    SimpleNamespace(
                        accesses=[
                            Access(
                                isr_operation, 0x2000, 4, "IRQ_Handler", address=address
                            )
                        ],
                        unresolved_calls=[],
                    )
                ],
            )

        read_only_cpu = CortexM()
        read_only_cpu.get_isr_memory_report = (
            lambda _project, _state, _specs: report("read")
        )
        read_only, _ = read_only_cpu._get_shared_access_regions_and_unresolved(
            project, None, specs
        )
        self.assertFalse(read_only["read"].overlaps(address, 4))

        write_cpu = CortexM()
        write_cpu.get_isr_memory_report = (
            lambda _project, _state, _specs: report("write")
        )
        shared, _ = write_cpu._get_shared_access_regions_and_unresolved(
            project, None, specs
        )
        self.assertTrue(shared["read"].overlaps(address, 4))
        self.assertTrue(shared["write"].overlaps(address, 4))

    def test_unresolved_access_becomes_instruction_checkpoint_without_effect(self):
        report = SimpleNamespace(
            initializer_accesses=[
                Access("read", 0x1000, 4, "main", unresolved="TOP address")
            ],
            initializer_unresolved_calls=[],
            isrs=[],
        )

        class SpecsStub:
            def get_access_effects(inner_self, *_args):
                del inner_self
                self.fail("unresolved accesses must not produce access effects")

        specs = SpecsStub()
        cpu = CortexM()
        cpu.get_isr_memory_report = lambda _project, _state, _specs: report

        _, unresolved = cpu._get_shared_access_regions_and_unresolved(
            object(), None, specs
        )

        self.assertEqual({0x1000}, unresolved)

    def test_unresolved_access_without_instruction_fails_closed(self):
        report = SimpleNamespace(
            initializer_accesses=[
                Access("read", None, 4, "main", unresolved="TOP address")
            ],
            initializer_unresolved_calls=[],
            isrs=[],
        )
        cpu = CortexM()
        cpu.get_isr_memory_report = lambda _project, _state, _specs: report

        with self.assertRaisesRegex(
            ValueError, "analyzer did not report an instruction address"
        ):
            cpu._get_shared_access_regions_and_unresolved(object(), None, object())

    def test_base_adds_only_two_shared_effect_breakpoints(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        specs = Specs(project)
        state = state_with_vector_alias(project, specs)
        cpu = CortexM()

        checkpoints = cpu.get_static_interrupt_checkpoints(
            project, state, project.analyses.CFGFast(normalize=True), specs
        )
        memory_checkpoints = {
            (checkpoint.event_type, checkpoint.when)
            for checkpoint in checkpoints
            if checkpoint.event_type in {"mem_read", "mem_write"}
        }

        self.assertEqual(
            {("mem_read", angr.BP_BEFORE), ("mem_write", angr.BP_BEFORE)},
            memory_checkpoints,
        )


class I2CModelTest(unittest.TestCase):
    def make_i2c_state(self):
        project = angr.load_shellcode(b"\x00", arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state()
        spec = SimpleNamespace(ANGR_ARCH=Specs.ANGR_ARCH)
        i2c = I2C(start=0x40005400, size=0x400, spec=spec, name="I2C1")
        state.register_plugin("I2C1_globals", Globals())

        for offset in (I2C.I2C_CR1.OFFSET, I2C.I2C_SR1.OFFSET, I2C.I2C_SR2.OFFSET):
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

    def test_pe_disabled_idle_cr1_write_clears_modeled_status_and_internal_phase(self):
        state, i2c = self.make_i2c_state()
        state.register_plugin(
            "I2C1_globals",
            Globals(
                is_address_phase=claripy.true(),
                rw=(claripy.true(), claripy.BVV(1, 1)),
                sr1_read=True,
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

    def test_pe_disabled_busy_keeps_flags_until_communication_reaches_idle(self):
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

        stored_cr1 = self.load_register(state, i2c, I2C.I2C_CR1.OFFSET)
        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_sr2 = self.load_register(state, i2c, I2C.I2C_SR2.OFFSET)

        self.assertEqual(0, state.solver.eval(stored_cr1[I2C.I2C_CR1.PE.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr1[I2C.I2C_SR1.TXE.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr1[I2C.I2C_SR1.SB.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr2[I2C.I2C_SR2.TRA.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr2[I2C.I2C_SR2.BUSY.bit]))
        self.assertEqual(1, state.solver.eval(stored_sr2[I2C.I2C_SR2.MSL.bit]))

    def test_pe_disabled_sr1_read_clears_fresh_symbolic_events(self):
        state, i2c = self.make_i2c_state()
        symbolic_sr1 = claripy.BVS("symbolic_sr1", state.arch.bits)

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

    def test_symbolic_address_phase_dr_write_keeps_address_and_data_behaviors(self):
        state, i2c = self.make_i2c_state()
        address_phase = claripy.BoolS("address_phase")
        state.register_plugin(
            "I2C1_globals",
            Globals(
                is_address_phase=address_phase,
                rw=(claripy.false(), claripy.BVV(0, 1)),
            ),
        )
        self.store_register(
            state,
            i2c,
            I2C.I2C_CR1.OFFSET,
            1 << I2C.I2C_CR1.PE.bit,
        )
        self.store_register(
            state,
            i2c,
            I2C.I2C_SR2.OFFSET,
            (1 << I2C.I2C_SR2.TRA.bit) | (1 << I2C.I2C_SR2.MSL.bit),
        )

        self.run_write(state, i2c, I2C.I2C_DR.OFFSET, 0xD0)

        stored_sr1 = self.load_register(state, i2c, I2C.I2C_SR1.OFFSET)
        stored_globals = state.get_plugin("I2C1_globals")

        self.assertTrue(
            state.solver.satisfiable(
                extra_constraints=[
                    address_phase,
                    stored_globals.rw[0],
                    stored_globals.rw[1] == 0,
                    stored_sr1[I2C.I2C_SR1.ADDR.bit] == 1,
                    stored_globals.is_address_phase == claripy.false(),
                ]
            )
        )
        self.assertTrue(
            state.solver.satisfiable(
                extra_constraints=[
                    claripy.Not(address_phase),
                    stored_globals.rw[0] == claripy.false(),
                ]
            )
        )

    def test_post_write_reapplies_rc_w0_mask_before_side_effects(self):
        state, i2c = self.make_i2c_state()

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

        # Reproduce an engine store that used the original expression despite
        # the BP_BEFORE replacement.
        state.memory.store(
            sr1_addr,
            raw_clear_af,
            size=state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )
        state.inspect.mem_write_expr = raw_clear_af
        i2c.post_write(state)

        stored_sr1 = state.memory.load(
            sr1_addr, state.arch.bytes, endness=state.arch.memory_endness, inspect=False
        )
        self.assertEqual(0, state.solver.eval(stored_sr1[I2C.I2C_SR1.ARLO.bit]))
        self.assertEqual(0, state.solver.eval(stored_sr1[I2C.I2C_SR1.AF.bit]))
        self.assertEqual(state.solver.eval(masked_value), state.solver.eval(stored_sr1))

    def test_pending_buffer_irqs_are_disabled_when_dma_requests_are_enabled(self):
        state, i2c = self.make_i2c_state()
        dmaen = claripy.BVS("dmaen", 1)
        cr2 = (1 << I2C.I2C_CR2.ITEVTEN.bit) | (1 << I2C.I2C_CR2.ITBUFEN.bit)
        cr2 = utils.replace_bit(
            claripy.BVV(cr2, state.arch.bits), I2C.I2C_CR2.DMAEN.bit, dmaen
        )
        sr1 = (
            (1 << I2C.I2C_SR1.BTF.bit)
            | (1 << I2C.I2C_SR1.TXE.bit)
            | (1 << I2C.I2C_SR1.RXNE.bit)
        )

        self.store_register(state, i2c, I2C.I2C_CR2.OFFSET, cr2)
        self.store_register(state, i2c, I2C.I2C_SR1.OFFSET, sr1)

        event_irq_conditions = [
            condition
            for condition, metadata in i2c.get_pending_irqs(state)
            if metadata["irq"] == I2C.IRQ_NUMBERS[0]
        ]

        self.assertEqual(3, len(event_irq_conditions))
        for condition in event_irq_conditions:
            self.assertFalse(
                state.solver.satisfiable(
                    extra_constraints=[condition, dmaen == claripy.BVV(1, 1)]
                )
            )
            self.assertTrue(
                state.solver.satisfiable(
                    extra_constraints=[condition, dmaen == claripy.BVV(0, 1)]
                )
            )


class InterruptSchedulingTest(unittest.TestCase):
    def test_terminal_state_without_event_is_found_and_successor_is_discarded(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        end_addr = 0x080002DF
        state = project.factory.blank_state(addr=end_addr)
        manager = BaseCPU.AsynchronousEventManager(
            cpu=None,
            end_addrs=(end_addr,),
        )

        class Simgr:
            def step_state(self, current_state, **kwargs):
                del kwargs
                successor = current_state.copy()
                successor.regs.pc = end_addr + 2
                return {None: [successor]}

        result = manager.step_state(Simgr(), state)

        self.assertEqual({"found": [state]}, result)

    def test_terminal_state_processes_before_event_before_becoming_found(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        end_addr = 0x080002DF
        state = project.factory.blank_state(addr=end_addr)
        manager = BaseCPU.AsynchronousEventManager(
            cpu=None,
            end_addrs=(end_addr,),
        )

        class Handler(EventForkHandler):
            def get_eligible_events(self, current_state):
                del current_state
                return [(claripy.true(), {})]

            def trigger_event(self, current_state):
                current_state.regs.pc = 0x08000612

        handler = Handler()

        class Simgr:
            def step_state(self, current_state, **kwargs):
                del kwargs
                successor = current_state.copy()
                successor.regs.pc = end_addr + 2
                successor.asynevt_globals.before_check_handlers.add(handler)
                return {None: [successor]}

        result = manager.step_state(Simgr(), state)

        self.assertEqual([], result["found"])
        self.assertEqual(1, len(result[None]))
        self.assertEqual(0x08000612, result[None][0].addr)

    def test_equal_conditions_from_one_handler_remain_alternative_events(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state()
        manager = BaseCPU.AsynchronousEventManager(cpu=None, end_addrs=())
        handler = EventForkHandler()

        groups = manager._merge(
            state,
            [
                (claripy.true(), handler, {"irq": 31}),
                (claripy.true(), handler, {"irq": 32}),
            ],
        )

        self.assertEqual(2, len(groups))

    def test_only_first_equal_priority_irq_is_taken(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state(addr=0x08000000)
        manager = BaseCPU.AsynchronousEventManager(cpu=None, end_addrs=())

        class Handler(EventForkHandler):
            def get_eligible_events(self, current_state):
                del current_state
                return [(claripy.true(), {"irq": 31}), (claripy.true(), {"irq": 32})]

            def trigger_event(self, current_state, irq):
                current_state.regs.pc = 0x08000612 if irq == 31 else 0x08000624

        output = manager._process_event([(state, [Handler()])])

        self.assertEqual(1, len(output))
        self.assertEqual(0x08000612, output[0].addr)

    def test_overlapping_events_from_different_handlers_fire_together(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state(addr=0x08000000)
        manager = BaseCPU.AsynchronousEventManager(cpu=None, end_addrs=())
        txe = claripy.BVS("txe", 1)
        itbufen = claripy.BVS("itbufen", 1)
        dmaen = claripy.BVS("dmaen", 1)

        class Handler(EventForkHandler):
            def __init__(self, condition, bit, pc):
                self.condition = condition
                self.bit = bit
                self.pc = pc

            def get_eligible_events(self, current_state):
                del current_state
                return [(self.condition, {})]

            def trigger_event(self, current_state):
                current_state.globals["event_mask"] = (
                    current_state.globals.get("event_mask", 0) | self.bit
                )
                current_state.regs.pc = self.pc

        irq_handler = Handler(
            claripy.And(txe == 1, itbufen == 1),
            bit=1,
            pc=0x08000612,
        )
        dma_handler = Handler(
            claripy.And(txe == 1, dmaen == 1),
            bit=2,
            pc=0x08000624,
        )

        output = manager._process_event([(state, [irq_handler, dma_handler])])

        both = [s for s in output if s.globals.get("event_mask") == 3]
        self.assertEqual(1, len(both))
        self.assertTrue(
            both[0].solver.satisfiable(
                extra_constraints=[txe == 1, itbufen == 1, dmaen == 1]
            )
        )

    def test_mandatory_event_normal_path_is_constrained(self):
        project = angr.load_shellcode(b"\x00", arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state(addr=0x08000000)
        manager = BaseCPU.AsynchronousEventManager(cpu=None, end_addrs=())
        pending = claripy.BVS("pending_irq", 1)

        class Handler(EventForkHandler):
            def get_eligible_events(self, current_state):
                del current_state
                return [(pending == 1, {})]

            def trigger_event(self, current_state):
                current_state.regs.pc = 0x08000612

        output = manager._process_event([(state, [Handler()])])

        event_states = [s for s in output if s.addr == 0x08000612]
        normal_states = [s for s in output if s.addr == 0x08000000]
        self.assertEqual(1, len(event_states))
        self.assertEqual(1, len(normal_states))
        self.assertFalse(
            normal_states[0].solver.satisfiable(extra_constraints=[pending == 1])
        )

    def test_optional_event_normal_path_remains_unconstrained(self):
        project = angr.load_shellcode(b"\x00", arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state(addr=0x08000000)
        manager = BaseCPU.AsynchronousEventManager(cpu=None, end_addrs=())
        eligible = claripy.BVS("eligible_dma", 1)

        class Handler(EventForkHandler):
            NO_EVENT_CONSTRAINS_STATE = False

            def get_eligible_events(self, current_state):
                del current_state
                return [(eligible == 1, {})]

            def trigger_event(self, current_state):
                current_state.regs.pc = 0x08000624

        output = manager._process_event([(state, [Handler()])])

        normal_states = [s for s in output if s.addr == 0x08000000]
        self.assertEqual(1, len(normal_states))
        self.assertTrue(
            normal_states[0].solver.satisfiable(extra_constraints=[eligible == 1])
        )
        self.assertTrue(
            normal_states[0].solver.satisfiable(extra_constraints=[eligible == 0])
        )

    def test_optional_handler_does_not_constrain_other_event_paths(self):
        project = angr.load_shellcode(b"\x00", arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state(addr=0x08000000)
        manager = BaseCPU.AsynchronousEventManager(cpu=None, end_addrs=())
        txe = claripy.BVS("shared_txe", 1)
        itbufen = claripy.BVS("irq_itbufen", 1)
        dmaen = claripy.BVS("dma_dmaen", 1)

        class Handler(EventForkHandler):
            def __init__(self, condition, bit):
                self.condition = condition
                self.bit = bit

            def get_eligible_events(self, current_state):
                del current_state
                return [(self.condition, {})]

            def trigger_event(self, current_state):
                current_state.globals["event_mask"] = (
                    current_state.globals.get("event_mask", 0) | self.bit
                )
                current_state.regs.pc = 0x08000612

        class OptionalHandler(Handler):
            NO_EVENT_CONSTRAINS_STATE = False

        irq_handler = Handler(claripy.And(txe == 1, itbufen == 1), bit=1)
        dma_handler = OptionalHandler(claripy.And(txe == 1, dmaen == 1), bit=2)

        output = manager._process_event([(state, [irq_handler, dma_handler])])

        irq_only = [s for s in output if s.globals.get("event_mask") == 1]
        self.assertEqual(1, len(irq_only))
        self.assertTrue(
            irq_only[0].solver.satisfiable(
                extra_constraints=[txe == 1, itbufen == 1, dmaen == 1]
            )
        )

    def test_merge_key_separates_interrupt_contexts(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        thread_state = project.factory.blank_state(addr=0x08000000)
        handler_state = thread_state.copy()
        handler_state.globals["current_priority"] = 0
        handler_state.globals["priority_stack"] = [256]

        self.assertNotEqual(
            state_merge_key(thread_state), state_merge_key(handler_state)
        )

    def test_merge_key_allows_i2c_latch_states_that_merge_conditionally(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        left = project.factory.blank_state(addr=0x08000000)
        right = left.copy()
        left.register_plugin(
            "I2C1_globals",
            Globals(sr1_read=claripy.false()),
        )
        right.register_plugin(
            "I2C1_globals",
            Globals(sr1_read=claripy.true()),
        )

        self.assertEqual(state_merge_key(left), state_merge_key(right))

        left_globals = left.get_plugin("I2C1_globals")
        right_globals = right.get_plugin("I2C1_globals")
        other_condition = claripy.BoolS("other_condition")
        left_globals.merge(
            [right_globals],
            [claripy.Not(other_condition), other_condition],
        )

        self.assertTrue(
            left.solver.satisfiable(extra_constraints=[left_globals.sr1_read])
        )
        self.assertTrue(
            left.solver.satisfiable(
                extra_constraints=[claripy.Not(left_globals.sr1_read)]
            )
        )


if __name__ == "__main__":
    unittest.main()
