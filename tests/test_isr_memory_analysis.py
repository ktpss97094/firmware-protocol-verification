from __future__ import annotations

import unittest
from pathlib import Path

import angr
import claripy

from firmwares.stm32f429.protocols.I2C.spec_hw import Specs
from project.analyses.isr_memory import (
    ISRMemoryRegions,
    RegionAccess,
    analyze_isr_memory,
)
from project.cores.arm.cortex_m.cortex_m import CortexM
from project.cores.base import BaseCPU
from project.main import state_merge_key
from project.peripherals.stm32f4.i2c import Globals, I2C
from project.types import AccessEffects, EventForkHandler, MemoryEffect, PluginEffect


ROOT = Path(__file__).resolve().parents[1]
ELF = (
    ROOT
    / "firmwares/stm32f429/build/protocols/I2C/master/Interrupt_Mode"
    / "stm32f4xx-hal-driver/firmware.elf"
)
SVD = (
    ROOT
    / "firmwares/stm32f429/protocols/I2C/master/Interrupt_Mode"
    / "stm32f4xx-hal-driver/STM32F429.svd"
)


class ISRMemoryAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        specs = Specs(project)
        cls.report = analyze_isr_memory(
            ELF,
            specs,
            svd_path=SVD,
        )

    def test_modeled_mmio_irqs_are_discovered_from_vector_table(self):
        targets = {
            report.irq: (report.address, report.isr) for report in self.report.isrs
        }
        self.assertEqual(
            {11, 12, 13, 14, 15, 16, 17, 31, 32},
            set(targets),
        )
        self.assertEqual((0x08000613, "I2C1_EV_IRQHandler"), targets[31])
        self.assertEqual((0x08000625, "I2C1_ER_IRQHandler"), targets[32])

    def test_identified_regions_support_fast_address_membership(self):
        regions = ISRMemoryRegions.from_report(self.report)
        main_data = next(region for region in regions if region.name == "main::data")

        self.assertIn(main_data.start, regions)
        self.assertIn(main_data.end - 1, regions)
        self.assertNotIn(0xDEADBEEF, regions)

    def test_main_stack_pointer_escape_is_recovered(self):
        facts = {
            (fact.cell.name, fact.value, fact.target)
            for fact in self.report.pointer_facts
        }
        self.assertIn(
            ("hi2c1.Instance", 0x40005400, "I2C1"),
            facts,
        )
        self.assertIn(
            ("hi2c1.pBuffPtr", 0x2001FFF4, "main::data"),
            facts,
        )

    def test_event_isr_resolves_expected_shared_regions(self):
        event = next(
            report
            for report in self.report.isrs
            if report.irq == 31
        )
        regions = {region.name: region for region in event.regions}
        self.assertIn("hi2c1", regions)
        self.assertIn("main::data", regions)
        for register in ("I2C1.CR1", "I2C1.CR2", "I2C1.DR", "I2C1.SR1", "I2C1.SR2"):
            self.assertIn(register, regions)
        self.assertEqual(("read", "write"), regions["main::data"].operations)
        self.assertIn(
            PluginEffect(
                "write",
                "I2C1_globals",
                ("is_address_phase", "rw", "sr1_read"),
            ),
            event.effects.plugins,
        )
        self.assertIn(
            MemoryEffect("write", 0x40005414, 4),
            event.effects.memory,
        )

    def test_error_isr_resolves_buffer_write_and_reports_incompleteness(self):
        error = next(
            report
            for report in self.report.isrs
            if report.irq == 32
        )
        regions = {region.name: region for region in error.regions}
        self.assertEqual(("write",), regions["main::data"].operations)
        self.assertTrue(error.unresolved_accesses)
        self.assertTrue(error.unresolved_calls)
        self.assertFalse(error.complete)
        self.assertFalse(self.report.complete)


class ISRMemoryRegionsTest(unittest.TestCase):
    def test_overlapping_regions_are_deduplicated_and_indexed(self):
        regions = ISRMemoryRegions(
            [
                RegionAccess("first", "global", 0x1000, 0x10, (), (), ()),
                RegionAccess("first", "global", 0x1000, 0x10, (), (), ()),
                RegionAccess("second", "global", 0x1008, 0x10, (), (), ()),
            ]
        )

        self.assertEqual(2, len(regions))
        self.assertIn(0x1000, regions)
        self.assertIn(0x1017, regions)
        self.assertNotIn(0x1018, regions)


class AccessEffectsTest(unittest.TestCase):
    def test_memory_conflicts_require_an_overlapping_write(self):
        read = AccessEffects.memory_access("read", 0x1000, 4)
        overlapping_read = AccessEffects.memory_access("read", 0x1002, 4)
        overlapping_write = AccessEffects.memory_access("write", 0x1002, 4)

        self.assertFalse(read.conflicts_with(overlapping_read))
        self.assertTrue(read.conflicts_with(overlapping_write))
        self.assertTrue(overlapping_write.writes_resources_used_by(read))

    def test_plugin_fields_are_resources(self):
        read = AccessEffects(
            plugins=frozenset(
                {PluginEffect("read", "I2C1_globals", ("sr1_read",))}
            )
        )
        write_same = AccessEffects(
            plugins=frozenset(
                {PluginEffect("write", "I2C1_globals", ("sr1_read",))}
            )
        )
        write_other = AccessEffects(
            plugins=frozenset(
                {PluginEffect("write", "I2C1_globals", ("rw",))}
            )
        )

        self.assertTrue(read.conflicts_with(write_same))
        self.assertFalse(read.conflicts_with(write_other))

    def test_i2c_access_includes_modeled_memory_and_plugin_effects(self):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        specs = Specs(project)
        effects = specs.MEMORY_REGIONS["I2C1"].get_access_effects(
            "read", 0x40005414, 4
        )

        self.assertIn(MemoryEffect("read", 0x40005414, 4), effects.memory)
        self.assertIn(MemoryEffect("write", 0x40005400, 4), effects.memory)
        self.assertIn(MemoryEffect("write", 0x40005414, 4), effects.memory)
        self.assertIn(MemoryEffect("write", 0x40005418, 4), effects.memory)
        self.assertIn(
            PluginEffect(
                "write",
                "I2C1_globals",
                ("is_address_phase", "rw", "sr1_read"),
            ),
            effects.plugins,
        )

    def test_cortex_checkpoint_considers_i2c_plugin_side_effects(self):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        specs = Specs(project)
        state = project.factory.blank_state()
        isr_effects = AccessEffects(
            plugins=frozenset(
                {
                    PluginEffect(
                        "read",
                        "I2C1_globals",
                        ("sr1_read",),
                    )
                }
            )
        )

        class CPU:
            @staticmethod
            def get_isr_shared_effects(project, current_specs):
                del project, current_specs
                return isr_effects

        handler = object.__new__(CortexM._InterruptHandler)
        handler.cpu = CPU()
        handler.specs = specs

        self.assertTrue(
            handler.in_globally_accessible_region(
                state,
                specs.MEMORY_REGIONS["I2C1"].start
                + specs.MEMORY_REGIONS["I2C1"].I2C_SR1.OFFSET,
                "read",
                4,
            )
        )
        self.assertFalse(
            handler.in_globally_accessible_region(
                state,
                specs.MEMORY_REGIONS["RAM"].start,
                "read",
                4,
            )
        )


class I2CModelTest(unittest.TestCase):
    def test_post_write_reapplies_rc_w0_mask_before_side_effects(self):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        state = project.factory.blank_state()
        specs = Specs(project)
        i2c = specs.MEMORY_REGIONS["I2C1"]
        state.register_plugin("I2C1_globals", Globals())

        for offset in (
            I2C.I2C_CR1.OFFSET,
            I2C.I2C_SR1.OFFSET,
            I2C.I2C_SR2.OFFSET,
        ):
            state.memory.store(
                i2c.start + offset,
                claripy.BVV(0, state.arch.bits),
                size=state.arch.bytes,
                endness=state.arch.memory_endness,
                inspect=False,
            )

        sr1_addr = i2c.start + I2C.I2C_SR1.OFFSET
        old_sr1 = claripy.BVV(1 << I2C.I2C_SR1.AF.bit, state.arch.bits)
        raw_clear_af = claripy.BVV(
            (~(1 << I2C.I2C_SR1.AF.bit)) & 0xFFFFFFFF,
            state.arch.bits,
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
            sr1_addr,
            state.arch.bytes,
            endness=state.arch.memory_endness,
            inspect=False,
        )
        self.assertEqual(
            0,
            state.solver.eval(stored_sr1[I2C.I2C_SR1.ARLO.bit]),
        )
        self.assertEqual(
            0,
            state.solver.eval(stored_sr1[I2C.I2C_SR1.AF.bit]),
        )
        self.assertEqual(
            state.solver.eval(masked_value),
            state.solver.eval(stored_sr1),
        )

    def test_arbitration_loss_dominates_start_when_updating_master_mode(self):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        state = project.factory.blank_state()
        specs = Specs(project)
        i2c = specs.MEMORY_REGIONS["I2C1"]

        sr1 = claripy.BVV(0, state.arch.bits)
        sr2 = claripy.BVV(1, state.arch.bits)
        cr1 = claripy.BVV(0, state.arch.bits)
        arlo = claripy.BVS("test_ARLO", 1)
        sb = claripy.BVS("test_SB", 1)

        sr1, sr2 = I2C.I2C_SR1.update_ARLO(
            i2c, state, sr1, cr1, sr2, force=True, value=arlo
        )
        sr1, cr1, sr2 = I2C.I2C_SR1.update_SB(
            i2c, state, sr1, cr1, sr2, force=True, value=sb
        )

        invalid_master_after_arlo = claripy.And(
            sr1[I2C.I2C_SR1.ARLO.bit] == 1,
            sr2[I2C.I2C_SR2.MSL.bit] == 1,
        )
        self.assertFalse(
            state.solver.satisfiable(
                extra_constraints=[invalid_master_after_arlo]
            )
        )


class InterruptSchedulingTest(unittest.TestCase):
    def test_equal_conditions_from_one_handler_remain_alternative_events(self):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        state = project.factory.blank_state()
        manager = BaseCPU.ForkEventManager(cpu=None, end_addrs=())
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
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        state = project.factory.blank_state(addr=0x08000000)
        manager = BaseCPU.ForkEventManager(cpu=None, end_addrs=())

        class Handler(EventForkHandler):
            def get_eligible_events(self, current_state):
                del current_state
                return [
                    (claripy.true(), {"irq": 31}),
                    (claripy.true(), {"irq": 32}),
                ]

            def trigger_event(self, current_state, irq):
                current_state.regs.pc = 0x08000612 if irq == 31 else 0x08000624

        output = manager._process_event([(state, [Handler()])])

        self.assertEqual(1, len(output))
        self.assertEqual(0x08000612, output[0].addr)

    def test_merge_key_separates_interrupt_contexts(self):
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        thread_state = project.factory.blank_state(addr=0x08000000)
        handler_state = thread_state.copy()
        handler_state.globals["current_priority"] = 0
        handler_state.globals["priority_stack"] = [256]

        self.assertNotEqual(
            state_merge_key(thread_state),
            state_merge_key(handler_state),
        )


if __name__ == "__main__":
    unittest.main()
