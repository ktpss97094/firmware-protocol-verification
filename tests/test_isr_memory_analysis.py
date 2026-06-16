from __future__ import annotations

import unittest
from pathlib import Path
from types import SimpleNamespace

import angr
import claripy

from firmwares.stm32f429.protocols.I2C.spec_hw import Specs
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
    def test_post_write_reapplies_rc_w0_mask_before_side_effects(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        state = project.factory.blank_state()
        specs = Specs(project)
        i2c = specs.MEMORY_REGIONS["I2C1"]
        state.register_plugin("I2C1_globals", Globals())

        for offset in (I2C.I2C_CR1.OFFSET, I2C.I2C_SR1.OFFSET, I2C.I2C_SR2.OFFSET):
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

    def test_merge_key_separates_interrupt_contexts(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        thread_state = project.factory.blank_state(addr=0x08000000)
        handler_state = thread_state.copy()
        handler_state.globals["current_priority"] = 0
        handler_state.globals["priority_stack"] = [256]

        self.assertNotEqual(
            state_merge_key(thread_state), state_merge_key(handler_state)
        )

    def test_merge_key_separates_plugin_states_that_reject_merge(self):
        project = angr.Project(str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH)
        left = project.factory.blank_state(addr=0x08000000)
        right = left.copy()
        left.register_plugin(
            "I2C1_globals",
            Globals(is_address_phase=claripy.false()),
        )
        right.register_plugin(
            "I2C1_globals",
            Globals(is_address_phase=claripy.true()),
        )

        self.assertNotEqual(state_merge_key(left), state_merge_key(right))


if __name__ == "__main__":
    unittest.main()
