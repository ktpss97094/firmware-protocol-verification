import unittest
from types import SimpleNamespace

import angr
import claripy
import pyvex
from angr.analyses.reaching_definitions.engine_vex import SimEngineRDVEX
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions.subject import Subject
from angr.code_location import CodeLocation
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from project.analyses.memory import (
    Access,
    AnalysisReport,
    FlowReport,
    _PointerInitializer,
    _record_rda_memory,
    _Recorder,
)
from project.cores.base import BaseCPU
from project.types import AccessEffects, MemoryEffect, PluginEffect


class ReportCPU(BaseCPU):
    def __init__(self, report):
        self.report = report

    def get_isr_memory_report(self, state, specs):
        return self.report

    def _compute_dma_synchronize_instruction_checkpoints(self):
        return set()


class MemorySpec:
    END_ADDRS = ()

    def __init__(self, overrides=None):
        self.overrides = overrides or {}

    def get_access_effects(self, operation, address, size):
        return self.overrides.get(
            (operation, address), AccessEffects.memory_access(operation, address, size)
        )


def flow(name, accesses=(), unresolved_calls=()):
    return FlowReport(name, 0, set(accesses), set(unresolved_calls))


class MemoryCheckpointTests(unittest.TestCase):
    def checkpoints(self, main, *isrs, specs=None):
        cpu = ReportCPU(AnalysisReport(main, list(isrs)))
        regions, unresolved = cpu._get_shared_access_regions_and_unresolved(
            None, specs or MemorySpec()
        )
        checkpoints = set(unresolved)
        for current_flow in (main, *isrs):
            for access in current_flow.accesses:
                if access.address is None or access.unresolved is not None:
                    continue
                state = SimpleNamespace(
                    inspect=SimpleNamespace(
                        **{
                            f"mem_{access.operation}_address": access.address,
                            f"mem_{access.operation}_length": access.size,
                        }
                    )
                )
                if cpu._inspect_access_in_regions(
                    state, access.operation, regions[access.operation]
                ):
                    checkpoints.add(access.instruction)
        return checkpoints

    def test_cross_flow_write_conflict_selects_both_instructions(self):
        main = flow("main", [Access("write", 0x100, 4, 0x20000000)])
        isr = flow("ISR", [Access("read", 0x200, 1, 0x20000003)])
        self.assertEqual(self.checkpoints(main, isr), {0x100, 0x200})

    def test_read_only_sharing_is_independent(self):
        main = flow("main", [Access("read", 0x100, 4, 0x20000000)])
        isr = flow("ISR", [Access("read", 0x200, 4, 0x20000000)])
        self.assertEqual(self.checkpoints(main, isr), set())

    def test_same_flow_accesses_do_not_create_shared_dependencies(self):
        main = flow(
            "main",
            [
                Access("write", 0x100, 4, 0x20000000),
                Access("read", 0x104, 4, 0x20000000),
            ],
        )
        self.assertEqual(self.checkpoints(main, flow("ISR")), set())

    def test_adjacent_memory_ranges_do_not_overlap(self):
        main = flow("main", [Access("write", 0x100, 4, 0x20000000)])
        isr = flow("ISR", [Access("read", 0x200, 4, 0x20000004)])
        self.assertEqual(self.checkpoints(main, isr), set())

    def test_dependencies_between_two_isrs_are_included(self):
        first = flow("ISR_A", [Access("write", 0x200, 4, 0x20000000)])
        second = flow("ISR_B", [Access("write", 0x300, 4, 0x20000000)])
        self.assertEqual(self.checkpoints(flow("main"), first, second), {0x200, 0x300})

    def test_modeled_read_side_effects_create_dependencies(self):
        # Reading one peripheral register can clear another register or update
        # modeled peripheral state. Neither conflict requires a firmware store.
        for side_effect, counterpart in (
            (
                AccessEffects(memory=frozenset({MemoryEffect("write", 0x40000004, 4)})),
                AccessEffects.memory_access("read", 0x40000004, 4),
            ),
            (
                AccessEffects(
                    plugins=frozenset({PluginEffect("write", "i2c", ("status",))})
                ),
                AccessEffects(
                    plugins=frozenset({PluginEffect("read", "i2c", ("status",))})
                ),
            ),
        ):
            with self.subTest(side_effect=side_effect):
                main = flow("main", [Access("read", 0x100, 4, 0x40000000)])
                isr = flow("ISR", [Access("read", 0x200, 4, 0x40000004)])
                specs = MemorySpec(
                    {
                        ("read", 0x40000000): side_effect,
                        ("read", 0x40000004): counterpart,
                    }
                )
                self.assertEqual(
                    self.checkpoints(main, isr, specs=specs), {0x100, 0x200}
                )

    def test_unknown_addresses_do_not_expand_to_unrelated_known_accesses(self):
        main = flow(
            "main",
            [
                Access("read", 0x100, 4, 0x20000000),
                Access("write", 0x104, 4, 0x20000004),
            ],
        )
        for reason in (None, "unknown address", "stack address"):
            with self.subTest(reason=reason):
                isr = flow("ISR", [Access("read", 0x200, 4, unresolved=reason)])
                self.assertEqual(self.checkpoints(main, isr), {0x200})

    def test_unknown_points_preserve_known_dependencies(self):
        main = flow(
            "main",
            [
                Access("write", 0x100, 4, 0x20000000),
                Access("write", 0x104, 4, 0x20000004),
            ],
        )
        isr = flow(
            "ISR",
            [
                Access("read", 0x200, 4, 0x20000000),
                Access("read", 0x204, 4, unresolved="unknown address"),
            ],
        )
        self.assertEqual(self.checkpoints(main, isr), {0x100, 0x200, 0x204})

    def test_unknown_access_does_not_make_its_own_flow_shared(self):
        main = flow(
            "main",
            [
                Access("read", 0x100, 4, unresolved="unknown address"),
                Access("write", 0x104, 4, 0x20000000),
            ],
        )
        self.assertEqual(self.checkpoints(main, flow("ISR")), {0x100})

    def test_unresolved_call_does_not_expand_to_unrelated_known_accesses(self):
        main = flow("main", [Access("read", 0x100, 4, 0x20000000)])
        isr = flow("ISR", unresolved_calls=[0x208])
        self.assertEqual(self.checkpoints(main, isr), {0x208})

    def test_checkpoint_without_instruction_address_fails_explicitly(self):
        for broken in (
            flow("ISR", [Access("read", None, 4, unresolved="unknown address")]),
            flow("ISR", unresolved_calls=[None]),
        ):
            with self.subTest(broken=broken):
                main = flow("main", [Access("write", 0x100, 4, 0x20000000)])
                with self.assertRaisesRegex(ValueError, "instruction address"):
                    self.checkpoints(main, broken)

    def test_breakpoints_keep_memory_conditions_barriers_store_conditionals_and_ends(
        self,
    ):
        main = flow("main", [Access("write", 0x100, 4, 0x20000000)])
        isr = flow("ISR", [Access("read", 0x200, 4, 0x20000000)])
        cpu = ReportCPU(AnalysisReport(main, [isr]))
        statements = [
            pyvex.stmt.IMark(0x300, 4, 0),
            pyvex.stmt.MBE("Imbe_Fence"),
            pyvex.stmt.IMark(0x304, 4, 0),
            pyvex.stmt.LLSC(
                pyvex.expr.Const(pyvex.const.U32(0x20000000)),
                pyvex.expr.Const(pyvex.const.U32(1)),
                0,
                "Iend_LE",
            ),
            pyvex.stmt.IMark(0x308, 4, 0),
            pyvex.stmt.LLSC(
                pyvex.expr.Const(pyvex.const.U32(0x20000000)), None, 1, "Iend_LE"
            ),
        ]
        block = SimpleNamespace(
            vex=SimpleNamespace(statements=statements),
            instruction_addrs=[0x300, 0x304, 0x308],
        )
        project = SimpleNamespace(
            factory=SimpleNamespace(block=lambda *args, **kwargs: block)
        )
        cfg = SimpleNamespace(
            graph=SimpleNamespace(
                nodes=lambda: [SimpleNamespace(block=True, addr=0x300, size=12)]
            )
        )
        specs = MemorySpec()
        specs.END_ADDRS = (0x400,)

        breakpoints = cpu.get_static_interrupt_checkpoints(project, None, cfg, specs)

        self.assertEqual(
            {
                bp.kwargs["instruction"]
                for bp in breakpoints
                if bp.event_type == "instruction"
            },
            {0x300, 0x304, 0x400},
        )
        memory_breakpoints = {
            bp.event_type: bp for bp in breakpoints if bp.event_type.startswith("mem_")
        }
        self.assertEqual(set(memory_breakpoints), {"mem_read", "mem_write"})
        for event, breakpoint in memory_breakpoints.items():
            for address, expected in ((0x20000003, True), (0x20000004, False)):
                state = SimpleNamespace(
                    inspect=SimpleNamespace(
                        **{f"{event}_address": address, f"{event}_length": 1}
                    )
                )
                self.assertEqual(breakpoint.condition(state), expected)
        self.assertTrue(all(bp.when == angr.BP_BEFORE for bp in breakpoints))


class PointerTransferTests(unittest.TestCase):
    def test_measured_main_sp_resolves_escaped_pointer_and_runtime_checkpoint(self):
        project = angr.load_shellcode(
            b"\x70\x47", arch="ARMCortexM", load_address=0x1000
        )
        reset_sp = 0x20020000
        main_entry_sp = reset_sp - 16  # Startup has an outstanding PUSH frame.
        target = main_entry_sp - 32
        cell = 0x20000000
        stack = claripy.BVS("stack_base", project.arch.bits, explicit_name=True)
        recorder = _Recorder(collect_stores=True, app_root_entry_sp=main_entry_sp)
        recorder.record_addresses(
            SimpleNamespace(ins_addr=0x100), "write", [stack - 32], 4
        )
        recorder.record_store(
            SimpleNamespace(arch=project.arch),
            [cell],
            project.arch.bytes,
            MultiValues(stack - 32),
        )
        self.assertEqual(recorder.stores[cell], {target})
        self.assertEqual(recorder.accesses, {Access("write", 0x100, 4, target)})

        function = project.kb.functions.function(addr=0x1001, create=True)
        initializer = _PointerInitializer(project.arch, project, recorder.stores)
        state = ReachingDefinitionsState(
            CodeLocation(0x1001, 0),
            project.arch,
            Subject(function),
            None,
            initializer=initializer,
            merge_into_tops=False,
        )
        pointer = state.memory.load(
            cell, size=project.arch.bytes, endness=project.arch.memory_endness
        ).one_value()
        self.assertFalse(pointer.symbolic)
        self.assertEqual(pointer.concrete_value, target)

        isr_recorder = _Recorder()
        isr_recorder.record_addresses(
            SimpleNamespace(ins_addr=0x200), "read", [pointer], 1
        )
        cpu = ReportCPU(
            AnalysisReport(
                flow("main", recorder.accesses), [flow("ISR", isr_recorder.accesses)]
            )
        )
        regions, unresolved = cpu._get_shared_access_regions_and_unresolved(
            None, MemorySpec()
        )
        self.assertEqual(unresolved, set())
        for operation in ("read", "write"):
            for address, expected in ((target, True), (reset_sp - 32, False)):
                runtime = SimpleNamespace(
                    inspect=SimpleNamespace(
                        **{
                            f"mem_{operation}_address": address,
                            f"mem_{operation}_length": 1,
                        }
                    )
                )
                self.assertEqual(
                    cpu._inspect_access_in_regions(
                        runtime, operation, regions[operation]
                    ),
                    expected,
                )

    def test_main_sp_resolves_alignment_without_concretizing_unknowns(self):
        stack = claripy.BVS("stack_base", 32, explicit_name=True)
        unknown = claripy.BVS("TOP", 32, explicit_name=True)
        recorder = _Recorder(app_root_entry_sp=0x2001FFF4)

        self.assertEqual(recorder.concretize((stack - 20) & 0xFFFFFFF8), 0x2001FFE0)
        self.assertIsNone(recorder.concretize(stack + unknown))
        self.assertIsNone(recorder.concretize(unknown))
        self.assertIsNone(_Recorder().concretize(stack - 20))

    def test_incomplete_pointer_words_remain_unknown(self):
        project = angr.load_shellcode(
            b"\x70\x47", arch="ARMCortexM", load_address=0x1000
        )
        cell = 0x20000000
        candidates = {
            "fragmented": MultiValues(
                offset_to_values={
                    0: {claripy.BVV(0x2000, 16)},
                    2: {claripy.BVV(0x1234, 16)},
                }
            ),
            "empty": MultiValues(),
            "empty alternatives": MultiValues(offset_to_values={0: set()}),
            "short value": MultiValues(claripy.BVV(0x2000, 16)),
            "nonzero offset": MultiValues(
                offset_to_values={2: {claripy.BVV(0x20000020, 32)}}
            ),
        }
        for description, data in candidates.items():
            with self.subTest(description=description):
                recorder = _Recorder(collect_stores=True)
                recorder.record_store(
                    SimpleNamespace(arch=project.arch), [cell], project.arch.bytes, data
                )
                self.assertEqual(recorder.stores[cell], {None})

    def test_escaped_stack_pointer_stays_unknown_alongside_known_pointer(self):
        project = angr.load_shellcode(
            b"\x70\x47", arch="ARMCortexM", load_address=0x1000
        )
        cell, target = 0x20000000, 0x20000020
        stack = claripy.BVS("stack_base", project.arch.bits, explicit_name=True)
        recorder = _Recorder(collect_stores=True)
        recorder.record_store(
            SimpleNamespace(arch=project.arch),
            [cell],
            project.arch.bytes,
            MultiValues(
                offset_to_values={
                    0: {stack - 32, claripy.BVV(target, project.arch.bits)}
                }
            ),
        )
        function = project.kb.functions.function(addr=0x1001, create=True)
        initializer = _PointerInitializer(project.arch, project, recorder.stores)
        state = ReachingDefinitionsState(
            CodeLocation(0x1001, 0),
            project.arch,
            Subject(function),
            None,
            initializer=initializer,
            merge_into_tops=False,
        )

        stored = state.memory.load(
            cell, size=project.arch.bytes, endness=project.arch.memory_endness
        )
        alternatives = {value for values in stored.values() for value in values}

        self.assertTrue(any(state.is_top(value) for value in alternatives))
        self.assertEqual(
            {value.concrete_value for value in alternatives if not value.symbolic},
            {target},
        )
        self.assertFalse(any(state.is_stack_address(value) for value in alternatives))


class UnresolvedInstructionTests(unittest.TestCase):
    def test_ambiguous_guarded_and_exclusive_accesses_are_not_dropped(self):
        address = pyvex.expr.Const(pyvex.const.U32(0x20000000))
        value = pyvex.expr.Const(pyvex.const.U32(1))
        guard = pyvex.expr.Const(pyvex.const.U1(1))
        statements = (
            (
                "_handle_stmt_StoreG",
                pyvex.stmt.StoreG("Iend_LE", address, value, guard),
                "write",
            ),
            ("_handle_stmt_LLSC", pyvex.stmt.LLSC(address, None, 0, "Iend_LE"), "read"),
            (
                "_handle_stmt_LLSC",
                pyvex.stmt.LLSC(address, value, 0, "Iend_LE"),
                "write",
            ),
        )
        addresses = (
            MultiValues(),
            MultiValues(
                offset_to_values={
                    0: {claripy.BVV(0x2000, 16)},
                    2: {claripy.BVV(0x1234, 16)},
                }
            ),
        )
        for unresolved in addresses:
            for handler_name, statement, operation in statements:
                with self.subTest(
                    handler=handler_name, operation=operation, addresses=unresolved
                ):
                    engine = SimpleNamespace(
                        ins_addr=0x100,
                        arch=SimpleNamespace(byte_width=8),
                        tyenv=SimpleNamespace(sizeof=lambda tmp: 32),
                        _expr=lambda expr: MultiValues(claripy.BVV(1, 32)),
                        _expr_bv=lambda expr: MultiValues(claripy.BVV(1, 1))
                        if expr is guard
                        else unresolved,
                    )
                    recorder = _Recorder()
                    with _record_rda_memory(recorder):
                        getattr(SimEngineRDVEX, handler_name)(engine, statement)
                    self.assertEqual(len(recorder.accesses), 1)
                    access = next(iter(recorder.accesses))
                    self.assertEqual(
                        (access.operation, access.instruction, access.size),
                        (operation, 0x100, 4),
                    )
                    self.assertIsNone(access.address)
                    self.assertIsNotNone(access.unresolved)

    def test_empty_address_list_retains_unresolved_instruction(self):
        recorder = _Recorder()
        recorder.record_addresses(SimpleNamespace(ins_addr=0x100), "read", [], 4)
        self.assertEqual(len(recorder.accesses), 1)
        access = next(iter(recorder.accesses))
        self.assertEqual(
            (access.operation, access.instruction, access.size), ("read", 0x100, 4)
        )
        self.assertIsNone(access.address)
        self.assertIsNotNone(access.unresolved)


if __name__ == "__main__":
    unittest.main()
