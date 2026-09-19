from __future__ import annotations

import contextlib
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

import angr
import claripy
from angr.analyses.reaching_definitions.engine_vex import SimEngineRDVEX
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_initializer import RDAStateInitializer
from angr.errors import SimMemoryMissingError
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from project import utils


@dataclass(frozen=True)
class Access:
    operation: str
    instruction: int | None
    size: int
    address: int | None = None
    unresolved: str | None = None


@dataclass
class FlowReport:
    name: str
    address: int
    accesses: set[Access]
    unresolved_calls: set[int | None]


@dataclass
class AnalysisReport:
    app_root: FlowReport
    isrs: list[FlowReport]


@dataclass(frozen=True)
class ISRTarget:
    irq: int
    address: int
    source: int | None = None


class _FunctionHandler(FunctionHandler):
    """Recurse with the supplied ABI assumptions; report calls without a body analysis."""

    def __init__(self, depth: int, preserved_registers: tuple[str, ...]):
        super().__init__(depth)
        self.preserved_registers = preserved_registers
        self.unresolved_calls: set[int | None] = set()

    def handle_generic_function(self, state, data):
        # Includes unresolved targets and calls beyond the recursion limit. VEX's
        # callsite block may contain earlier instructions, so use the call itself.
        instruction = data.callsite_codeloc.ins_addr
        if instruction is None and data.callsite_codeloc.block_addr is not None:
            block = state.analysis.project.factory.block(
                data.callsite_codeloc.block_addr
            )
            if block.instruction_addrs:
                instruction = block.instruction_addrs[-1]
        self.unresolved_calls.add(instruction)
        super().handle_generic_function(state, data)

    def recurse_analysis(self, state, data) -> None:
        saved = {}
        for name in self.preserved_registers:
            offset, size = state.arch.registers[name]
            try:
                saved[offset] = state.registers.load(
                    offset, size, endness=state.arch.register_endness
                )
            except SimMemoryMissingError:
                continue

        super().recurse_analysis(state, data)

        for offset, values in saved.items():
            state.registers.store(offset, values, endness=state.arch.register_endness)


class _PointerInitializer(RDAStateInitializer):
    def __init__(self, arch, project, facts: dict[int, set[int | None]]):
        super().__init__(arch, project=project)
        self.facts = facts

    def initialize_function_state(
        self, state, cc, func_addr: int, rtoc_value: int | None = None
    ) -> None:
        super().initialize_function_state(state, cc, func_addr, rtoc_value)
        for address, values in self.facts.items():
            # Preserve unknown alternatives alongside resolved pointers. Main
            # stack pointers have already been bound to the main-entry SP.
            data = MultiValues(
                offset_to_values={
                    0: {
                        state.top(self.arch.bits)
                        if value is None
                        else claripy.BVV(value, self.arch.bits)
                        for value in values
                    }
                }
            )
            state.memory.store(
                address, data, size=self.arch.bytes, endness=self.arch.memory_endness
            )


class _Recorder:
    def __init__(self, collect_stores=False, app_root_entry_sp: int | None = None):
        self.app_root_entry_sp = app_root_entry_sp
        self._stack_values = {}
        self.accesses: set[Access] = set()
        self.collect_stores = collect_stores
        self.stores: dict[int, set[int | None]] = defaultdict(set)

    def concretize(self, value) -> int | None:
        if isinstance(value, int):
            return value
        if not value.symbolic:
            return value.concrete_value
        if self.app_root_entry_sp is None or value.variables != frozenset(
            {"stack_base"}
        ):
            return None
        # The RDA root is main, so this symbol denotes SP before main's prologue.
        # Solving also handles aligned PUSH addresses which get_stack_offset
        # cannot express as a simple offset.
        if value in self._stack_values:
            return self._stack_values[value]
        solver = claripy.Solver()
        solver.add(
            claripy.BVS("stack_base", value.size(), explicit_name=True)
            == self.app_root_entry_sp
        )
        concrete = solver.eval(value, 1)[0]
        self._stack_values[value] = concrete
        return concrete

    def record_addresses(self, engine, operation: str, addresses, size: int):
        if not addresses:
            self.accesses.add(
                Access(operation, engine.ins_addr, size, unresolved="empty address set")
            )
        for address in addresses:
            concrete = self.concretize(address)
            reason = None
            if concrete is None:
                if engine.state.is_top(address):
                    reason = "unknown address"
                elif engine.state.is_stack_address(address):
                    # An ISR can preempt at different stack depths. Its own stack
                    # must not be bound to the main-entry SP.
                    reason = "ISR stack address"
                else:
                    reason = "symbolic address"
            self.accesses.add(
                Access(operation, engine.ins_addr, size, concrete, reason)
            )

    def record_store(self, engine, addresses, size, data):
        if not self.collect_stores or size != engine.arch.bytes:
            return
        if (
            data.count() == 1
            and 0 in data
            and data[0]
            and all(
                isinstance(value, claripy.ast.BV) and value.size() == engine.arch.bits
                for value in data[0]
            )
        ):
            values = {self.concretize(value) for value in data[0]}
        else:
            # Fragments are not complete pointers; do not invent addresses by
            # treating each fragment as an independent machine word.
            values = {None}
        for address in addresses:
            if isinstance(address, int):
                self.stores[address].update(values)
            elif not address.symbolic:
                self.stores[address.concrete_value].update(values)


@contextlib.contextmanager
def _record_rda_memory(recorder: _Recorder):
    # RDA creates its own engines, including for recursive calls. Scope these
    # hooks to a single synchronous analysis and always restore them.
    original_load = SimEngineRDVEX._load_core
    original_store = SimEngineRDVEX._store_core
    original_load_expr = SimEngineRDVEX._handle_expr_Load
    statement_handlers = {
        name: getattr(SimEngineRDVEX, name)
        for name in ("_handle_stmt_Store", "_handle_stmt_StoreG", "_handle_stmt_LLSC")
    }

    def load_core(engine, addresses, size, endness):
        address_list = list(addresses)
        recorder.record_addresses(engine, "read", address_list, size)
        return original_load(engine, address_list, size, endness)

    def store_core(engine, addresses, size, data, data_old=None, endness=None):
        address_list = list(addresses)
        recorder.record_addresses(engine, "write", address_list, size)
        recorder.record_store(
            engine,
            address_list,
            size,
            data.merge(data_old) if data_old is not None else data,
        )
        return original_store(
            engine, address_list, size, data, data_old=data_old, endness=endness
        )

    def load_expr(engine, expr):
        addresses = engine._expr_bv(expr.addr)
        if not (addresses.count() == 1 and 0 in addresses):
            recorder.accesses.add(
                Access(
                    "read",
                    engine.ins_addr,
                    expr.result_size(engine.tyenv) // engine.arch.byte_width,
                    unresolved="non-singleton address set",
                )
            )
        return original_load_expr(engine, expr)

    def wrap_statement(original):
        def statement(engine, stmt):
            if engine._expr_bv(stmt.addr).count() != 1:
                data = stmt.data if hasattr(stmt, "data") else stmt.storedata
                bits = (
                    engine.tyenv.sizeof(stmt.result)
                    if data is None
                    else data.result_size(engine.tyenv)
                )
                recorder.accesses.add(
                    Access(
                        "read" if data is None else "write",
                        engine.ins_addr,
                        bits // engine.arch.byte_width,
                        unresolved="non-singleton address set",
                    )
                )
            return original(engine, stmt)

        return statement

    SimEngineRDVEX._load_core = load_core
    SimEngineRDVEX._store_core = store_core
    SimEngineRDVEX._handle_expr_Load = load_expr
    for name, original in statement_handlers.items():
        setattr(SimEngineRDVEX, name, wrap_statement(original))
    try:
        yield
    finally:
        SimEngineRDVEX._load_core = original_load
        SimEngineRDVEX._store_core = original_store
        SimEngineRDVEX._handle_expr_Load = original_load_expr
        for name, original in statement_handlers.items():
            setattr(SimEngineRDVEX, name, original)


class MemoryAnalyzer:
    """Collect accesses per flow; dependency and side-effect checks belong to the CPU.

    Bind main's stack to its measured entry SP so exported stack pointers retain
    their addresses in ISR analysis. ISR-local stacks and other unresolved points
    remain explicit; CFG/RDA coverage and analysis bounds still limit completeness.
    """

    def __init__(
        self,
        elf_path: Path,
        *,
        app_root_entry_sp: int,
        app_root: str = "main",
        init_depth: int = 4,
        isr_depth: int = 8,
        max_iterations: int = 8,
        preserved_registers: tuple[str, ...] = (),
    ):
        self.app_root_entry_sp = app_root_entry_sp
        self.app_root = app_root
        self.init_depth = init_depth
        self.isr_depth = isr_depth
        self.max_iterations = max_iterations
        self.preserved_registers = preserved_registers
        self.project = angr.Project(elf_path, auto_load_libs=False)
        self.cfg = self.project.analyses.CFGFast(
            normalize=True, data_references=True, resolve_indirect_jumps=True
        )
        self.project.analyses.CompleteCallingConventions(
            recover_variables=True, analyze_callsites=True
        )

    def _analyze_flow(self, function, depth, recorder, initializer=None):
        handler = _FunctionHandler(depth, self.preserved_registers)
        with _record_rda_memory(recorder):
            self.project.analyses.ReachingDefinitions(
                function,
                function_handler=handler,
                state_initializer=initializer,
                track_tmps=True,
                element_limit=30,
                max_iterations=self.max_iterations,
                merge_into_tops=False,
                track_liveness=False,
            )
        return FlowReport(
            function.name, function.addr, recorder.accesses, handler.unresolved_calls
        )

    def analyze(self, specs, isr_targets: tuple[ISRTarget, ...]) -> AnalysisReport:
        main_recorder = _Recorder(
            collect_stores=True, app_root_entry_sp=self.app_root_entry_sp
        )
        main = self._analyze_flow(
            utils.get_func_by_name(self.cfg, self.app_root),
            self.init_depth,
            main_recorder,
        )
        # Infer possible pointer cells from word stores to writable memory.
        # Avoid initializing unrelated scalar state from main's stores; retain
        # all alternatives (including unknowns) once a cell may hold a pointer.
        facts = {}
        for address, values in main_recorder.stores.items():
            section = self.project.loader.find_section_containing(address)
            region = specs.get_memory_region(address)
            writable = (section is not None and section.is_writable) or (
                region is not None and region.transfer
            )
            if writable and any(
                value is None
                or specs.get_memory_region(value) is not None
                or self.project.loader.find_section_containing(value) is not None
                for value in values
            ):
                facts[address] = values
        initializer = _PointerInitializer(self.project.arch, self.project, facts)
        reports = {}
        isrs = []
        for target in isr_targets:
            if target.address not in reports:
                try:
                    function = utils.get_func_by_addr(self.cfg, target.address)
                except ValueError as error:
                    raise ValueError(
                        f"Cannot resolve modeled IRQ {target.irq} at {target.address:#x}"
                    ) from error
                reports[target.address] = self._analyze_flow(
                    function, self.isr_depth, _Recorder(), initializer
                )
            # Distinct IRQs remain distinct flows even when they share a handler.
            isrs.append(reports[target.address])
        return AnalysisReport(main, isrs)
