from __future__ import annotations

import contextlib
import dataclasses
import logging
from collections import defaultdict
from pathlib import Path

import angr
import claripy
from angr.analyses.reaching_definitions.engine_vex import SimEngineRDVEX
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_initializer import RDAStateInitializer
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues

from project.types import AccessEffects, MMIOMemoryRegion

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class MemoryObject:
    name: str
    start: int
    size: int
    kind: str

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclasses.dataclass(frozen=True)
class PointerCell:
    name: str
    address: int


@dataclasses.dataclass(frozen=True)
class PointerFact:
    cell: PointerCell
    value: int
    target: str
    instruction: int | None


@dataclasses.dataclass(frozen=True)
class Access:
    operation: str
    instruction: int | None
    size: int
    function: str
    address: int | None = None
    stack_offset: int | None = None
    unresolved: str | None = None


@dataclasses.dataclass(frozen=True)
class RegionAccess:
    name: str
    kind: str
    start: int
    size: int
    operations: tuple[str, ...]
    addresses: tuple[int, ...]
    functions: tuple[str, ...]


@dataclasses.dataclass
class ISRReport:
    isr: str
    irq: int
    address: int
    accesses: list[Access]
    regions: list[RegionAccess]
    unresolved_accesses: list[Access]
    unresolved_calls: list[tuple[str, int]]
    effects: AccessEffects = dataclasses.field(default_factory=AccessEffects)

    @property
    def complete(self) -> bool:
        return not self.unresolved_accesses and not self.unresolved_calls


@dataclasses.dataclass
class AnalysisReport:
    elf: Path
    initializer: str
    pointer_facts: list[PointerFact]
    initializer_accesses: list[Access]
    initializer_unresolved_calls: list[tuple[str, int]]
    isrs: list[ISRReport]

    @property
    def complete(self) -> bool:
        return (
            not any(
                access.unresolved is not None
                for access in self.initializer_accesses
            )
            and not self.initializer_unresolved_calls
            and all(report.complete for report in self.isrs)
        )

    @property
    def effects(self) -> AccessEffects:
        effects = AccessEffects()
        for report in self.isrs:
            effects = effects.union(report.effects)
        return effects


@dataclasses.dataclass
class _RawAccess:
    operation: str
    instruction: int | None
    size: int
    address: int | None = None
    stack_offset: int | None = None
    unresolved: str | None = None


@dataclasses.dataclass
class _RawStore:
    instruction: int | None
    address: int
    size: int
    values: tuple[claripy.ast.BV, ...]


@dataclasses.dataclass(frozen=True)
class _ISRTarget:
    irq: int
    vector_address: int
    address: int
    function: object


class _BinaryObjectIndex:
    def __init__(self, project):
        objects = {}
        for symbol in project.loader.main_object.symbols:
            if symbol.size <= 0 or symbol.type.name != "TYPE_OBJECT":
                continue
            key = (symbol.rebased_addr, symbol.size, symbol.name)
            objects[key] = MemoryObject(
                symbol.name, symbol.rebased_addr, symbol.size, "symbol"
            )
        self.objects = sorted(
            objects.values(), key=lambda obj: (obj.start, -obj.size, obj.name)
        )

    def find_object(self, address: int) -> MemoryObject | None:
        matches = [obj for obj in self.objects if obj.start <= address < obj.end]
        return min(matches, key=lambda obj: obj.size) if matches else None

    def name_for(self, address: int) -> str:
        obj = self.find_object(address)
        if obj is None:
            return f"memory@{address:#x}"
        offset = address - obj.start
        return obj.name if offset == 0 else f"{obj.name}+{offset:#x}"


class _PreservingFunctionHandler(FunctionHandler):
    _preserved_registers = ("sp", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11")

    def handle_local_function(self, state, data) -> None:
        if (
            self.interfunction_level <= 0
            or data.function is None
            or data.function.name == "UnresolvableCallTarget"
        ):
            self.handle_generic_function(state, data)
            return

        saved = {}
        for reg_name in self._preserved_registers:
            offset, size = state.arch.registers[reg_name]
            with contextlib.suppress(Exception):
                saved[reg_name] = state.registers.load(
                    offset, size, endness=state.arch.register_endness
                )

        self.interfunction_level -= 1
        try:
            self.recurse_analysis(state, data)
        finally:
            self.interfunction_level += 1

        for reg_name, values in saved.items():
            offset, _ = state.arch.registers[reg_name]
            state.registers.store(offset, values, endness=state.arch.register_endness)


class _PointerInitializer(RDAStateInitializer):
    def __init__(self, arch, project, facts: dict[int, set[int]]):
        super().__init__(arch, project=project)
        self.facts = facts

    def initialize_function_state(
        self, state, cc, func_addr: int, rtoc_value: int | None = None
    ) -> None:
        super().initialize_function_state(state, cc, func_addr, rtoc_value)
        for address, values in self.facts.items():
            if not values:
                continue
            data = MultiValues(
                offset_to_values={
                    0: {claripy.BVV(value, self.arch.bits) for value in values}
                }
            )
            state.memory.store(
                address, data, size=self.arch.bytes, endness=self.arch.memory_endness
            )


class _Recorder:
    def __init__(self):
        self.accesses: list[_RawAccess] = []
        self.stores: list[_RawStore] = []

    def _record_addresses(self, engine, operation: str, addresses, size: int):
        for address in addresses:
            if isinstance(address, int):
                self.accesses.append(
                    _RawAccess(operation, engine.ins_addr, size, address=address)
                )
            elif engine.state.is_top(address):
                self.accesses.append(
                    _RawAccess(
                        operation, engine.ins_addr, size, unresolved="TOP address"
                    )
                )
            elif engine.state.is_stack_address(address):
                self.accesses.append(
                    _RawAccess(
                        operation,
                        engine.ins_addr,
                        size,
                        stack_offset=engine.state.get_stack_offset(address),
                    )
                )
            elif not address.symbolic:
                self.accesses.append(
                    _RawAccess(
                        operation, engine.ins_addr, size, address=address.concrete_value
                    )
                )
            else:
                self.accesses.append(
                    _RawAccess(
                        operation, engine.ins_addr, size, unresolved=str(address)
                    )
                )


@contextlib.contextmanager
def _record_rda_memory(recorder: _Recorder):
    original_load = SimEngineRDVEX._load_core
    original_store = SimEngineRDVEX._store_core
    original_load_expr = SimEngineRDVEX._handle_expr_Load

    def load_core(engine, addresses, size, endness):
        address_list = list(addresses)
        recorder._record_addresses(engine, "read", address_list, size)
        return original_load(engine, address_list, size, endness)

    def store_core(engine, addresses, size, data, data_old=None, endness=None):
        address_list = list(addresses)
        recorder._record_addresses(engine, "write", address_list, size)
        values = tuple(value for _, value_set in data.items() for value in value_set)
        for address in address_list:
            if isinstance(address, int):
                concrete = address
            elif address.symbolic:
                continue
            else:
                concrete = address.concrete_value
            recorder.stores.append(_RawStore(engine.ins_addr, concrete, size, values))
        return original_store(
            engine, address_list, size, data, data_old=data_old, endness=endness
        )

    def load_expr(engine, expr):
        addresses = engine._expr_bv(expr.addr)
        if not (addresses.count() == 1 and 0 in addresses):
            recorder.accesses.append(
                _RawAccess(
                    "read",
                    engine.ins_addr,
                    expr.result_size(engine.tyenv) // engine.arch.byte_width,
                    unresolved="non-singleton address set",
                )
            )
        return original_load_expr(engine, expr)

    SimEngineRDVEX._load_core = load_core
    SimEngineRDVEX._store_core = store_core
    SimEngineRDVEX._handle_expr_Load = load_expr
    try:
        yield
    finally:
        SimEngineRDVEX._load_core = original_load
        SimEngineRDVEX._store_core = original_store
        SimEngineRDVEX._handle_expr_Load = original_load_expr


class ISRMemoryAnalyzer:
    def __init__(
        self,
        elf_path: str | Path,
        *,
        initializer: str = "main",
        init_depth: int = 4,
        isr_depth: int = 8,
        max_iterations: int = 8,
    ):
        self.elf_path = Path(elf_path).resolve()
        self.initializer = initializer
        self.init_depth = init_depth
        self.isr_depth = isr_depth
        self.max_iterations = max_iterations

        self.project = angr.Project(str(self.elf_path), auto_load_libs=False)
        self.cfg = self.project.analyses.CFGFast(
            normalize=True, data_references=True, resolve_indirect_jumps=True
        )
        fact_logger = logging.getLogger(
            "angr.analyses.calling_convention.fact_collector.SimEngineFactCollectorVEX"
        )
        previous_level = fact_logger.level
        fact_logger.setLevel(logging.CRITICAL)
        try:
            self.project.analyses.CompleteCallingConventions(
                recover_variables=True, analyze_callsites=True
            )
        finally:
            fact_logger.setLevel(previous_level)

        stack_symbol = self.project.loader.find_symbol("_estack")
        self.stack_base = (
            stack_symbol.rebased_addr if stack_symbol is not None else None
        )
        self.binary_objects = _BinaryObjectIndex(self.project)

    def _function_by_name(self, name: str):
        function = self.cfg.kb.functions.function(name=name)
        if function is None:
            raise ValueError(f"Function not found in ELF: {name}")
        return function

    def _function_at(self, address: int):
        function = self.cfg.kb.functions.get(address)
        if function is None:
            raise ValueError(f"Function not found at ISR address {address:#x}")
        return function

    def _vector_table_base(self) -> int:
        symbol = self.project.loader.find_symbol("g_pfnVectors")
        if symbol is not None:
            return symbol.rebased_addr

        for section in self.project.loader.main_object.sections:
            if section.name == ".isr_vector":
                return section.vaddr

        raise ValueError(
            "Cannot locate the Cortex-M vector table: "
            "ELF has neither g_pfnVectors nor an .isr_vector section"
        )

    @staticmethod
    def _modeled_irq_numbers(specs) -> list[int]:
        irq_numbers = set()
        for region in specs.get_MMIOMemoryRegions():
            for irq in getattr(region, "IRQ_NUMBERS", ()) or ():
                irq = int(irq)
                if irq < 0:
                    raise ValueError(
                        f"Invalid IRQ number {irq} on MMIO region {region.name}"
                    )
                irq_numbers.add(irq)
        return sorted(irq_numbers)

    def _isr_targets(self, specs) -> list[_ISRTarget]:
        vector_table_base = self._vector_table_base()
        targets = []
        for irq in self._modeled_irq_numbers(specs):
            vector_address = vector_table_base + (irq + 16) * self.project.arch.bytes
            if vector_address not in self.project.loader.memory:
                raise ValueError(
                    f"Vector entry for IRQ {irq} is not mapped at {vector_address:#x}"
                )

            address = self.project.loader.memory.unpack_word(
                vector_address,
                size=self.project.arch.bytes,
                endness=self.project.arch.memory_endness,
            )
            if address == 0:
                raise ValueError(f"Vector entry for modeled IRQ {irq} is null")

            try:
                function = self._function_at(address)
            except ValueError as error:
                raise ValueError(
                    f"Cannot resolve modeled IRQ {irq}: vector entry "
                    f"{vector_address:#x} points to {address:#x}"
                ) from error
            targets.append(_ISRTarget(irq, vector_address, address, function))
        return targets

    def _function_name(self, instruction: int | None) -> str:
        if instruction is None:
            return "<external>"
        function = self.cfg.kb.functions.floor_func(instruction)
        return function.name if function is not None else "<unknown>"

    @staticmethod
    def _is_pointer_value(value: claripy.ast.BV) -> bool:
        if not value.symbolic:
            concrete = value.concrete_value
            return (
                0x08000000 <= concrete < 0x10000000
                or 0x10000000 <= concrete < 0x40000000
                or 0x40000000 <= concrete < 0x60000000
                or concrete >= 0xE0000000
            )
        return value.variables == frozenset({"stack_base"})

    def _concretize_pointer(self, value: claripy.ast.BV) -> int | None:
        if not value.symbolic:
            return value.concrete_value
        if self.stack_base is None or value.variables != frozenset({"stack_base"}):
            return None
        stack_var = claripy.BVS(
            "stack_base", self.project.arch.bits, explicit_name=True
        )
        solver = claripy.Solver()
        solver.add(stack_var == self.stack_base)
        solutions = solver.eval(value, 2)
        return solutions[0] if len(solutions) == 1 else None

    def _collect_pointer_facts(
        self, specs
    ) -> tuple[dict[int, set[int]], list[PointerFact], list[_RawAccess]]:
        recorder = _Recorder()
        with _record_rda_memory(recorder):
            self.project.analyses.ReachingDefinitions(
                self._function_by_name(self.initializer),
                function_handler=_PreservingFunctionHandler(self.init_depth),
                track_tmps=True,
                element_limit=30,
                max_iterations=self.max_iterations,
                merge_into_tops=False,
                track_liveness=False,
            )

        values_by_cell: dict[int, set[int]] = defaultdict(set)
        facts: list[PointerFact] = []
        for store in recorder.stores:
            if store.size != self.project.arch.bytes:
                continue
            # Without type metadata, every pointer-shaped word stored in writable
            # memory is a possible persistent pointer cell. This may add facts,
            # but does not discard a pointer solely because DWARF is unavailable.
            section = self.project.loader.find_section_containing(store.address)
            region = specs.get_memory_region(store.address)
            if not (
                (section is not None and section.is_writable)
                or (region is not None and region.transfer)
            ):
                continue
            cell = PointerCell(
                self.binary_objects.name_for(store.address), store.address
            )
            for value in store.values:
                if not self._is_pointer_value(value):
                    continue
                concrete = self._concretize_pointer(value)
                if concrete is None:
                    continue
                values_by_cell[cell.address].add(concrete)
                target = self._region_for(concrete, self.project.arch.bytes, specs)
                facts.append(
                    PointerFact(
                        cell,
                        concrete,
                        target.name if target is not None else f"{concrete:#x}",
                        store.instruction,
                    )
                )

        unique = {
            (fact.cell.address, fact.value, fact.instruction): fact for fact in facts
        }
        return values_by_cell, sorted(
            unique.values(),
            key=lambda fact: (fact.cell.address, fact.value, fact.instruction or 0),
        ), recorder.accesses

    def _add_mmio_backers(self, facts: dict[int, set[int]]) -> None:
        pages = {
            value & ~0xFFF
            for values in facts.values()
            for value in values
            if 0x40000000 <= value < 0x60000000 or value >= 0xE0000000
        }
        for page in sorted(pages):
            if page in self.project.loader.memory:
                continue
            self.project.loader.memory.add_backer(page, bytes(0x1000))

    def _unresolved_calls(self, root) -> list[tuple[str, int]]:
        functions = {root, *root.functions_reachable()}
        unresolved = set()
        for function in functions:
            for callsite in function.get_call_sites():
                target = function.get_call_target(callsite)
                target_function = (
                    self.cfg.kb.functions.get(target) if target is not None else None
                )
                if (
                    target is None
                    or target_function is None
                    or target_function.name == "UnresolvableCallTarget"
                ):
                    unresolved.add((function.name, callsite))
        return sorted(unresolved, key=lambda item: (item[0], item[1]))

    def _region_for(self, address: int, size: int, specs) -> MemoryObject | None:
        obj = self.binary_objects.find_object(address)
        if obj is not None:
            return obj

        if address < 0x1000:
            return MemoryObject("NULL-derived", 0, 0x1000, "invalid")

        modeled = specs.get_memory_region(address)
        if modeled is not None:
            offset = address - modeled.start
            name = modeled.name if offset == 0 else f"{modeled.name}+{offset:#x}"
            kind = "mmio" if isinstance(modeled, MMIOMemoryRegion) else "memory"
            return MemoryObject(name, address, max(1, size), kind)

        section = self.project.loader.find_section_containing(address)
        if section is not None and section.is_writable:
            return MemoryObject(
                f"{section.name}@{address:#x}",
                address,
                max(1, size),
                "section",
            )
        return MemoryObject(
            f"memory@{address:#x}", address, max(1, size), "unknown"
        )

    def _build_accesses(
        self, raw_accesses: list[_RawAccess], *, resolve_stack: bool
    ) -> list[Access]:
        accesses = set()
        for raw in raw_accesses:
            address = raw.address
            if (
                address is None
                and resolve_stack
                and raw.stack_offset is not None
                and self.stack_base is not None
            ):
                address = (self.stack_base + raw.stack_offset) & 0xFFFFFFFF

            accesses.add(
                Access(
                    raw.operation,
                    raw.instruction,
                    raw.size,
                    self._function_name(raw.instruction),
                    address=address,
                    stack_offset=raw.stack_offset,
                    unresolved=raw.unresolved,
                )
            )

        return sorted(
            accesses,
            key=lambda access: (
                access.function,
                access.instruction or 0,
                access.operation,
                access.address if access.address is not None else -1,
                access.size,
                access.unresolved or "",
            ),
        )

    def _build_isr_report(
        self, target: _ISRTarget, raw_accesses: list[_RawAccess], specs
    ) -> ISRReport:
        grouped: dict[tuple[str, int, int, str], dict[str, set]] = {}
        effects = AccessEffects()
        accesses = self._build_accesses(raw_accesses, resolve_stack=False)

        for access in accesses:
            if access.unresolved is not None:
                continue
            if access.stack_offset is not None:
                continue
            if access.address is None:
                continue
            effects = effects.union(
                specs.get_access_effects(
                    access.operation, access.address, access.size
                )
            )
            region = self._region_for(access.address, access.size, specs)
            if region is None:
                continue
            key = (region.name, region.start, region.size, region.kind)
            entry = grouped.setdefault(
                key, {"operations": set(), "addresses": set(), "functions": set()}
            )
            entry["operations"].add(access.operation)
            entry["addresses"].add(access.address)
            entry["functions"].add(access.function)

        regions = [
            RegionAccess(
                name,
                kind,
                start,
                size,
                tuple(sorted(data["operations"])),
                tuple(sorted(data["addresses"])),
                tuple(sorted(data["functions"])),
            )
            for (name, start, size, kind), data in grouped.items()
        ]
        regions.sort(key=lambda region: (region.kind, region.start, region.name))
        unresolved = [
            access for access in accesses if access.unresolved is not None
        ]
        unresolved_calls = self._unresolved_calls(target.function)
        if unresolved or unresolved_calls:
            effects = effects.union(AccessEffects())

        return ISRReport(
            target.function.name,
            target.irq,
            target.address,
            accesses,
            regions,
            unresolved,
            unresolved_calls,
            effects,
        )

    def analyze(self, specs) -> AnalysisReport:
        targets = self._isr_targets(specs)
        facts_by_cell, pointer_facts, initializer_raw_accesses = (
            self._collect_pointer_facts(specs)
        )
        self._add_mmio_backers(facts_by_cell)
        initializer = _PointerInitializer(
            self.project.arch, self.project, facts_by_cell
        )

        accesses_by_address = {}
        reports = []
        for target in targets:
            if target.address not in accesses_by_address:
                recorder = _Recorder()
                with _record_rda_memory(recorder):
                    self.project.analyses.ReachingDefinitions(
                        target.function,
                        function_handler=_PreservingFunctionHandler(self.isr_depth),
                        state_initializer=initializer,
                        track_tmps=True,
                        element_limit=30,
                        max_iterations=self.max_iterations,
                        merge_into_tops=False,
                        track_liveness=False,
                    )
                accesses_by_address[target.address] = recorder.accesses
            reports.append(
                self._build_isr_report(
                    target, accesses_by_address[target.address], specs
                )
            )

        initializer_function = self._function_by_name(self.initializer)
        return AnalysisReport(
            self.elf_path,
            self.initializer,
            pointer_facts,
            self._build_accesses(initializer_raw_accesses, resolve_stack=True),
            self._unresolved_calls(initializer_function),
            reports,
        )


def analyze_isr_memory(
    elf_path: str | Path,
    specs,
    *,
    initializer: str = "main",
) -> AnalysisReport:
    return ISRMemoryAnalyzer(elf_path, initializer=initializer).analyze(specs)
