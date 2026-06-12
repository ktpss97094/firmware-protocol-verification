from __future__ import annotations

import contextlib
import dataclasses
import logging
import xml.etree.ElementTree as ET
from bisect import bisect_right
from collections import defaultdict
from pathlib import Path
from typing import Iterable

import angr
import claripy
from angr.analyses.reaching_definitions.engine_vex import SimEngineRDVEX
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_initializer import RDAStateInitializer
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.elf.elffile import ELFFile

logger = logging.getLogger(__name__)


@dataclasses.dataclass(frozen=True)
class MemoryObject:
    name: str
    start: int
    size: int
    kind: str
    frame_offset: int | None = None

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


@dataclasses.dataclass(frozen=True)
class ISRMemoryRegion:
    name: str
    kind: str
    start: int
    size: int

    @property
    def end(self) -> int:
        return self.start + self.size


class ISRMemoryRegions:
    def __init__(self, regions: Iterable[RegionAccess]):
        unique = {
            ISRMemoryRegion(region.name, region.kind, region.start, region.size)
            for region in regions
            if region.size > 0
        }
        self.regions = tuple(
            sorted(unique, key=lambda region: (region.start, region.end, region.name))
        )

        merged = []
        for region in self.regions:
            if merged and region.start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], region.end))
            else:
                merged.append((region.start, region.end))
        self._starts = tuple(start for start, _ in merged)
        self._ends = tuple(end for _, end in merged)

    @classmethod
    def from_report(cls, report: AnalysisReport) -> ISRMemoryRegions:
        return cls(
            region
            for isr_report in report.isrs
            for region in isr_report.regions
        )

    def __contains__(self, address: int) -> bool:
        index = bisect_right(self._starts, address) - 1
        return index >= 0 and address < self._ends[index]

    def __iter__(self):
        return iter(self.regions)

    def __len__(self) -> int:
        return len(self.regions)


@dataclasses.dataclass
class ISRReport:
    isr: str
    irq: int
    address: int
    regions: list[RegionAccess]
    unresolved_accesses: list[Access]
    unresolved_calls: list[tuple[str, int]]

    @property
    def complete(self) -> bool:
        return not self.unresolved_accesses and not self.unresolved_calls


@dataclasses.dataclass
class AnalysisReport:
    elf: Path
    initializer: str
    pointer_facts: list[PointerFact]
    isrs: list[ISRReport]

    @property
    def complete(self) -> bool:
        return all(report.complete for report in self.isrs)


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


class _DwarfIndex:
    def __init__(self, elf_path: Path, stack_base: int | None):
        self.objects: list[MemoryObject] = []
        self.stack_objects: list[MemoryObject] = []
        self.pointer_cells: dict[int, PointerCell] = {}
        self._load(elf_path, stack_base)

    @staticmethod
    def _name(die) -> str | None:
        attr = die.attributes.get("DW_AT_name")
        return attr.value.decode(errors="replace") if attr is not None else None

    @staticmethod
    def _type_die(die):
        if "DW_AT_type" not in die.attributes:
            return None
        return die.get_DIE_from_attribute("DW_AT_type")

    def _unwrap_type(self, die):
        seen = set()
        while die is not None and die.offset not in seen:
            seen.add(die.offset)
            if die.tag not in {
                "DW_TAG_const_type",
                "DW_TAG_typedef",
                "DW_TAG_volatile_type",
                "DW_TAG_restrict_type",
                "DW_TAG_atomic_type",
            }:
                return die
            die = self._type_die(die)
        return die

    def _type_size(self, die) -> int | None:
        die = self._unwrap_type(die)
        if die is None:
            return None
        byte_size = die.attributes.get("DW_AT_byte_size")
        if byte_size is not None:
            return int(byte_size.value)
        if die.tag == "DW_TAG_pointer_type":
            return 4
        if die.tag == "DW_TAG_array_type":
            elem_size = self._type_size(self._type_die(die))
            if elem_size is None:
                return None
            count = 1
            for child in die.iter_children():
                if child.tag != "DW_TAG_subrange_type":
                    continue
                if "DW_AT_count" in child.attributes:
                    count *= int(child.attributes["DW_AT_count"].value)
                elif "DW_AT_upper_bound" in child.attributes:
                    count *= int(child.attributes["DW_AT_upper_bound"].value) + 1
                else:
                    return None
            return elem_size * count
        return None

    def _pointer_members(
        self, die, base_address: int, prefix: str
    ) -> Iterable[PointerCell]:
        die = self._unwrap_type(die)
        if die is None:
            return
        if die.tag == "DW_TAG_pointer_type":
            yield PointerCell(prefix, base_address)
            return
        if die.tag not in {"DW_TAG_structure_type", "DW_TAG_union_type"}:
            return
        for child in die.iter_children():
            if child.tag != "DW_TAG_member":
                continue
            location = child.attributes.get("DW_AT_data_member_location")
            if location is None or not isinstance(location.value, int):
                continue
            member_name = self._name(child) or f"member_{location.value:x}"
            member_type = self._type_die(child)
            yield from self._pointer_members(
                member_type,
                base_address + int(location.value),
                f"{prefix}.{member_name}",
            )

    def _load(self, elf_path: Path, stack_base: int | None) -> None:
        with elf_path.open("rb") as stream:
            elf = ELFFile(stream)
            if not elf.has_dwarf_info():
                return
            dwarf = elf.get_dwarf_info()
            expr_parser = DWARFExprParser(dwarf.structs)

            def visit(die, function_name: str | None = None) -> None:
                if die.tag == "DW_TAG_subprogram":
                    function_name = self._name(die)
                if die.tag == "DW_TAG_variable":
                    self._load_variable(die, function_name, stack_base, expr_parser)
                for child in die.iter_children():
                    visit(child, function_name)

            for cu in dwarf.iter_CUs():
                visit(cu.get_top_DIE())

        self.objects.sort(key=lambda obj: (obj.start, -obj.size, obj.name))
        self.stack_objects.sort(key=lambda obj: (obj.start, -obj.size, obj.name))

    def _load_variable(
        self,
        die,
        function_name: str | None,
        stack_base: int | None,
        expr_parser: DWARFExprParser,
    ) -> None:
        name = self._name(die)
        location = die.attributes.get("DW_AT_location")
        type_die = self._type_die(die)
        size = self._type_size(type_die)
        if name is None or location is None or size is None:
            return
        if not isinstance(location.value, list):
            return
        try:
            ops = expr_parser.parse_expr(location.value)
        except Exception:
            return
        if len(ops) != 1:
            return

        op = ops[0]
        if op.op_name == "DW_OP_addr":
            address = int(op.args[0])
            self.objects.append(MemoryObject(name, address, size, "global"))
            for cell in self._pointer_members(type_die, address, name):
                self.pointer_cells[cell.address] = cell
        elif (
            op.op_name == "DW_OP_fbreg"
            and function_name is not None
            and stack_base is not None
        ):
            offset = int(op.args[0])
            self.stack_objects.append(
                MemoryObject(
                    f"{function_name}::{name}",
                    (stack_base + offset) & 0xFFFFFFFF,
                    size,
                    "escaped-stack",
                    frame_offset=offset,
                )
            )

    def find_object(self, address: int) -> MemoryObject | None:
        for obj in self.stack_objects:
            if obj.start <= address < obj.end:
                return obj
        matches = [
            obj for obj in self.objects if obj.start <= address < obj.end and obj.size
        ]
        return min(matches, key=lambda obj: obj.size) if matches else None

    def target_name(self, address: int) -> str:
        obj = self.find_object(address)
        return obj.name if obj is not None else f"{address:#x}"


class _SVDIndex:
    def __init__(self, svd_path: Path | None):
        self.registers: dict[int, tuple[str, int]] = {}
        self.peripherals: list[MemoryObject] = []
        if svd_path is not None:
            self._load(svd_path)

    def _load(self, svd_path: Path) -> None:
        root = ET.parse(svd_path).getroot()
        for peripheral in root.findall("./peripherals/peripheral"):
            name_node = peripheral.find("name")
            base_node = peripheral.find("baseAddress")
            if name_node is None or base_node is None:
                continue
            name = name_node.text or "peripheral"
            base = int(base_node.text or "0", 0)
            block = peripheral.find("addressBlock/size")
            block_size = (
                int(block.text, 0) if block is not None and block.text else 0x400
            )
            self.peripherals.append(MemoryObject(name, base, block_size, "mmio"))
            for register in peripheral.findall("registers/register"):
                reg_name = register.find("name")
                reg_offset = register.find("addressOffset")
                reg_size = register.find("size")
                if reg_name is None or reg_offset is None:
                    continue
                address = base + int(reg_offset.text or "0", 0)
                size_bits = (
                    int(reg_size.text, 0)
                    if reg_size is not None and reg_size.text
                    else 32
                )
                self.registers[address] = (
                    f"{name}.{reg_name.text or 'register'}",
                    max(1, size_bits // 8),
                )

    def describe(self, address: int) -> MemoryObject | None:
        if address in self.registers:
            name, size = self.registers[address]
            return MemoryObject(name, address, size, "mmio")
        for peripheral in self.peripherals:
            if peripheral.start <= address < peripheral.end:
                return peripheral
        if 0x40000000 <= address < 0x60000000 or 0xE0000000 <= address:
            return MemoryObject(f"MMIO@{address:#x}", address, 4, "mmio")
        return None

    def pointer_target(self, address: int) -> MemoryObject | None:
        for peripheral in self.peripherals:
            if peripheral.start == address:
                return peripheral
        return self.describe(address)


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
        svd_path: str | Path | None = None,
        initializer: str = "main",
        init_depth: int = 4,
        isr_depth: int = 8,
        max_iterations: int = 8,
    ):
        self.elf_path = Path(elf_path).resolve()
        self.svd_path = Path(svd_path).resolve() if svd_path is not None else None
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
        self.dwarf = _DwarfIndex(self.elf_path, self.stack_base)
        self.svd = _SVDIndex(self.svd_path)

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

    def _collect_pointer_facts(self) -> tuple[dict[int, set[int]], list[PointerFact]]:
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
            cell = self.dwarf.pointer_cells.get(store.address)
            if cell is None:
                continue
            for value in store.values:
                if not self._is_pointer_value(value):
                    continue
                concrete = self._concretize_pointer(value)
                if concrete is None:
                    continue
                values_by_cell[cell.address].add(concrete)
                target = self.svd.pointer_target(concrete)
                facts.append(
                    PointerFact(
                        cell,
                        concrete,
                        (
                            target.name
                            if target is not None
                            else self.dwarf.target_name(concrete)
                        ),
                        store.instruction,
                    )
                )

        unique = {
            (fact.cell.address, fact.value, fact.instruction): fact for fact in facts
        }
        return values_by_cell, sorted(
            unique.values(),
            key=lambda fact: (fact.cell.address, fact.value, fact.instruction or 0),
        )

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

    def _region_for(self, address: int) -> MemoryObject | None:
        mmio = self.svd.describe(address)
        if mmio is not None:
            return mmio
        obj = self.dwarf.find_object(address)
        if obj is not None:
            return obj
        section = self.project.loader.find_section_containing(address)
        if section is not None and section.is_writable:
            return MemoryObject(section.name, section.vaddr, section.memsize, "section")
        if address < 0x1000:
            return MemoryObject("NULL-derived", 0, 0x1000, "invalid")
        return None

    def _build_isr_report(
        self, target: _ISRTarget, raw_accesses: list[_RawAccess]
    ) -> ISRReport:
        grouped: dict[tuple[str, int, int, str], dict[str, set]] = {}
        unresolved = set()

        for raw in raw_accesses:
            function = self._function_name(raw.instruction)
            if raw.unresolved is not None:
                unresolved.add(
                    Access(
                        raw.operation,
                        raw.instruction,
                        raw.size,
                        function,
                        unresolved=raw.unresolved,
                    )
                )
                continue
            if raw.stack_offset is not None:
                continue
            if raw.address is None:
                continue
            region = self._region_for(raw.address)
            if region is None:
                continue
            key = (region.name, region.start, region.size, region.kind)
            entry = grouped.setdefault(
                key, {"operations": set(), "addresses": set(), "functions": set()}
            )
            entry["operations"].add(raw.operation)
            entry["addresses"].add(raw.address)
            entry["functions"].add(function)

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
        return ISRReport(
            target.function.name,
            target.irq,
            target.address,
            regions,
            sorted(
                unresolved,
                key=lambda access: (
                    access.function,
                    access.instruction or 0,
                    access.operation,
                    access.size,
                ),
            ),
            self._unresolved_calls(target.function),
        )

    def analyze(self, specs) -> AnalysisReport:
        targets = self._isr_targets(specs)
        facts_by_cell, pointer_facts = self._collect_pointer_facts()
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
                self._build_isr_report(target, accesses_by_address[target.address])
            )

        return AnalysisReport(self.elf_path, self.initializer, pointer_facts, reports)


def analyze_isr_memory(
    elf_path: str | Path,
    specs,
    *,
    svd_path: str | Path | None = None,
    initializer: str = "main",
) -> AnalysisReport:
    return ISRMemoryAnalyzer(
        elf_path, svd_path=svd_path, initializer=initializer
    ).analyze(specs)
