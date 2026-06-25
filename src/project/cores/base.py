import logging
from abc import ABC, abstractmethod
from bisect import bisect_right
from collections import defaultdict
from functools import cache, partial

import angr
import claripy
import pyvex
from angr.errors import SimMergeError
from angr.state_plugins.plugin import SimStatePlugin

from project.analyses.isr_memory import ISRTarget, analyze_isr_memory
from project.types import AccessEffects, BPConfig, MMIOMemoryRegion

logging.getLogger("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX").setLevel(
    logging.CRITICAL
)
logging.getLogger("angr.analyses.xrefs.SimEngineXRefsVEX").setLevel(logging.CRITICAL)
logging.getLogger(
    "angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX"
).setLevel(logging.CRITICAL)

logger = logging.getLogger(__name__)


class _MemoryAccessRegions:
    def __init__(self, regions):
        merged = []
        for start, size in sorted(regions):
            end = start + max(1, size)
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))

        self._starts = tuple(start for start, _ in merged)
        self._ends = tuple(end for _, end in merged)

    def overlaps(self, start, size):
        end = start + max(1, size)
        index = bisect_right(self._starts, start) - 1
        if index >= 0 and self._ends[index] > start:
            return True

        next_index = index + 1
        return next_index < len(self._starts) and self._starts[next_index] < end


class AsynchronousEventGlobals(SimStatePlugin):
    def __init__(
        self,
        before_check_handlers=None,
        after_check_handlers=None,
        prev_after_check_handlers=None,
    ):
        super().__init__()

        self.before_check_handlers = (
            set() if before_check_handlers is None else before_check_handlers
        )
        self.after_check_handlers = (
            set() if after_check_handlers is None else after_check_handlers
        )
        self.prev_after_check_handlers = (
            set() if prev_after_check_handlers is None else prev_after_check_handlers
        )

    def copy(self, memo):
        o = super().copy(memo)

        o.before_check_handlers = set()
        o.after_check_handlers = set()
        o.prev_after_check_handlers = set()

        return o

    def merge_key(self):
        return (
            frozenset(self.before_check_handlers),
            frozenset(self.after_check_handlers),
            frozenset(self.prev_after_check_handlers),
        )

    def merge(self, others, merge_conditions, common_ancestor=None):
        del common_ancestor

        if any(
            self.before_check_handlers != other.before_check_handlers
            or self.after_check_handlers != other.after_check_handlers
            or self.prev_after_check_handlers != other.prev_after_check_handlers
            for other in others
        ):
            raise SimMergeError(
                "Cannot merge Asynchronous Event globals (before_check_handlers or after_check_handlers or prev_after_check_handlers)"
            )

        return False


class BaseCPU(ABC):
    @abstractmethod
    def normalize_address(self, addr):
        return addr

    def get_current_return_address(self, state):
        if state.arch.call_pushes_ret:
            return state.mem[state.regs.sp].uint.resolved

        if state.arch.lr_offset is not None:
            return state.registers.load(
                state.arch.lr_offset,
                state.arch.bytes,
                endness=state.arch.register_endness,
            )

        raise NotImplementedError("No return address can be retrieved")

    @staticmethod
    def _add_unresolved_instruction(unresolved_inst_addrs, instruction, description):
        if instruction is None:
            raise ValueError(
                f"Cannot create a checkpoint for {description}: "
                "the analyzer did not report an instruction address"
            )
        unresolved_inst_addrs.add(instruction)

    @staticmethod
    def _modeled_irq_numbers(specs) -> tuple[int, ...]:
        irq_numbers = set()
        for region in specs.get_MMIOMemoryRegions():
            for irq in getattr(region, "IRQ_NUMBERS", ()) or ():
                irq = int(irq)
                if irq < 0:
                    raise ValueError(
                        f"Invalid IRQ number {irq} on MMIO region {region.name}"
                    )
                irq_numbers.add(irq)
        return tuple(sorted(irq_numbers))

    @staticmethod
    def _concrete_state_value(state, value, description):
        if isinstance(value, int):
            return value
        if not state.solver.unique(value):
            raise ValueError(f"Cannot resolve concrete value for {description}")
        return state.solver.eval(value)

    def _compute_isr_target(self, state, irq: int) -> ISRTarget:
        raise NotImplementedError(
            f"{type(self).__name__} does not provide ISR target discovery"
        )

    def get_isr_targets(self, state, specs) -> tuple[ISRTarget, ...]:
        return tuple(
            self._compute_isr_target(state, irq)
            for irq in self._modeled_irq_numbers(specs)
        )

    def get_isr_memory_report(self, proj, state, specs):
        return self._get_isr_memory_report(
            proj, specs, self.get_isr_targets(state, specs)
        )

    @cache
    def _get_isr_memory_report(self, proj, specs, isr_targets):
        report = analyze_isr_memory(
            proj.filename, specs, isr_targets=tuple(isr_targets)
        )
        for access in report.initializer_accesses:
            if access.unresolved is None:
                continue
            logger.warning(
                "Adding conservative checkpoint for unresolved main memory access | "
                "function: %s | instruction: %#x | operation: %s | reason: %s",
                access.function,
                access.instruction or 0,
                access.operation,
                access.unresolved,
            )
        for function, callsite in report.initializer_unresolved_calls:
            logger.warning(
                "Adding conservative checkpoint for unresolved main call | function: %s | callsite: %#x",
                function,
                callsite,
            )
        for isr in report.isrs:
            for access in isr.unresolved_accesses:
                logger.warning(
                    "Adding conservative checkpoint for unresolved ISR memory access | ISR: %s | "
                    "function: %s | instruction: %#x | operation: %s | reason: %s",
                    isr.isr,
                    access.function,
                    access.instruction or 0,
                    access.operation,
                    access.unresolved,
                )
            for function, callsite in isr.unresolved_calls:
                logger.warning(
                    "Adding conservative checkpoint for unresolved ISR call | ISR: %s | "
                    "function: %s | callsite: %#x",
                    isr.isr,
                    function,
                    callsite,
                )
        return report

    def _get_shared_access_regions_and_unresolved(self, proj, state, specs):
        report = self.get_isr_memory_report(proj, state, specs)
        flow_accesses = [
            report.initializer_accesses,
            *(isr.accesses for isr in report.isrs),
        ]

        unresolved_inst_addrs = set()
        for function, callsite in report.initializer_unresolved_calls:
            self._add_unresolved_instruction(
                unresolved_inst_addrs, callsite, f"unresolved call in {function}"
            )
        for isr in report.isrs:
            for function, callsite in isr.unresolved_calls:
                self._add_unresolved_instruction(
                    unresolved_inst_addrs, callsite, f"unresolved call in {function}"
                )

        flow_entries = []
        flow_effects = []
        for accesses in flow_accesses:
            entries = []
            effects = AccessEffects()
            for access in accesses:
                if access.address is None or access.unresolved is not None:
                    self._add_unresolved_instruction(
                        unresolved_inst_addrs,
                        access.instruction,
                        f"unresolved {access.operation} in {access.function}",
                    )
                    continue
                access_effects = specs.get_access_effects(
                    access.operation, access.address, access.size
                )
                entries.append((access, access_effects))
                effects = effects.union(access_effects)
            flow_entries.append(entries)
            flow_effects.append(effects)

        shared = {"read": [], "write": []}
        for flow_index, entries in enumerate(flow_entries):
            other_effects = AccessEffects()
            for other_index, effects in enumerate(flow_effects):
                if other_index != flow_index:
                    other_effects = other_effects.union(effects)

            for access, effects in entries:
                if effects.conflicts_with(other_effects):
                    shared[access.operation].append((access.address, access.size))

        return {
            operation: _MemoryAccessRegions(regions)
            for operation, regions in shared.items()
        }, unresolved_inst_addrs

    def get_static_interrupt_checkpoints(self, proj, state, cfg, specs):
        # 1. shared variables (regions) R/W 之前
        shared_regions, unresolved_inst_addrs = (
            self._get_shared_access_regions_and_unresolved(proj, state, specs)
        )
        ckpts = {
            BPConfig(
                "mem_read",
                when=angr.BP_BEFORE,
                condition=partial(
                    self._inspect_access_in_regions,
                    operation="read",
                    regions=shared_regions["read"],
                ),
            ),
            BPConfig(
                "mem_write",
                when=angr.BP_BEFORE,
                condition=partial(
                    self._inspect_access_in_regions,
                    operation="write",
                    regions=shared_regions["write"],
                ),
            ),
        }
        for inst_addr in unresolved_inst_addrs:
            ckpts.add(
                BPConfig("instruction", when=angr.BP_BEFORE, instruction=inst_addr)
            )

        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = proj.factory.block(node.addr, size=node.size)

            for stmt_idx, stmt in enumerate(block.vex.statements):
                # 1. Memory Bus Event (Memory Barriers, Synchronization events) 之前
                # e.g., ARM 的 DSB, DMB, ISB
                if isinstance(stmt, pyvex.stmt.MBE):
                    try:
                        ins_addr = block.instruction_addrs[
                            self._stmt_idx_to_inst_idx(block.vex, stmt_idx)
                        ]
                        ckpts.add(
                            BPConfig(
                                "instruction", when=angr.BP_BEFORE, instruction=ins_addr
                            )
                        )
                    except IndexError:
                        pass
                # 2. Store-Conditional 之前
                # e.g., ARM 的 STREX
                elif isinstance(stmt, pyvex.stmt.LLSC):
                    if hasattr(stmt, "storedata") and stmt.storedata != 0:
                        try:
                            ins_addr = block.instruction_addrs[
                                self._stmt_idx_to_inst_idx(block.vex, stmt_idx)
                            ]
                            ckpts.add(
                                BPConfig(
                                    "instruction",
                                    when=angr.BP_BEFORE,
                                    instruction=ins_addr,
                                )
                            )
                        except IndexError:
                            pass

        # 3. End Addresses 之前
        ckpts.update(self.get_end_addrs_ckpts(specs.END_ADDRS))

        return ckpts

    @staticmethod
    def _concrete_inspect_value(state, value):
        if value is None:
            return None
        if isinstance(value, int):
            return value
        if not state.solver.unique(value):
            return None
        return state.solver.eval(value)

    def _inspect_access_in_regions(self, state, operation, regions):
        if operation == "read":
            address = state.inspect.mem_read_address
            size = state.inspect.mem_read_length
        else:
            address = state.inspect.mem_write_address
            size = state.inspect.mem_write_length

        address = self._concrete_inspect_value(state, address)
        size = self._concrete_inspect_value(state, size)
        if address is None or size is None:
            return False

        return regions.overlaps(address, size)

    @abstractmethod
    def _compute_dma_synchronize_instruction_checkpoints(self):
        pass

    def get_end_addrs_ckpts(self, end_addrs):
        ckpts = set()

        for end_addr in end_addrs:
            ckpts.add(
                BPConfig("instruction", when=angr.BP_BEFORE, instruction=end_addr)
            )

        return ckpts

    @cache
    def get_dma_synchronize_instruction_checkpoints(self):
        return self._compute_dma_synchronize_instruction_checkpoints()

    def _stmt_idx_to_inst_idx(self, vex_block, stmt_idx):
        """
        將 VEX 的 statement index 轉回對應的 instruction index
        """

        curr_inst = 0
        for i in range(stmt_idx + 1):
            if isinstance(vex_block.statements[i], pyvex.stmt.IMark):
                curr_inst += 1
        return curr_inst - 1 if curr_inst > 0 else 0

    class AsynchronousEventManager(angr.ExplorationTechnique):
        def __init__(self, cpu, end_addrs):
            super().__init__()
            self.cpu = cpu
            self.end_addrs = end_addrs

            AsynchronousEventGlobals.register_default("asynevt_globals")

        def _merge(self, state, trig_list):
            """
            需要維持 trigger condition 的順序
            """

            output = []

            for trig_cond, handler, handler_kwargs in trig_list:
                matched = False

                for group in output:
                    rep_cond = group[0]

                    if state.solver.is_true(trig_cond == rep_cond):
                        if any(
                            grouped_handler is handler
                            for grouped_handler, _ in group[1]
                        ):
                            continue
                        group[1].append((handler, handler_kwargs))
                        matched = True
                        break

                if not matched:
                    output.append((trig_cond, [(handler, handler_kwargs)]))

            return output

        @staticmethod
        def _and_conditions(conditions):
            conditions = list(conditions)
            if not conditions:
                return claripy.true()
            if len(conditions) == 1:
                return conditions[0]
            return claripy.And(*conditions)

        @staticmethod
        def _handler_sort_key(handler):
            cls = handler.__class__
            return (cls.__qualname__, cls.__module__, id(handler))

        def _satisfiable(self, state, condition):
            return condition.is_true() or state.solver.satisfiable(
                extra_constraints=[condition]
            )

        def _handler_options(self, state, handler):
            options = []
            neg_prev_conds = []
            no_event_constrains_state = getattr(
                handler, "NO_EVENT_CONSTRAINS_STATE", True
            )

            for trig_cond, handler_kwargs in handler.get_eligible_events(state):
                option_cond = self._and_conditions((*neg_prev_conds, trig_cond))
                if self._satisfiable(state, option_cond):
                    options.append((option_cond, [(handler, handler_kwargs)]))

                neg_prev_conds.append(claripy.Not(trig_cond))
                none_cond = self._and_conditions(neg_prev_conds)
                if no_event_constrains_state and not self._satisfiable(
                    state, none_cond
                ):
                    return options, None

            if not no_event_constrains_state:
                return options, claripy.true()

            none_cond = self._and_conditions(neg_prev_conds)
            if self._satisfiable(state, none_cond):
                return options, none_cond
            return options, None

        def _compose_handler_options(self, state, handlers):
            groups = [(claripy.true(), [])]
            no_event_cond = claripy.true()

            for handler in sorted(handlers, key=self._handler_sort_key):
                options, handler_no_event_cond = self._handler_options(state, handler)
                next_groups = []

                handler_choices = list(options)
                if handler_no_event_cond is not None:
                    handler_choices.append((handler_no_event_cond, []))
                    no_event_cond = claripy.And(no_event_cond, handler_no_event_cond)
                else:
                    no_event_cond = claripy.false()

                for group_cond, group_events in groups:
                    for option_cond, option_events in handler_choices:
                        combined_cond = claripy.And(group_cond, option_cond)
                        if self._satisfiable(state, combined_cond):
                            next_groups.append(
                                (combined_cond, group_events + option_events)
                            )

                groups = next_groups
                if not groups:
                    break

            event_groups = [
                (condition, events) for condition, events in groups if events
            ]
            normal_cond = no_event_cond if self._satisfiable(state, no_event_cond) else None
            return event_groups, normal_cond

        def _process_event(self, check_items):
            output = []

            while check_items:
                check_state, handlers = check_items.pop(0)

                event_groups, normal_cond = self._compose_handler_options(
                    check_state, handlers
                )

                for trig_cond, handler_info_list in event_groups:
                    new_state = check_state.copy()
                    new_state.add_constraints(trig_cond)

                    for handler, handler_kwargs in handler_info_list:
                        handler.trigger_event(new_state, **handler_kwargs)

                    if new_state.addr == check_state.addr:
                        # FIXME: 不確定如果執行 event 中間又有 checkpoint，有沒有必要檢查。目前是全部先忽略
                        new_state.asynevt_globals.before_check_handlers = set()
                        new_state.asynevt_globals.after_check_handlers = set()
                        check_items.append((new_state, handlers))
                    else:
                        output.append(new_state)

                # normal state
                if normal_cond is not None:
                    if normal_cond.is_true():
                        output.append(check_state)
                    else:
                        normal_state = check_state.copy()
                        normal_state.add_constraints(normal_cond)
                        output.append(normal_state)

            return output

        def step_state(self, simgr, state, **kwargs):
            """
            回傳值的 key None 表示 active
            """

            merged_results = defaultdict(list)

            succ_stashes = simgr.step_state(state, **kwargs)
            pruning = True
            is_terminal = state.addr in self.end_addrs
            for before_active_state in self._process_event(
                [
                    (
                        state,
                        set().union(
                            *(
                                succ_active_state.asynevt_globals.before_check_handlers
                                for succ_active_state in succ_stashes.get(None, [])
                            )
                        ),
                    )
                ]
            ):
                if before_active_state is state:
                    pruning = False
                    if is_terminal:
                        merged_results["found"].append(state)
                else:
                    merged_results[None].append(before_active_state)
            if pruning or is_terminal:
                # A terminal address is also an event checkpoint. Keep event
                # successors, but never execute the terminal marker normally.
                return merged_results

            for k, v in succ_stashes.items():
                if k is not None:
                    merged_results[k].extend(v)
            after_check_items = []
            for succ_active_state in succ_stashes.get(None, []):
                after_check_items.append(
                    (
                        succ_active_state,
                        succ_active_state.asynevt_globals.after_check_handlers,
                    )
                )
                succ_active_state.asynevt_globals.prev_after_check_handlers = (
                    succ_active_state.asynevt_globals.after_check_handlers
                )
            merged_results[None].extend(self._process_event(after_check_items))

            return merged_results


class BaseDMA(ABC, MMIOMemoryRegion):
    pass
