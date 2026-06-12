import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from functools import cache

import angr
import claripy
import pyvex

from project.analyses.isr_memory import ISRMemoryRegions, analyze_isr_memory
from project.types import BPConfig, MMIOMemoryRegion

logging.getLogger("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX").setLevel(
    logging.CRITICAL
)
logging.getLogger("angr.analyses.xrefs.SimEngineXRefsVEX").setLevel(logging.CRITICAL)
logging.getLogger(
    "angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX"
).setLevel(logging.CRITICAL)


class BaseCPU(ABC):
    @abstractmethod
    def normalize_address(self, addr):
        return addr

    @cache
    def get_isr_shared_regions(self, proj, specs, svd_path=None) -> ISRMemoryRegions:
        report = analyze_isr_memory(proj.filename, specs, svd_path=svd_path)
        return ISRMemoryRegions.from_report(report)

    @cache
    def get_static_interrupt_checkpoints(self, proj, cfg, specs):
        ckpts = set()

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

    class ForkEventManager(angr.ExplorationTechnique):
        def __init__(self, cpu, end_addrs):
            super().__init__()
            self.cpu = cpu
            self.end_addrs = end_addrs

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
                        group[1].append((handler, handler_kwargs))
                        matched = True
                        break

                if not matched:
                    output.append((trig_cond, [(handler, handler_kwargs)]))

            return output

        def _process_event(self, check_items):
            output = []

            while check_items:
                check_state, handlers = check_items.pop(0)

                trig_list = []
                for handler in handlers:
                    for trig_cond, handler_kwargs in handler.get_eligible_events(
                        check_state
                    ):
                        trig_list.append((trig_cond, handler, handler_kwargs))
                trig_list = self._merge(check_state, trig_list)

                neg_prev_conds = []
                pruning = False

                for trig_cond, handler_info_list in trig_list:
                    if (
                        not trig_cond.is_true()  # pruning，如果是 concrete true 就不用再算 satisfiable
                        and not check_state.solver.satisfiable(
                            extra_constraints=neg_prev_conds + [trig_cond]
                        )  # 因為加了 neg_prev_conds constraints，所以需要檢查
                    ):
                        continue

                    new_state = check_state.copy()
                    if neg_prev_conds:
                        new_state.add_constraints(*neg_prev_conds)
                    new_state.add_constraints(trig_cond)

                    for handler, handler_kwargs in handler_info_list:
                        handler.trigger_event(new_state, **handler_kwargs)

                    if new_state.addr == check_state.addr:
                        # FIXME: 不確定如果執行 event 中間又有 checkpoint，有沒有必要檢查。目前是全部先忽略
                        new_state.custom_globals.before_check_handlers = set()
                        new_state.custom_globals.after_check_handlers = set()
                        check_items.append((new_state, handlers))
                    else:
                        output.append(new_state)

                    neg_prev_conds.append(claripy.Not(trig_cond))
                    if not check_state.solver.satisfiable(
                        extra_constraints=neg_prev_conds
                    ):  # pruning，如果這個 trigger condition 到目前是一定會被觸發，則代表到目前 fork 出的所有 state 已滿足所有可能的情況。所以同等於計算是否不可能有滿足 neg_prev_conds 的情況
                        pruning = True
                        break

                # normal state
                if not pruning:
                    output.append(check_state)

            return output

        def step_state(self, simgr, state, **kwargs):
            """
            回傳值的 key None 表示 active
            """

            merged_results = defaultdict(list)

            succ_stashes = simgr.step_state(state, **kwargs)
            pruning = True
            found_target = False
            for before_active_state in self._process_event(
                [
                    (
                        state,
                        set().union(
                            *(
                                succ_active_state.custom_globals.before_check_handlers
                                for succ_active_state in succ_stashes.get(None, [])
                            )
                        ),
                    )
                ]
            ):
                if before_active_state is state:
                    pruning = False
                    if state.addr in self.end_addrs:
                        merged_results["found"].append(state)
                        found_target = True
                else:
                    merged_results[None].append(before_active_state)
            if (
                pruning or found_target
            ):  # found_target: 理論上不能在 end address 設 BP_AFTER，這裡直接截斷
                return merged_results

            for k, v in succ_stashes.items():
                if k is not None:
                    merged_results[k].extend(v)
            after_check_items = []
            for succ_active_state in succ_stashes.get(None, []):
                after_check_items.append(
                    (
                        succ_active_state,
                        succ_active_state.custom_globals.after_check_handlers,
                    )
                )
                succ_active_state.custom_globals.prev_after_check_handlers = (
                    succ_active_state.custom_globals.after_check_handlers
                )
            merged_results[None].extend(self._process_event(after_check_items))

            return merged_results


class BaseDMA(ABC, MMIOMemoryRegion):
    pass
