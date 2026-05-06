import logging
from abc import ABC, abstractmethod
from collections import defaultdict
from functools import cache

import angr
import angr.analyses.variable_recovery.engine_vex as engine_vex
import claripy
import pyvex

logging.getLogger("angr.analyses.variable_recovery.engine_vex.SimEngineVRVEX").setLevel(
    logging.CRITICAL
)
logging.getLogger("angr.analyses.xrefs.SimEngineXRefsVEX").setLevel(logging.CRITICAL)
logging.getLogger(
    "angr.analyses.propagator.engine_vex.SimEnginePropagatorVEX"
).setLevel(logging.CRITICAL)


"""
修補 angr/analyses/variable_recovery/engine_vex.py 中 SimEngineVRVEX 的 _handle_stmt_LoadG(), _handle_stmt_StoreG 的 bug，把 AST(1) 跟 True 比較會是 False，
而忽略部分 global variable R/W instruction
"""
original_LoadG = engine_vex.SimEngineVRVEX._handle_stmt_LoadG
original_StoreG = engine_vex.SimEngineVRVEX._handle_stmt_StoreG


def _is_guard_true(guard_expr):
    if hasattr(guard_expr, "data"):
        data = guard_expr.data
        if hasattr(data, "concrete") and data.concrete:
            if hasattr(data, "args") and len(data.args) > 0 and data.args[0] == 0:
                return False
            return True
        else:
            # VariableRecoveryFast 只有當該指令的 guard 是百分之百 True 時才會視為 global variable R/W，如果 guard 算出來是 TOP (未知) 等就不會。這裡為了要最大限度找出所有 checkpoint，所以未知的情況也回傳 True
            return True
    elif guard_expr is False:
        return False
    return True


def _patched_handle_stmt_LoadG(self, stmt):
    guard_expr = getattr(self, "_expr", lambda x: None)(stmt.guard)
    if _is_guard_true(guard_expr):
        addr = self._expr_bv(stmt.addr)
        if addr is not None and getattr(addr.data, "concrete", False):
            try:
                self.tmps[stmt.dst] = self._load(
                    addr, getattr(self, "tyenv").sizeof(stmt.dst) // 8
                )
                return
            except Exception:
                pass
    return original_LoadG(self, stmt)


def _patched_handle_stmt_StoreG(self, stmt):
    guard_expr = getattr(self, "_expr", lambda x: None)(stmt.guard)
    if _is_guard_true(guard_expr):
        addr = self._expr_bv(stmt.addr)
        if addr is not None and getattr(addr.data, "concrete", False):
            size = stmt.data.result_size(getattr(self, "tyenv")) // 8
            data = self._expr(stmt.data)
            try:
                self._store(addr, data, size, atom=stmt)
                return
            except Exception:
                pass
    return original_StoreG(self, stmt)


engine_vex.SimEngineVRVEX._handle_stmt_LoadG = _patched_handle_stmt_LoadG
engine_vex.SimEngineVRVEX._handle_stmt_StoreG = _patched_handle_stmt_StoreG


class CPU(ABC):
    @abstractmethod
    def normalize_address(self, addr):
        return addr

    @cache
    def get_static_interrupt_checkpoints(self, proj, cfg, specs):
        ckpts = defaultdict(set)

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
                        ckpts[angr.BP_BEFORE].add(ins_addr)
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
                            ckpts[angr.BP_BEFORE].add(ins_addr)
                        except IndexError:
                            pass

        # 3. End Addresses 之前
        for end_addr in specs.END_ADDRS:
            ckpts[angr.BP_BEFORE].add(end_addr)

        return ckpts

    @abstractmethod
    def _compute_dma_synchronize_instruction_checkpoints(self):
        pass

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

        def step_state(self, simgr, state, **kwargs):
            """
            回傳值的 key None 表示 active
            """

            merged_results = defaultdict(list)

            succ_stashes = simgr.step_state(state, **kwargs)
            for k, v in succ_stashes.items():
                if k is not None:
                    merged_results[k].extend(v)

            check_items = []
            before_state_appended = False
            for active_state in succ_stashes.get(None, []):
                if (
                    not before_state_appended
                    and active_state.custom_globals.before_check_handlers
                ):
                    check_items.append(
                        (state, active_state.custom_globals.before_check_handlers)
                    )
                    before_state_appended = True

                if active_state.custom_globals.after_check_handlers:
                    check_items.append(
                        (active_state, active_state.custom_globals.after_check_handlers)
                    )
            if not check_items:
                if state.addr in self.end_addrs:
                    return {"found": [state]}
                merged_results[None].extend(succ_stashes.get(None, []))
                return merged_results

            # 清除標籤
            for active_state in succ_stashes.get(None, []):
                active_state.custom_globals.before_check_handlers = set()
                active_state.custom_globals.after_check_handlers = set()

            while check_items:
                (check_state, handlers) = check_items.pop(0)
                handler_triggered = False

                for handler in handlers:
                    eligible_events = handler.get_eligible_events(check_state)
                    if not eligible_events:
                        continue

                    handler_triggered = True
                    neg_prev_conds = []
                    pruning = False

                    for event_info, trig_conds in eligible_events:
                        for trig_cond in trig_conds:
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

                            handler.trigger_event(new_state, event_info)
                            check_items.append((new_state, handlers))

                            neg_prev_conds.append(claripy.Not(trig_cond))
                            if not check_state.solver.satisfiable(
                                extra_constraints=neg_prev_conds
                            ):  # pruning，如果這個 trigger condition 到目前是一定會被觸發，則代表到目前 fork 出的所有 state 已滿足所有可能的情況。所以同等於計算是否不可能有滿足 neg_prev_conds 的情況
                                pruning = True
                                break
                        if pruning:
                            break

                    if not pruning:
                        if check_state.addr in self.end_addrs:
                            merged_results["found"].append(check_state)
                        else:
                            merged_results[None].append(check_state)

                    # 只要有觸發事件（或狀態被切分），就中斷這輪 handler 輪詢，因為放入 worklist 的 states 會重新從第一個 handler 開始檢查
                    break

                if not handler_triggered:
                    if check_state.addr in self.end_addrs:
                        merged_results["found"].append(check_state)
                    else:
                        merged_results[None].append(check_state)

            return merged_results
