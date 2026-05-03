import logging
from collections import defaultdict

import angr
import angr.analyses.variable_recovery.engine_vex as engine_vex
import claripy
import pyvex
from angr.knowledge_plugins.variables.variable_access import VariableAccessSort
from angr.knowledge_plugins.xrefs.xref_types import XRefType

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


class CPU:
    def __init__(self):
        self._mmio_rw_addrs = None
        self._global_rw_addrs = None

    def normalize_address(self, addr):
        return addr

    def get_explicit_memory_access_instruction_address(self, proj, mmio_regions):
        if self._mmio_rw_addrs is not None:
            return self._mmio_rw_addrs

        self._mmio_rw_addrs = []

        for dst_addr, xref_set in proj.kb.xrefs.xrefs_by_dst.items():
            if any(mmio_region.in_region(dst_addr) for mmio_region in mmio_regions):
                for xref in xref_set:
                    if xref.ins_addr is not None:
                        if xref.type == XRefType.Read or xref.type == XRefType.Write:
                            self._mmio_rw_addrs.append(
                                self.normalize_address(xref.ins_addr)
                            )

        return self._mmio_rw_addrs

    def get_global_variable_access_instruction_address(self, proj):
        if self._global_rw_addrs is not None:
            return self._global_rw_addrs

        self._global_rw_addrs = []

        for addr, func in proj.kb.functions.items():
            # 排除掉 SimProcedures 或只是用來對齊的空函數
            if not func.is_simprocedure and not func.is_alignment:
                try:
                    proj.analyses.VariableRecoveryFast(func)
                except Exception as e:
                    print(f"Analyze {hex(addr)} error: {e}")
        global_varmgr = proj.kb.variables["global"]
        for var in global_varmgr.get_variables():
            accesses = global_varmgr.get_variable_accesses(var)
            for access in accesses:
                ins_addr = access.location.ins_addr
                if (
                    access.access_type == VariableAccessSort.READ
                    or access.access_type == VariableAccessSort.WRITE
                ):
                    self._global_rw_addrs.append(self.normalize_address(ins_addr))

        return self._global_rw_addrs

    def get_interrupt_checkpoints(self, proj, cfg, mmio_regions):
        checkpoints = defaultdict(set)

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
                        checkpoints[self.normalize_address(ins_addr)].add("inst_before")
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
                            checkpoints[self.normalize_address(ins_addr)].add(
                                "inst_before"
                            )
                        except IndexError:
                            pass

        # 3. Global Variable R/W 之前
        global_rw_addrs = self.get_global_variable_access_instruction_address(proj)
        for ins_addr in global_rw_addrs:
            checkpoints[ins_addr].add("inst_before")

        # 4. MMIO R/W 之前
        mmio_rw_addrs = self.get_explicit_memory_access_instruction_address(
            proj, mmio_regions
        )
        for ins_addr in mmio_rw_addrs:
            checkpoints[ins_addr].add("inst_before")

        return checkpoints

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
        def __init__(self, handlers, end_addrs):
            super().__init__()
            self.handlers = handlers
            self.end_addrs = end_addrs

            self.checkpoints = defaultdict(set)
            for handler in handlers:
                for addr, when in handler.get_checkpoints().items():
                    self.checkpoints[addr].update(when)

        def _process_events(self, states, check_type):
            final_states = []

            while states:
                check_state = states.pop(0)
                handler_triggered = False

                # 輪詢每個註冊的 EventHandler
                for handler in self.handlers:
                    if check_type not in handler.get_checkpoints()[check_state.addr]:
                        continue

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
                            states.append(new_state)

                            neg_prev_conds.append(claripy.Not(trig_cond))
                            if not check_state.solver.satisfiable(
                                extra_constraints=neg_prev_conds
                            ):  # pruning，如果這個 trigger condition 到目前是一定會被觸發，則代表到目前 fork 出的所有 state 已滿足所有可能的情況。所以同等於計算是否不可能有滿足 neg_prev_conds 的情況
                                pruning = True
                                break
                        if pruning:
                            break

                    if not pruning:
                        final_states.append(check_state)

                    # 只要有觸發事件（或狀態被切分），就中斷這輪 handler 輪詢，因為放入 worklist 的 states 會重新從第一個 handler 開始檢查
                    break

                if not handler_triggered:
                    final_states.append(check_state)

            return final_states

        def step(self, simgr, stash="active", **kwargs):
            # 將 checkpoints 加入 kwargs["extra_stop_points"]
            new_extra_stop_points = set(kwargs.get("extra_stop_points", set()))
            new_extra_stop_points.update(self.checkpoints.keys())
            kwargs["extra_stop_points"] = new_extra_stop_points

            return simgr.step(stash=stash, **kwargs)

        def step_state(self, simgr, state, **kwargs):
            if state.addr not in self.checkpoints:
                return simgr.step_state(state, **kwargs)

            check_types = self.checkpoints[state.addr]
            merged_results = defaultdict(list)

            # 階段 1: 執行前檢查
            before_states = []
            if "inst_before" in check_types:
                before_states = self._process_events([state], "inst_before")
            else:
                before_states = [state]

            # 階段 2：對確認可以放行的 state，實際上推動一個 instruction
            stepped_states = []
            step_kwargs = kwargs.copy()
            step_kwargs["num_inst"] = 1

            for b_state in before_states:
                # 檢查 termination
                if b_state.addr in self.end_addrs:
                    merged_results["found"].append(b_state)
                    continue

                succ_stashes = simgr.step_state(b_state, **step_kwargs)
                stepped_states.extend(succ_stashes.get(None, []))
                for stash_name, states in succ_stashes.items():
                    if stash_name is not None:
                        merged_results[stash_name].extend(states)

            # 階段 3：對執行完指令的 successor states，做 inst_after 檢查
            if "inst_after" in check_types:
                after_results = self._process_events(stepped_states, "inst_after")
                merged_results[None].extend(after_results)
            else:
                merged_results[None].extend(stepped_states)

            return merged_results
