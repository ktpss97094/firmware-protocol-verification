import logging

import angr.analyses.variable_recovery.engine_vex as engine_vex
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
    def normalize_address(self, addr):
        return addr

    def get_interrupt_checkpoints(self, proj, cfg, mmio_regions):
        checkpoints: dict[int, str] = {}

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
                        checkpoints[self.normalize_address(ins_addr)] = "inst_before"
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
                            checkpoints[self.normalize_address(ins_addr)] = (
                                "inst_before"
                            )
                        except IndexError:
                            pass

        # 3. Global Variable R/W 之前
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
                    checkpoints[self.normalize_address(ins_addr)] = "inst_before"

        # 4. MMIO R/W 之前
        for dst_addr, xref_set in proj.kb.xrefs.xrefs_by_dst.items():
            if any(mmio_region.in_region(dst_addr) for mmio_region in mmio_regions):
                for xref in xref_set:
                    if xref.ins_addr is not None:
                        if xref.type == XRefType.Read or xref.type == XRefType.Write:
                            checkpoints[self.normalize_address(xref.ins_addr)] = (
                                "inst_before"
                            )

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
