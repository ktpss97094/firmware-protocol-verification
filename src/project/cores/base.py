import pyvex


class CPU:
    def normalize_address(self, addr):
        return addr

    def get_interrupt_checkpoints(self, proj, cfg):
        checkpoints: dict[int, str] = {}
        sp_offset = proj.arch.sp_offset

        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = proj.factory.block(node.addr, size=node.size)

            for stmt_idx, stmt in enumerate(block.vex.statements):
                addr_expr = None

                # 2.1 尋找普遍的 Memory Read / Write
                if isinstance(stmt, pyvex.stmt.Store):
                    addr_expr = stmt.addr
                elif isinstance(stmt, pyvex.stmt.WrTmp) and isinstance(
                    stmt.data, pyvex.expr.Load
                ):
                    addr_expr = stmt.data.addr

                # 2.2 尋找同步指令 (取代特定的 DSB, DMB, ISB)
                elif isinstance(stmt, pyvex.stmt.MBE):
                    try:
                        insn_addr = block.instruction_addrs[
                            self._stmt_idx_to_inst_idx(block.vex, stmt_idx)
                        ]
                        checkpoints[self.normalize_address(insn_addr)] = "inst_before"
                    except IndexError:
                        pass

                # 2.3 尋找 Exclusive Memory Access (取代特定的 STREX)
                elif isinstance(stmt, pyvex.stmt.LLSC):
                    # stmt.storedata 不為 0 表示這是 Store 操作 (對應 STREX 等)
                    if hasattr(stmt, "storedata") and stmt.storedata != 0:
                        try:
                            insn_addr = block.instruction_addrs[
                                self._stmt_idx_to_inst_idx(block.vex, stmt_idx)
                            ]
                            checkpoints[self.normalize_address(insn_addr)] = (
                                "inst_before"
                            )
                        except IndexError:
                            pass
                else:
                    continue

                # 分析記憶體位址的表達式 (過濾掉 Stack 存取 ...)
                if addr_expr is not None:
                    is_stack = self._check_if_expr_contains_reg(addr_expr, sp_offset)
                    if not is_stack:
                        try:
                            insn_addr = block.instruction_addrs[
                                self._stmt_idx_to_inst_idx(block.vex, stmt_idx)
                            ]
                            checkpoints[self.normalize_address(insn_addr)] = (
                                "inst_before"
                            )
                        except IndexError:
                            pass

        return checkpoints

    def _stmt_idx_to_inst_idx(self, vex_block, stmt_idx):
        """
        將 VEX 的 statement index 轉回對應的 instruction index
        """
        # angr 的 VEX block 會有一個方法或屬性記錄 IMark (Instruction Mark)
        # 我們往上找最近的 IMark
        curr_inst = 0
        for i in range(stmt_idx + 1):
            if isinstance(vex_block.statements[i], pyvex.stmt.IMark):
                curr_inst += 1
        return curr_inst - 1 if curr_inst > 0 else 0

    def _check_if_expr_contains_reg(self, expr, reg_offset):
        """
        遞迴檢查 VEX VSA 的表達式中，是否包含了特定的暫存器 (比如 SP)
        """
        if isinstance(expr, pyvex.expr.Get):
            return expr.offset == reg_offset
        elif hasattr(expr, "args"):
            for arg in expr.args:
                if self._check_if_expr_contains_reg(arg, reg_offset):
                    return True
        return False
