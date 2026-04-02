from project.cores.base import CPU


class ARM(CPU):
    def normalize_address(self, addr):
        return addr & ~1

    def get_interrupt_checkpoints(self, proj, cfg):
        checkpoints = super().get_interrupt_checkpoints(proj, cfg)

        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = proj.factory.block(node.addr, size=node.size)

            # -----------------------------------------------------------------
            # 任務 1：處理系統層級與中斷指令 (維持 Capstone 會更精準穩固)
            # -----------------------------------------------------------------
            for insn in block.capstone.insns:
                mnemonic = insn.mnemonic.upper()

                if mnemonic in {"WFI", "WFE"}:
                    checkpoints[self.normalize_address(insn.address)] = "inst_before"

                elif mnemonic.startswith("CPS"):
                    if mnemonic == "CPSID":
                        checkpoints[self.normalize_address(insn.address)] = (
                            "inst_before"
                        )
                    elif mnemonic == "CPSIE":
                        checkpoints[self.normalize_address(insn.address)] = "inst_after"

        return checkpoints
