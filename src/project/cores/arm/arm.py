from project.cores.base import CPU


class ARM(CPU):
    def normalize_address(self, addr):
        return addr & ~1

    def get_interrupt_checkpoints(self, proj, cfg, mmio_regions):
        checkpoints = super().get_interrupt_checkpoints(proj, cfg, mmio_regions)

        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = proj.factory.block(node.addr, size=node.size)

            for insn in block.capstone.insns:
                mnemonic = insn.mnemonic.upper()

                # 1. WFI, WFE (休眠) 之前
                if mnemonic in {"WFI", "WFE"}:
                    checkpoints[self.normalize_address(insn.address)].add("inst_before")
                # 2. CPSID (禁用中斷) 之前、CPSIE (開啟中斷) 之後
                elif mnemonic.startswith("CPS"):
                    if mnemonic == "CPSID":
                        checkpoints[self.normalize_address(insn.address)].add(
                            "inst_before"
                        )
                    elif mnemonic == "CPSIE":
                        checkpoints[self.normalize_address(insn.address)].add(
                            "inst_after"
                        )

        return checkpoints
