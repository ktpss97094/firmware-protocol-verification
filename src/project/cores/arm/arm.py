import angr

from project.cores.base import BaseCPU
from project.types import BPConfig


class ARM(BaseCPU):
    def get_static_interrupt_checkpoints(self, proj, cfg, specs):
        ckpts = super().get_static_interrupt_checkpoints(proj, cfg, specs)

        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = proj.factory.block(node.addr, size=node.size)

            for insn in block.capstone.insns:
                mnemonic = insn.mnemonic.upper()

                # 1. WFI, WFE (休眠) 之前
                if mnemonic in {"WFI", "WFE"}:
                    ckpts.add(
                        BPConfig(
                            "instruction", when=angr.BP_BEFORE, instruction=insn.address
                        )
                    )
                # 2. CPSID (禁用中斷) 之前、CPSIE (開啟中斷) 之後
                elif mnemonic.startswith("CPS"):
                    if mnemonic == "CPSID":
                        ckpts.add(
                            BPConfig(
                                "instruction",
                                when=angr.BP_BEFORE,
                                instruction=insn.address,
                            )
                        )
                    elif mnemonic == "CPSIE":
                        ckpts.add(
                            BPConfig(
                                "instruction",
                                when=angr.BP_AFTER,
                                instruction=insn.address,
                            )
                        )

        return ckpts
