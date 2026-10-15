import angr

from project.cores.base import BaseCPU
from project.types import BPConfig


class ARM(BaseCPU):
    def thumb_mode(self, registers):
        cpsr = registers.get("cpsr")
        if cpsr is None:
            return None

        return bool(cpsr & (1 << 5))

    def get_static_interrupt_checkpoints(self, proj, state, cfg, specs):
        ckpts = super().get_static_interrupt_checkpoints(proj, state, cfg, specs)

        for node in cfg.graph.nodes():
            if node.block is None:
                continue

            block = proj.factory.block(node.addr, size=node.size)

            for insn in block.capstone.insns:
                mnemonic = insn.mnemonic.upper()

                # 1. Before WFI, WFE (low-power standby)
                if mnemonic in {"WFI", "WFE"}:
                    ckpts.add(
                        BPConfig(
                            "instruction", when=angr.BP_BEFORE, instruction=insn.address
                        )
                    )
                # 2. Before CPSID (Disable Interrupts) and after CPSIE (Enable Interrupts)
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
