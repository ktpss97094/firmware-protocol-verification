import angr
import claripy

from project import utils
from project.cores.cortex_m.nvic import NVIC
from project.types import MMIOMemoryRegion


class CortexM:
    VTOR_ADDR = None

    def setup(self, proj, specs, simgr):
        # ARMv7-M Architecture Reference Manual B1.5.8 Exception return behavior
        proj.hook(
            0xFFFFFFF1, self._ExcpReturnProcedure(cpu=self)
        )  # return to handler mode, main stack, basic frame
        proj.hook(
            0xFFFFFFF9, self._ExcpReturnProcedure(cpu=self)
        )  # return to thread mode, main stack, basic frame
        # TODO: return stack 為 process stack pointer (PSP) 時、frame type 為 extended 時

        simgr.use_technique(self._InterruptInjector(self, specs))

    def excp_entry(self, state, int_no):
        self._push_basic_frame(state)

        priority_stack = state.globals.get("priority_stack", []).copy()
        priority_stack.append(state.globals.get("current_priority", 256))
        state.globals["priority_stack"] = priority_stack
        state.globals["current_priority"] = NVIC.get_irq_priority(state, int_no)

        # 計算 ISR 的 address
        excp_no = int_no + 16
        vector_table_base = self._get_vector_table_base(state)
        vector_addr = vector_table_base + (excp_no * 4)
        isr_addr = state.solver.eval(utils.load(state, vector_addr))

        state.regs.pc = isr_addr
        state.regs.lr = 0xFFFFFFF1 if NVIC.is_in_handler_mode(state) else 0xFFFFFFF9

    def _push_basic_frame(self, state):
        # ARMv7-M Architecture Reference Manual B1.5.6 Exception entry behavior
        self._push(
            state, state.regs.iepsr
        )  # TODO: push iepsr 是不精確的，要看 B1.5.6 的行為
        self._push(state, state.regs.pc)
        self._push(state, state.regs.lr)
        self._push(state, state.regs.r12)
        self._push(state, state.regs.r3)
        self._push(state, state.regs.r2)
        self._push(state, state.regs.r1)
        self._push(state, state.regs.r0)

    def _push(self, s, reg):
        s.regs.sp -= 4
        utils.store(s, s.regs.sp, reg)

    def excp_exit(self, state):
        # ARMv7-M Architecture Reference Manual B1.5.8 Exception return behavior
        state.regs.r0 = self._pop(state)
        state.regs.r1 = self._pop(state)
        state.regs.r2 = self._pop(state)
        state.regs.r3 = self._pop(state)
        state.regs.r12 = self._pop(state)
        state.regs.lr = self._pop(state)
        pc = self._pop(state)
        state.regs.iepsr = self._pop(state)

        priority_stack = state.globals.get("priority_stack", []).copy()
        try:
            state.globals["current_priority"] = priority_stack.pop()
            state.globals["priority_stack"] = priority_stack
        except IndexError:
            raise Exception("Priority stack underflow")

        return pc

    def _pop(self, state):
        reg = utils.load(state, state.regs.sp)
        state.regs.sp += 4
        return reg

    def _get_vector_table_base(self, state):
        if self.VTOR_ADDR is not None:
            return state.solver.eval(utils.load(state, self.VTOR_ADDR)) & 0xFFFFFF80
        return 0x00000000

    class _ExcpReturnProcedure(angr.SimProcedure):
        NO_RET = True

        def __init__(self, cpu, **kwargs):
            super().__init__(**kwargs)
            self.cpu = cpu

        def run(self):
            pc = self.cpu.excp_exit(self.state)
            self.successors.add_successor(self.state, pc, claripy.true(), "Ijk_Boring")

    class _InterruptInjector(angr.ExplorationTechnique):
        def __init__(self, cpu, specs):
            super().__init__()
            self.cpu = cpu
            self.specs = specs

        def step_state(self, simgr, state, **kwargs):
            # 過濾掉不必要做 interrupt 注入的情況
            try:
                block = state.project.factory.block(state.addr)

                if (
                    block.vex.jumpkind == "Ijk_Ret"  # function return
                    or (
                        block.vex.jumpkind == "Ijk_Boring" and block.instructions == 1
                    )  # normal jump
                    or block.vex.jumpkind == "Ijk_Call"  # function call
                    or block.vex.jumpkind.startswith("Ijk_Sys")  # system call
                    or (
                        block.vex.jumpkind in ("Ijk_NoDecode", "Ijk_MapFail")
                        or block.instructions == 0
                    )  # 無效或空的 block
                ):
                    return simgr.step_state(state, **kwargs)
            except Exception:
                pass

            # 收集所有 peripheral 的 pending IRQ
            IRQ_triggers = {}
            for region in self.specs.MEMORY_REGIONS.values():
                if isinstance(region, MMIOMemoryRegion) and hasattr(
                    region, "get_pending_irqs"
                ):
                    for irq_number, triggers in region.get_pending_irqs(state).items():
                        IRQ_triggers.setdefault(irq_number, []).extend(triggers)

            if all(not v for v in IRQ_triggers.values()):
                return simgr.step_state(state, **kwargs)

            # 計算目前 priority 最大的 IRQ
            best_IRQ = min(
                IRQ_triggers.keys(), key=lambda k: (NVIC.get_irq_priority(state, k), k)
            )
            if NVIC.get_irq_priority(state, best_IRQ) >= state.globals.get(
                "current_priority", 256
            ):
                return simgr.step_state(state, **kwargs)

            merged_results = {}
            negated_previous_conds = []

            # 分支 1: 觸發 IRQ
            for trigger_var, trigger_cond in IRQ_triggers[best_IRQ]:
                isr_state = state.copy()

                isr_state.add_constraints(trigger_cond)
                for neg_cond in negated_previous_conds:
                    isr_state.add_constraints(neg_cond)

                if isr_state.satisfiable():
                    isr_handled_hashes = set(
                        isr_state.custom_globals.irq[best_IRQ]["handled_hashes"]
                    )
                    isr_handled_hashes.add(hash(trigger_var))
                    isr_state.custom_globals.irq[best_IRQ]["handled_hashes"] = (
                        frozenset(isr_handled_hashes)
                    )

                    self.cpu.excp_entry(isr_state, best_IRQ)

                    print(
                        f"IRQ Injection | pc: {state.regs.pc} -> Branching into IRQ {best_IRQ}"
                    )

                    new_simgr = simgr.step_state(isr_state, **kwargs)
                    for stash_name, states in new_simgr.items():
                        merged_results.setdefault(stash_name, []).extend(states)

                negated_previous_conds.append(claripy.Not(trigger_cond))

            # 分支 2: 不觸發 IRQ
            normal_state = state.copy()
            new_simgr_normal = simgr.step_state(normal_state, **kwargs)
            for stash_name, states in new_simgr_normal.items():
                merged_results.setdefault(stash_name, []).extend(states)

            return merged_results


class ARMv7M(CortexM):
    VTOR_ADDR = 0xE000ED08

    def __init__(self, has_fpu=False):
        self.has_fpu = has_fpu

    def _push_extended_frame(self, state):
        # TODO: Extended frame type
        raise NotImplementedError("Extended Frame is not implemented yet")
