import angr
import claripy

from project import utils
from project.cores.arm.arm import ARM
from project.cores.arm.cortex_m.nvic import NVIC
from project.types import MMIOMemoryRegion


class CortexM(ARM):
    VTOR_ADDR = None

    def setup(self, proj, specs, simgr, state):
        # ARMv7-M Architecture Reference Manual B1.5.8 Exception return behavior
        proj.hook(
            0xFFFFFFF1, self._ExcpReturnProcedure(cpu=self)
        )  # return to handler mode, main stack, basic frame
        proj.hook(
            0xFFFFFFF9, self._ExcpReturnProcedure(cpu=self)
        )  # return to thread mode, main stack, basic frame
        # TODO: return stack 為 process stack pointer (PSP) 時、frame type 為 extended 時

        cfg = proj.analyses.CFGFast(normalize=True)

        interrupt_checkpoints = self.get_interrupt_checkpoints(proj, cfg)
        interrupt_checkpoints[0xFFFFFFF1] = "inst_after"
        interrupt_checkpoints[0xFFFFFFF9] = "inst_after"
        for end_addr in specs.END_ADDRS:
            interrupt_checkpoints[end_addr] = "inst_before"
        simgr.use_technique(
            self._InterruptAndTerminateChecker(
                self, specs, interrupt_checkpoints, specs.END_ADDRS
            )
        )

        return cfg

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

    class _InterruptAndTerminateChecker(angr.ExplorationTechnique):
        def __init__(self, cpu, specs, interrupt_checkpoints, end_addrs):
            super().__init__()
            self.cpu = cpu
            self.specs = specs
            self.interrupt_checkpoints = interrupt_checkpoints
            self.end_addrs = end_addrs
            self._is_first_step = True

        def step_state(self, simgr, state, **kwargs):
            if self._is_first_step:
                new_extra_stop_points = kwargs.get("extra_stop_points", set())
                new_extra_stop_points.update(self.interrupt_checkpoints.keys())
                kwargs["extra_stop_points"] = new_extra_stop_points
                self._is_first_step = False

            is_end_addr = state.addr in self.end_addrs

            if state.addr not in self.interrupt_checkpoints and not is_end_addr:
                return simgr.step_state(state, **kwargs)

            merged_results = {}
            states_to_check = []
            if (
                state.addr in self.interrupt_checkpoints
                and self.interrupt_checkpoints[state.addr] == "inst_after"
            ):  # instruction 執行後才 inject interrupt
                kwargs_single = kwargs.copy()
                kwargs_single["num_inst"] = 1
                succs = simgr.step_state(state, **kwargs_single)
                states_to_check.extend(succs.get("active", []))
                for stash_name, states in succs.items():
                    if stash_name != "active":
                        merged_results.setdefault(stash_name, []).extend(states)
            else:  # instruction 執行前就 inject interrupt
                states_to_check.append(state)

            for current_state in states_to_check:
                # 收集所有 peripheral 的 pending IRQ
                IRQ_triggers = {}
                for region in self.specs.MEMORY_REGIONS.values():
                    if isinstance(region, MMIOMemoryRegion):
                        for irq_number, triggers in region.get_pending_irqs(
                            current_state
                        ).items():
                            IRQ_triggers.setdefault(irq_number, []).extend(triggers)

                if all(not v for v in IRQ_triggers.values()):
                    if is_end_addr:
                        merged_results.setdefault("found", []).append(current_state)
                    elif current_state is state:
                        new_simgr_normal = simgr.step_state(current_state, **kwargs)
                        for stash_name, states in new_simgr_normal.items():
                            merged_results.setdefault(stash_name, []).extend(states)
                    else:
                        merged_results.setdefault("active", []).append(current_state)
                    continue

                # 計算目前 priority 最大的 IRQ
                best_IRQ = min(
                    IRQ_triggers.keys(),
                    key=lambda k: (NVIC.get_irq_priority(current_state, k), k),
                )
                if NVIC.get_irq_priority(
                    current_state, best_IRQ
                ) >= current_state.globals.get("current_priority", 256):
                    if is_end_addr:
                        merged_results.setdefault("found", []).append(current_state)
                    elif current_state is state:
                        new_simgr_normal = simgr.step_state(current_state, **kwargs)
                        for stash_name, states in new_simgr_normal.items():
                            merged_results.setdefault(stash_name, []).extend(states)
                    else:
                        merged_results.setdefault("active", []).append(current_state)
                    continue

                negated_previous_conds = []

                # 分支 1: 觸發 IRQ
                for trigger_var, trigger_cond in IRQ_triggers[best_IRQ]:
                    isr_state = current_state.copy()

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
                            f"IRQ Injection | pc: {current_state.regs.pc} -> Branching into IRQ {best_IRQ}"
                        )

                        if current_state is state:
                            new_simgr = simgr.step_state(isr_state, **kwargs)
                            for stash_name, states in new_simgr.items():
                                merged_results.setdefault(stash_name, []).extend(states)
                        else:
                            merged_results.setdefault("active", []).append(isr_state)

                    # trigger_cond 為 claripy True 時表示 trigger_var 為 concrete value，不需要儲存 not trigger_cond
                    if not current_state.solver.is_true(trigger_cond):
                        negated_previous_conds.append(claripy.Not(trigger_cond))

                # 分支 2: 不觸發 IRQ
                normal_state = current_state.copy()
                if is_end_addr:
                    merged_results.setdefault("found", []).append(normal_state)
                elif current_state is state:
                    new_simgr_normal = simgr.step_state(normal_state, **kwargs)
                    for stash_name, states in new_simgr_normal.items():
                        merged_results.setdefault(stash_name, []).extend(states)
                else:
                    merged_results.setdefault("active", []).append(normal_state)

            return merged_results


class ARMv7M(CortexM):
    VTOR_ADDR = 0xE000ED08

    def __init__(self, has_fpu=False):
        self.has_fpu = has_fpu

    def _push_extended_frame(self, state):
        # TODO: Extended frame type
        raise NotImplementedError("Extended Frame is not implemented yet")
