from collections import defaultdict

import angr
import claripy

from project import utils
from project.cores.arm.arm import ARM
from project.cores.arm.cortex_m.nvic import NVIC


class CortexM(ARM):
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

        # 要在所有的 hook 都完成後才執行
        cfg = proj.analyses.CFGFast(normalize=True, cross_references=True)

        # interrupt_checkpoints = {}
        interrupt_checkpoints = self.get_interrupt_checkpoints(
            proj, cfg, specs.get_MMIOMemoryRegions()
        )
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

        def step(self, simgr, stash="active", **kwargs):
            # 將 interrupt checkpoints 加入 kwargs["extra_stop_points"]
            new_extra_stop_points = set(kwargs.get("extra_stop_points", set()))
            new_extra_stop_points.update(self.interrupt_checkpoints.keys())
            kwargs["extra_stop_points"] = new_extra_stop_points

            return simgr.step(stash=stash, **kwargs)

        def step_state(self, simgr, state, **kwargs):
            """
            回傳值的 key None 即表示 active
            """

            if state.addr not in self.interrupt_checkpoints:
                return simgr.step_state(state, **kwargs)

            merged_results = defaultdict(list)
            states_to_check = []

            if (
                self.interrupt_checkpoints[state.addr] == "inst_after"
            ):  # instruction 執行後才 inject interrupt
                kwargs["num_inst"] = 1
                succ_stashes = simgr.step_state(state, **kwargs)
                states_to_check.extend(succ_stashes.get(None, []))
                for stash_name, states in succ_stashes.items():
                    if stash_name is not None:
                        merged_results[stash_name].extend(states)
            else:  # instruction 執行前就 inject interrupt
                states_to_check.append(state)

            for check_state in states_to_check:
                is_end_addr = check_state.addr in self.end_addrs

                # 收集所有 peripheral 的 pending IRQs
                pending_irqs = defaultdict(
                    list
                )  # {irq: [(trigger variable, trigger condition), ...]}
                for region in self.specs.get_MMIOMemoryRegions():
                    for irq, trig_info in region.get_pending_irqs(check_state).items():
                        pending_irqs[irq].extend(trig_info)
                if not pending_irqs:
                    if is_end_addr:
                        merged_results["found"].append(check_state)
                    elif check_state is state:
                        succ_stashes = simgr.step_state(check_state, **kwargs)
                        for stash_name, states in succ_stashes.items():
                            merged_results[stash_name].extend(states)
                    else:
                        merged_results[None].append(check_state)
                    continue

                # 剔除低於目前 priority 的 IRQ，並根據 priority 排序 IRQ
                eligible_irqs = []  # [(priority, irq, [(trigger variable, trigger condition), ...]), ...]
                for irq, trig_info in pending_irqs.items():
                    prio = NVIC.get_irq_priority(check_state, irq)
                    if prio < check_state.globals.get("current_priority", 256):
                        eligible_irqs.append((prio, irq, trig_info))
                eligible_irqs.sort()
                if not eligible_irqs:
                    if is_end_addr:
                        merged_results["found"].append(check_state)
                    elif check_state is state:
                        succ_stashes = simgr.step_state(check_state, **kwargs)
                        for stash_name, states in succ_stashes.items():
                            merged_results[stash_name].extend(states)
                    else:
                        merged_results[None].append(check_state)
                    continue

                accumulated_neg_conds = []
                found_unconditional_irq = False

                for _, irq, trig_info in eligible_irqs:
                    for trig_var, trig_cond in trig_info:
                        if not check_state.solver.satisfiable(
                            extra_constraints=accumulated_neg_conds + [trig_cond]
                        ):  # 因為加了 neg_prev_conds constraints，所以需要檢查
                            continue

                        new_state = check_state.copy()
                        for neg_prev_cond in accumulated_neg_conds:
                            new_state.add_constraints(neg_prev_cond)
                        new_state.add_constraints(trig_cond)

                        self.cpu.excp_entry(new_state, irq)
                        print(
                            f"IRQ Injection | pc: {check_state.regs.pc} -> Branching into IRQ {irq}"
                        )
                        if check_state is state:
                            succ_stashes = simgr.step_state(new_state, **kwargs)
                            for stash_name, states in succ_stashes.items():
                                merged_results[stash_name].extend(states)
                        else:
                            merged_results[None].append(new_state)

                        if trig_cond.is_true():
                            found_unconditional_irq = True
                        else:
                            can_skip = check_state.solver.satisfiable(
                                extra_constraints=accumulated_neg_conds
                                + [claripy.Not(trig_cond)]
                            )
                            if not can_skip:
                                found_unconditional_irq = True
                            else:
                                accumulated_neg_conds.append(claripy.Not(trig_cond))

                    if found_unconditional_irq:
                        break
                if found_unconditional_irq:
                    continue

                # 沒有 IRQ 觸發
                if check_state.solver.satisfiable(
                    extra_constraints=accumulated_neg_conds
                ):
                    normal_state = check_state.copy()
                    if is_end_addr:
                        merged_results["found"].append(normal_state)
                    elif check_state is state:
                        succ_stashes = simgr.step_state(normal_state, **kwargs)
                        for stash_name, states in succ_stashes.items():
                            merged_results[stash_name].extend(states)
                    else:
                        merged_results[None].append(normal_state)

            return merged_results


class ARMv7M(CortexM):
    VTOR_ADDR = 0xE000ED08

    def __init__(self, has_fpu=False):
        self.has_fpu = has_fpu

    def _push_extended_frame(self, state):
        # TODO: Extended frame type
        raise NotImplementedError("Extended Frame is not implemented yet")
