from __future__ import annotations

from collections import defaultdict

import angr
import claripy

from project import utils
from project.cores.arm.arm import ARM
from project.cores.arm.cortex_m.nvic import NVIC
from project.types import EventForkHandler


class CortexM(ARM):
    VTOR_ADDR = None

    def setup(self, proj, specs, simgr):
        # ARMv7-M Architecture Reference Manual B1.5.8 Exception return behavior
        # 實際上 processor 的行為是攔截到 write exception return value 到 pc 的時機做 exception return；但我的實作是讓 pc 成功 write exception return value 之後，把 pc 要執行的指令 hook 成 exception return 行為
        proj.hook(
            0xFFFFFFF1, self._ExcpReturnProcedure(cpu=self)
        )  # return to handler mode, main stack, basic frame
        proj.hook(
            0xFFFFFFF9, self._ExcpReturnProcedure(cpu=self)
        )  # return to thread mode, main stack, basic frame
        # TODO: return stack 為 process stack pointer (PSP) 時、frame type 為 extended 時

        # 要在所有的 hook 都完成後才執行
        cfg = proj.analyses.CFGFast(normalize=True, cross_references=True)

        checkpoints_list = []
        checkpoints_list.extend(self.set_handlers(proj=proj, cfg=cfg, specs=specs))
        checkpoints_list.extend(
            specs.set_handlers(cpu=self, proj=proj, cfg=cfg, specs=specs)
        )
        simgr.use_technique(
            CortexM.ForkEventManager(
                cpu=self, checkpoints_list=checkpoints_list, end_addrs=specs.END_ADDRS
            )
        )

        return cfg

    def normalize_address(self, addr):
        # Cortex-M 永遠是 thumb mode
        return addr & ~1

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

    def _sort_irqs(self, irqs):
        # 1. trigger condition 為 concrete true 的放到前面
        for _, _, trig_conds in irqs:
            concrete_trues = []
            not_concrete_trues = []

            for trig_cond in trig_conds:
                if trig_cond.is_true():
                    concrete_trues.append(trig_cond)
                else:
                    not_concrete_trues.append(trig_cond)

            trig_conds[:] = concrete_trues + not_concrete_trues

        # 依照 priority 及 IRQ number 排序
        irqs.sort(key=lambda x: (x[0], x[1]))

    class _ExcpReturnProcedure(angr.SimProcedure):
        NO_RET = True

        def __init__(self, cpu, **kwargs):
            super().__init__(**kwargs)
            self.cpu = cpu

        def run(self):
            # TODO: If an EXC_RETURN value is loaded into the PC when in Thread mode, or from the vector table, or by any other instruction, the value is treated as an address, not as a special value. The 0xFXXXXXXX address range, that includes all possible EXC_RETURN values, has Execute Never (XN) permissions, and loading this value causes a MemManage exception, or an INVSTATE UsageFault exception, or escalation of the exception to a HardFault.
            pc = self.cpu.excp_exit(self.state)

            self.successors.add_successor(self.state, pc, claripy.true(), "Ijk_Boring")

    def get_interrupt_checkpoints(self, proj, cfg, specs, handler):
        checkpoints = super().get_interrupt_checkpoints(proj, cfg, specs, handler)

        checkpoints[self.normalize_address(0xFFFFFFF1)][1].append(handler)
        checkpoints[self.normalize_address(0xFFFFFFF9)][1].append(handler)

        return checkpoints

    class _InterruptHandler(EventForkHandler):
        def __init__(self, cpu, proj, cfg, specs):
            self.cpu = cpu
            self.specs = specs

            # checkpoints = {}
            # self.checkpoints = utils.process_cache_file(
            #     self.specs.FIRMWARE_PATH,
            #     Path(self.specs.FIRMWARE_PATH).with_suffix(".intrckpt"),
            #     self.cpu.get_interrupt_checkpoints,
            #     proj=proj,
            #     cfg=cfg,
            #     specs=specs,
            #     handler=self,
            # )
            self.checkpoints = self.cpu.get_interrupt_checkpoints(
                proj=proj, cfg=cfg, specs=specs, handler=self
            )

        def get_checkpoints(self):
            return self.checkpoints

        def get_eligible_events(self, state):
            # 收集所有 peripheral 的 pending IRQs
            pending_irqs = defaultdict(list)  # {irq: trigger condition, ...}
            for region in self.specs.get_MMIOMemoryRegions():
                for irq, trig_conds in region.get_pending_irqs(state).items():
                    pending_irqs[irq].extend(trig_conds)

            # 剔除低於目前 priority 的 IRQ，並根據 priority 排序 IRQ
            eligible_irqs = []  # [(priority, irq, trigger conditions), ...]
            for irq, trig_conds in pending_irqs.items():
                prio = NVIC.get_irq_priority(state, irq)
                if prio < state.globals.get("current_priority", 256):
                    eligible_irqs.append((prio, irq, trig_conds))
            self.cpu._sort_irqs(eligible_irqs)
            return [(irq, trig_conds) for _, irq, trig_conds in eligible_irqs]

        def trigger_event(self, state, irq):
            self.cpu.excp_entry(state, irq)
            print(f"IRQ Injection | pc: {state.regs.pc} -> Branching into IRQ {irq}")

    def set_handlers(self, proj, cfg, specs):
        self.interrupt_handler = CortexM._InterruptHandler(
            cpu=self, proj=proj, cfg=cfg, specs=specs
        )
        return [self.interrupt_handler.get_checkpoints()]


class ARMv7M(CortexM):
    VTOR_ADDR = 0xE000ED08

    def __init__(self, has_fpu=False):
        self.has_fpu = has_fpu

    def _push_extended_frame(self, state):
        # TODO: Extended frame type
        raise NotImplementedError("Extended Frame is not implemented yet")
