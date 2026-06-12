from __future__ import annotations

import warnings
from collections import defaultdict
from functools import cache

import angr
import claripy

from project import utils
from project.cores.arm.arm import ARM
from project.cores.arm.cortex_m.nvic import NVIC
from project.types import BPConfig, EventForkHandler


class CortexM(ARM):
    VTOR_ADDR = None

    def setup(self, state, specs, simgr):
        # ARMv7-M Architecture Reference Manual B1.5.8 Exception return behavior
        # 實際上 processor 的行為是攔截到 write exception return value 到 pc 的時機做 exception return；但我的實作是讓 pc 成功 write exception return value 之後，把 pc 要執行的指令 hook 成 exception return 行為
        state.project.hook(
            0xFFFFFFF1, self._ExcpReturnProcedure(cpu=self)
        )  # return to handler mode, main stack, basic frame
        state.project.hook(
            0xFFFFFFF9, self._ExcpReturnProcedure(cpu=self)
        )  # return to thread mode, main stack, basic frame
        # TODO: return stack 為 process stack pointer (PSP) 時、frame type 為 extended 時

        # 要在所有的 hook 都完成後才執行
        cfg = state.project.analyses.CFGFast(normalize=True, cross_references=True)

        self.initial_sp = self._compute_initial_sp(state)
        self.stack_size = self._compute_stack_size(state)

        specs.set_handlers(cpu=self, state=state, cfg=cfg, specs=specs)
        self.set_handlers(state=state, cfg=cfg, specs=specs)
        self.fork_event_manager = CortexM.ForkEventManager(
            cpu=self, end_addrs=specs.END_ADDRS
        )
        simgr.use_technique(self.fork_event_manager)

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

    def _compute_initial_sp(self, state):
        """
        ArchARMCortexM 的 initial_sp 是預設值，實際上是根據 firmware linker script 決定，會被放在 IVT 開頭
        """

        return state.project.loader.memory.unpack_word(
            state.project.loader.main_object.min_addr
        )

    def _compute_stack_size(self, state):
        limit_symbols = ["__StackLimit", "_estack_limit", "__stack_limit", "_ebss"]

        stack_limit = None
        for sym_name in limit_symbols:
            sym = state.project.loader.find_symbol(sym_name)
            if sym is not None:
                stack_limit = sym.rebased_addr
                break

        if stack_limit is not None:
            return self._compute_initial_sp(state) - stack_limit
        else:
            warnings.warn(
                f"Cannot find stack limit symbol, using default stack size {state.arch.stack_size}"
            )
            return state.arch.stack_size

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

    def get_static_interrupt_checkpoints(self, proj, cfg, specs):
        ckpts = super().get_static_interrupt_checkpoints(proj, cfg, specs)

        ckpts.add(BPConfig("instruction", when=angr.BP_AFTER, instruction=0xFFFFFFF1))
        ckpts.add(BPConfig("instruction", when=angr.BP_AFTER, instruction=0xFFFFFFF9))

        return ckpts

    def _compute_dma_synchronize_instruction_checkpoints(self):
        return set()

    class _InterruptHandler(EventForkHandler):
        def __init__(self, cpu, state, cfg, specs):
            self.cpu = cpu
            self.specs = specs

            for ckpt in self.get_checkpoints(state, cfg, specs):
                ckpt.apply_to(state, handler=self)

        @cache
        def get_checkpoints(self, state, cfg, specs):
            ckpts = set()

            ckpts.update(
                self.cpu.get_static_interrupt_checkpoints(
                    proj=state.project, cfg=cfg, specs=specs
                )
            )

            # globally accessible regions
            ckpts.add(
                BPConfig(
                    "mem_read",
                    when=angr.BP_BEFORE,
                    condition=self.in_globally_accessible_region_read,
                )
            )
            ckpts.add(
                BPConfig(
                    "mem_write",
                    when=angr.BP_BEFORE,
                    condition=self.in_globally_accessible_region_write,
                )
            )
            ckpts.add(
                BPConfig(
                    "mem_read",
                    when=angr.BP_AFTER,
                    condition=self.globally_accessible_region_read_may_affect_isr,
                )
            )
            ckpts.add(
                BPConfig(
                    "mem_write",
                    when=angr.BP_AFTER,
                    condition=self.globally_accessible_region_write_may_affect_isr,
                )
            )

            # DMA
            for dma in specs.get_DMAs():
                ckpts.update(dma.dma_handler.get_checkpoints())

            return ckpts

        def get_eligible_events(self, state):
            # 收集所有 peripheral 的 pending IRQs
            pending_irqs = defaultdict(list)  # {irq: trigger conditions, ...}
            for region in self.specs.get_MMIOMemoryRegions():
                for trig_cond, kwargs in region.get_pending_irqs(state):
                    irq = kwargs["irq"]
                    pending_irqs[irq].append(trig_cond)

            # 剔除低於目前 priority 的 IRQ，並根據 priority 排序 IRQ
            eligible_irqs = []
            for irq, trig_conds in pending_irqs.items():
                prio = NVIC.get_irq_priority(state, irq)
                if prio < state.globals.get("current_priority", 256):
                    eligible_irqs.append((prio, irq, trig_conds))
            self.cpu._sort_irqs(eligible_irqs)
            return [
                (trig_cond, {"irq": irq})
                for _, irq, trig_conds in eligible_irqs
                for trig_cond in trig_conds
            ]

        def trigger_event(self, state, irq):
            print(f"IRQ Injection | pc: {state.regs.pc} -> Branching into IRQ {irq}")
            self.cpu.excp_entry(state, irq)

        @staticmethod
        def _concrete_inspect_value(state, value):
            if value is None:
                return None
            if isinstance(value, int):
                return value
            if not state.solver.unique(value):
                return None
            return state.solver.eval(value)

        def _access_effects(self, state, operation, address, size):
            address = self._concrete_inspect_value(state, address)
            size = self._concrete_inspect_value(state, size)
            if address is None or size is None:
                from project.types import AccessEffects

                return AccessEffects()
            return self.specs.get_access_effects(operation, address, size)

        def _inspect_access_effects(self, state, operation):
            if operation == "read":
                return self._access_effects(
                    state,
                    operation,
                    state.inspect.mem_read_address,
                    state.inspect.mem_read_length,
                )
            return self._access_effects(
                state,
                operation,
                state.inspect.mem_write_address,
                state.inspect.mem_write_length,
            )

        def in_globally_accessible_region(self, state, addr, operation, size=1):
            current_effects = self._access_effects(state, operation, addr, size)
            isr_effects = self.cpu.get_isr_shared_effects(state.project, self.specs)
            return current_effects.conflicts_with(isr_effects)

        def in_globally_accessible_region_read(self, state):
            return self.in_globally_accessible_region(
                state,
                state.inspect.mem_read_address,
                "read",
                state.inspect.mem_read_length,
            )

        def in_globally_accessible_region_write(self, state):
            return self.in_globally_accessible_region(
                state,
                state.inspect.mem_write_address,
                "write",
                state.inspect.mem_write_length,
            )

        def _access_may_affect_isr(self, state, operation):
            current_effects = self._inspect_access_effects(state, operation)
            isr_effects = self.cpu.get_isr_shared_effects(state.project, self.specs)
            return current_effects.writes_resources_used_by(isr_effects)

        def globally_accessible_region_read_may_affect_isr(self, state):
            return self._access_may_affect_isr(state, "read")

        def globally_accessible_region_write_may_affect_isr(self, state):
            return self._access_may_affect_isr(state, "write")

    def set_handlers(self, state, cfg, specs):
        self.interrupt_handler = CortexM._InterruptHandler(
            cpu=self, state=state, cfg=cfg, specs=specs
        )


class ARMv7M(CortexM):
    VTOR_ADDR = 0xE000ED08

    def __init__(self, has_fpu=False):
        self.has_fpu = has_fpu

    def _push_extended_frame(self, state):
        # TODO: Extended frame type
        raise NotImplementedError("Extended Frame is not implemented yet")
