from __future__ import annotations

import copy
import inspect
import logging
from collections import defaultdict
from functools import cache

import angr
import claripy
from angr.errors import SimMergeError

from project import utils
from project.analyses.memory import ISRTarget
from project.cores.arm.arm import ARM
from project.cores.arm.cortex_m.nvic import NVIC
from project.types import BPConfig, CustomSimStatePlugin, EventForkHandler

logger = logging.getLogger(__name__)


class CortexM(ARM):
    VTOR_ADDR = None

    def setup(self, state, specs, simgr):
        # ARMv7-M Architecture Reference Manual: Exception return behavior
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

        specs.set_handlers(cpu=self, state=state, cfg=cfg, specs=specs)
        self.set_handlers(state=state, cfg=cfg, specs=specs)
        simgr.use_technique(
            self.AsynchronousEventManager(cpu=self, end_addrs=specs.END_ADDRS)
        )

        self.ExceptionGlobals.register_default("excp_globals")

        return cfg

    def thumb_mode(self, registers) -> bool:
        return True

    def excp_entry(self, state, int_no):
        self._push_basic_frame(state)

        state.excp_globals.priority_stack.append(state.excp_globals.current_priority)
        state.excp_globals.current_priority = NVIC.get_irq_priority(state, int_no)

        _, isr_addr = self._get_exception_handler_address(state, int_no)
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

        try:
            state.excp_globals.current_priority = (
                state.excp_globals.priority_stack.pop()
            )
        except IndexError:
            raise Exception("Priority stack underflow")

        return pc

    def _pop(self, state):
        reg = utils.load(state, state.regs.sp)
        state.regs.sp += 4
        return reg

    def _get_vector_table_base(self, state):
        if self.VTOR_ADDR is not None:
            return (
                self._concrete_state_value(
                    state, utils.load(state, self.VTOR_ADDR), "VTOR"
                )
                & 0xFFFFFF80
            )
        return 0x00000000

    def _get_exception_handler_address(self, state, int_no: int):
        excp_no = int_no + 16
        vector_addr = self._get_vector_table_base(state) + (excp_no * state.arch.bytes)
        isr_addr = self._concrete_state_value(
            state,
            utils.load(state, vector_addr),
            f"Cortex-M vector entry for IRQ {int_no}",
        )
        return vector_addr, isr_addr

    def _compute_isr_target(self, state, irq: int) -> ISRTarget:
        vector_addr, isr_addr = self._get_exception_handler_address(state, irq)
        if isr_addr == 0:
            raise ValueError(f"Vector entry for modeled IRQ {irq} is null")
        return ISRTarget(irq=irq, address=isr_addr, source=vector_addr)

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
            logger.warning(
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

    def get_static_interrupt_checkpoints(self, proj, state, cfg, specs):
        ckpts = super().get_static_interrupt_checkpoints(proj, state, cfg, specs)

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
                    proj=state.project, state=state, cfg=cfg, specs=specs
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
                if prio < state.excp_globals.current_priority:
                    eligible_irqs.append((prio, irq, trig_conds))
            self.cpu._sort_irqs(eligible_irqs)
            return [
                (trig_cond, {"irq": irq})
                for _, irq, trig_conds in eligible_irqs
                for trig_cond in trig_conds
            ]

        def trigger_event(self, state, irq):
            self.cpu.excp_entry(state, irq)

    class ExceptionGlobals(CustomSimStatePlugin):
        current_priority: int
        priority_stack: list[int]

        def __init__(self, current_priority=None, priority_stack=None):
            super().__init__()

            self.current_priority = (
                current_priority if current_priority is not None else 256
            )
            self.priority_stack = priority_stack if priority_stack is not None else []

        def copy(self, memo):
            o = super().copy(memo)

            for field in inspect.get_annotations(type(self)):
                setattr(o, field, copy.copy(getattr(self, field)))

            return o

        def _merge_key(self):
            return (self.current_priority, tuple(self.priority_stack))

        def merge(self, others, merge_conditions, common_ancestor=None):
            del common_ancestor

            if any(
                self.current_priority != other.current_priority
                or self.priority_stack != other.priority_stack
                for other in others
            ):
                raise SimMergeError(
                    "Cannot merge Exception globals (current_priority or priority_stack)"
                )

            return False

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

    @classmethod
    def translate_avatar_registers(cls, regs):
        # ARMv7-M Architecture Reference Manual: The special-purpose Program Status Registers, xPSR
        # xpsr is split into multiple registers in angr
        regs["flags"] = regs["xpsr"] & 0xF0000000
        regs["qflag32"] = (regs["xpsr"] >> 27) & 1
        regs["iepsr"] = (regs["xpsr"] & 0x1FF) | (regs["xpsr"] & (1 << 24))
        regs["itstate"] = (((regs["xpsr"] >> 10) & 0x3F) << 2) | (
            (regs["xpsr"] >> 25) & 0x3
        )
        regs.pop("xpsr", None)

        return regs
