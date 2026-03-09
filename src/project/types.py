import copy

import angr
import claripy
from angr.engines import HooksMixin, SimEngineFailure, SimEngineSyscall
from angr.engines.vex import (
    HeavyResilienceMixin,
    HeavyVEXMixin,
    SimInspectMixin,
    SuperFastpathMixin,
    TrackActionsMixin,
)

from project import utils


class CustomEngine(
    SimEngineFailure,
    SimEngineSyscall,
    HooksMixin,
    SuperFastpathMixin,
    TrackActionsMixin,
    SimInspectMixin,
    HeavyResilienceMixin,
    # SootMixin,
    # AILMixin,
    # SimEngineUnicorn,
    HeavyVEXMixin,
):
    pass


class CustomLoopLimiter(angr.ExplorationTechnique):
    def __init__(self, limit=100, max_concrete_limit=100000, discard_stash="spinning"):
        super(CustomLoopLimiter, self).__init__()
        self.limit = limit
        self.max_concrete_limit = (
            max_concrete_limit  # 給正常迴圈一個超大的上限，避免真的跑太久
        )
        self.discard_stash = discard_stash

    def step(self, simgr, stash="active", **kwargs):
        new_active = []
        # 建立(或取得)一個用於存放被砍掉的狀態的 stash
        simgr.stashes.setdefault(self.discard_stash, [])

        for state in simgr.stashes[stash]:
            # 取得當前基本塊的執行次數
            # 注意：state.addr 是當前 Instruction Pointer
            loop_count = list(state.history.bbl_addrs).count(state.addr)

            if loop_count > self.limit:
                # --- 關鍵判斷：是「運算迴圈」還是「等待迴圈」？ ---

                # 取得導致跳轉回來的那個條件 (Guard)
                # 我們嘗試檢查最後一個跳轉的條件是否依賴於符號變數
                try:
                    last_guard = state.history.jump_guards[-1]
                    is_symbolic = state.solver.symbolic(last_guard)
                except (IndexError, AttributeError):
                    # 如果找不到 guard (極少見)，保守起見假設它是具體的
                    is_symbolic = False

                if is_symbolic:
                    # [情況 3] 符號迴圈 (Polling) -> 這是你要殺的
                    # 條件不明確 (依賴 Input)，且已經跑了 100 次，判定為無窮等待
                    # print(f"砍掉 Polling: {hex(state.addr)}")
                    simgr.stashes[self.discard_stash].append(state)
                    continue

                else:
                    # [情況 1] 具體迴圈 (Normal Loop / while(1)) -> 這是你要留的
                    # 條件是確定的 (例如 loop counter)，只是跑比較多次

                    # 為了防止真正的死結 (while(1)) 跑道天荒地老，我們還是設一個極限
                    if loop_count > self.max_concrete_limit:
                        # print(f"砍掉過長的具體迴圈: {hex(state.addr)}")
                        simgr.stashes[self.discard_stash].append(state)
                        continue

                    # 否則，放行！讓它繼續跑
                    pass

            new_active.append(state)

        simgr.stashes[stash] = new_active
        return simgr.step(stash=stash, **kwargs)


class InterruptInjector(angr.ExplorationTechnique):
    def __init__(self, specs, vector_table_base):
        super().__init__()
        self.specs = specs
        self.vector_table_base = vector_table_base

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

        from project.peripherals.nrf52840.twi import TWI as NRF52840_TWI

        IRQ_triggers = {3: []}

        # IRQ 3
        if 3 not in state.globals["IRQ"]:
            state.globals["IRQ"][3] = {"handled_hashes": frozenset()}
        intenset = utils.load(
            state,
            self.specs.MEMORY_REGIONS["TWI0"].start + NRF52840_TWI.INTENSET.OFFSET,
        )

        if state.solver.is_true(intenset[NRF52840_TWI.INTENSET.STOPPED] == 1):
            events_stopped_bit = utils.load(
                state,
                self.specs.MEMORY_REGIONS["TWI0"].start
                + NRF52840_TWI.EVENTS_STOPPED.OFFSET,
            )[NRF52840_TWI.EVENTS_STOPPED.EVENTS_STOPPED]

            trigger_cond = events_stopped_bit != 0
            if hash(events_stopped_bit) not in state.globals["IRQ"][3][
                "handled_hashes"
            ] and state.solver.satisfiable(extra_constraints=[trigger_cond]):
                IRQ_triggers[3].append((events_stopped_bit, trigger_cond))
        if state.solver.is_true(intenset[NRF52840_TWI.INTENSET.TXDSENT] == 1):
            events_txdsent_bit = utils.load(
                state,
                self.specs.MEMORY_REGIONS["TWI0"].start
                + NRF52840_TWI.EVENTS_TXDSENT.OFFSET,
            )[NRF52840_TWI.EVENTS_TXDSENT.EVENTS_TXDSENT]

            trigger_cond = events_txdsent_bit != 0
            if hash(events_txdsent_bit) not in state.globals["IRQ"][3][
                "handled_hashes"
            ] and state.solver.satisfiable(extra_constraints=[trigger_cond]):
                IRQ_triggers[3].append((events_txdsent_bit, trigger_cond))
        if state.solver.is_true(intenset[NRF52840_TWI.INTENSET.ERROR] == 1):
            events_error_bit = utils.load(
                state,
                self.specs.MEMORY_REGIONS["TWI0"].start
                + NRF52840_TWI.EVENTS_ERROR.OFFSET,
            )[NRF52840_TWI.EVENTS_ERROR.EVENTS_ERROR]

            trigger_cond = events_error_bit != 0
            if hash(events_error_bit) not in state.globals["IRQ"][3][
                "handled_hashes"
            ] and state.solver.satisfiable(extra_constraints=[trigger_cond]):
                IRQ_triggers[3].append((events_error_bit, trigger_cond))

        # 其他 IRQ ...

        if all(not v for v in IRQ_triggers.values()):  # 所有 element 都是空的
            return simgr.step_state(state, **kwargs)

        # 計算目前 priority 最大的 IRQ
        best_IRQ = min(
            IRQ_triggers.keys(), key=lambda k: (self.get_irq_priority(state, k), k)
        )
        if self.get_irq_priority(state, best_IRQ) >= state.globals.get(
            "current_priority", 256
        ):
            return simgr.step_state(state, **kwargs)

        merged_results = {}
        negated_previous_conds = []

        # 分支 1
        for trigger_var, trigger_cond in IRQ_triggers[best_IRQ]:
            isr_state = state.copy()
            isr_state.globals["IRQ"] = copy.deepcopy(state.globals["IRQ"])

            isr_state.add_constraints(trigger_cond)
            for neg_cond in negated_previous_conds:
                isr_state.add_constraints(neg_cond)

            if isr_state.satisfiable():
                isr_handled_hashes = set(
                    isr_state.globals["IRQ"][best_IRQ]["handled_hashes"]
                )
                isr_handled_hashes.add(hash(trigger_var))
                isr_state.globals["IRQ"][best_IRQ]["handled_hashes"] = frozenset(
                    isr_handled_hashes
                )

                self._excp_entry(isr_state, best_IRQ)

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

    def get_irq_priority(self, state, irq_number):
        return state.solver.eval(
            utils.load(state, 0xE000E400 + irq_number, size=1)[7:4]
        )

    def is_in_handler_mode(self, state):
        ipsr = state.regs.iepsr & 0x1FF
        return state.solver.is_true(ipsr > 0)

    """
    以下改編自 AIM code
    """

    def _excp_entry(self, s, int_no):
        # Basic frame type
        # TODO: Extended frame type
        # ARMv7-M Architecture Reference Manual B1.5.6 Exception entry behavior
        self._push(s, s.regs.iepsr)  # TODO: push iepsr 是不精確的，要看 B1.5.6 的行為
        self._push(s, s.regs.pc)
        self._push(s, s.regs.lr)
        self._push(s, s.regs.r12)
        self._push(s, s.regs.r3)
        self._push(s, s.regs.r2)
        self._push(s, s.regs.r1)
        self._push(s, s.regs.r0)

        priority_stack = s.globals.get("priority_stack", []).copy()
        priority_stack.append(s.globals.get("current_priority", 256))
        s.globals["priority_stack"] = priority_stack
        s.globals["current_priority"] = self.get_irq_priority(s, int_no)

        # 計算 ISR 的 address
        excp_no = int_no + 16
        vector_addr = self.vector_table_base + (excp_no * 4)
        isr_addr = s.solver.eval(utils.load(s, vector_addr))

        s.regs.pc = isr_addr
        s.regs.lr = 0xFFFFFFF1 if self.is_in_handler_mode(s) else 0xFFFFFFF9

    def _push(self, s, reg):
        s.regs.sp -= 4
        utils.store(s, s.regs.sp, reg)


class ExcpReturnProcedure(angr.SimProcedure):
    NO_RET = True

    def run(self):
        self.state.regs.r0 = self._pop()
        self.state.regs.r1 = self._pop()
        self.state.regs.r2 = self._pop()
        self.state.regs.r3 = self._pop()
        self.state.regs.r12 = self._pop()
        self.state.regs.lr = self._pop()
        pc = self._pop()
        self.state.regs.iepsr = self._pop()

        priority_stack = self.state.globals.get("priority_stack", []).copy()
        try:
            self.state.globals["current_priority"] = priority_stack.pop()
            self.state.globals["priority_stack"] = priority_stack
        except IndexError:
            raise Exception("Priority stack underflow")

        self.successors.add_successor(self.state, pc, claripy.true(), "Ijk_Boring")

    def _pop(self):
        reg = utils.load(self.state, self.state.regs.sp)
        self.state.regs.sp += 4
        return reg


class MemoryRegion:
    def __init__(
        self,
        start: int,
        size: int,
        physical_addr: int | None = None,
        transfer: bool = True,
        name: str = "",
    ):
        super().__init__()

        self.start = start
        self.size = size
        self.physical_addr = physical_addr if physical_addr is not None else start
        self.transfer = transfer
        self.name = name
        self.symbolic_masks = {}

    # def __init_subclass__(cls, *args, **kwargs):
    #     super().__init_subclass__(*args, **kwargs)

    #     # --- read() wrapper ---
    #     if getattr(cls, "_read_is_wrapped", False) or "read" not in cls.__dict__:
    #         return
    #     orig_read = cls.__dict__["read"]

    #     def wrapped_read(self, state):
    #         addr = state.solver.eval(state.inspect.mem_read_address)
    #         offset = addr - self.start
    #         orig_read(self, state, offset)
    #         # if isinstance(self, MMIOMemoryRegion):
    #         #     self._apply_symbolic(state, offset)

    #     cls.read = wrapped_read
    #     cls._read_is_wrapped = True

    #     # --- write() wrapper ---
    #     if getattr(cls, "_write_is_wrapped", False) or "write" not in cls.__dict__:
    #         return
    #     orig_write = cls.__dict__["write"]

    #     def wrapped_write(self, state):
    #         addr = state.solver.eval(state.inspect.mem_write_address)
    #         offset = addr - self.start
    #         value = state.inspect.mem_write_expr
    #         orig_write(self, state, offset, value)

    #     cls.write = wrapped_write
    #     cls._write_is_wrapped = True

    def _apply_symbolic(self, state, offset):
        symbolic_mask = self.symbolic_masks.get(self.start + offset, 0)
        if symbolic_mask == 0:
            return

        prev_val = utils.load(state, self.start + offset)
        for i in range(state.arch.bits):
            mask = symbolic_mask & (1 << i)
            # 如果值是 symbolic，且有被 constraint 過，就不再新增一個新的 symbolic variable
            if (
                mask
                and prev_val[i].symbolic
                and not (
                    state.solver.min(prev_val[i]) == 0
                    and state.solver.max(prev_val[i]) == ((1 << prev_val[i].size()) - 1)
                )
            ):
                symbolic_mask &= ~(1 << i)

        state.inspect.mem_read_expr = utils.set_symbolic(
            state, self.start + offset, symbolic_mask, f"{self.name}_{offset:#x}"
        )

    def pre_read(self, state, offset):
        pass

    def pre_write(self, state, offset, value):
        pass

    def read(self, state):
        raise NotImplementedError("Call abstract method")

    def write(self, state):
        raise NotImplementedError("Call abstract method")

    def in_region_read(self, state):
        try:
            addr = state.solver.eval(state.inspect.mem_read_address)
            return self.start <= addr < self.start + self.size
        except Exception:
            return False

    def in_region_write(self, state):
        try:
            addr = state.solver.eval(state.inspect.mem_write_address)
            return self.start <= addr < self.start + self.size
        except Exception:
            return False

    def set_symbolic_mask(self, global_symbolic_mask):
        """
        只挑出屬於此 memory region 的 symbolic mask
        """

        for addr, mask in global_symbolic_mask.items():
            if self.start <= addr < (self.start + self.size):
                self.symbolic_masks[addr] = mask


class MMIOMemoryRegion(MemoryRegion):
    pass


class VariableMemoryRegion(MemoryRegion):
    pass


class BaseSpecs:
    def __init__(self, proj):
        super().__init__()

        self.proj = proj
        self.SYMBOLIC_MASKS = {}
        self.MEMORY_REGIONS = {}
        self.BEGIN_ADDR = None
        self.END_ADDRS = []
        self.API_PROTOTYPE = None
        self.API_ARGS = []

        self._define_specs()

        self._apply_symbolic_masks()

    def _define_specs(self):
        pass

    def _apply_symbolic_masks(self):
        for memory_region in self.MEMORY_REGIONS.values():
            memory_region.set_symbolic_mask(self.SYMBOLIC_MASKS)

    def precondition(self, state):
        return True

    def postcondition(self, simgr):
        pass
