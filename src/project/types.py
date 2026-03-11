import copy

import angr
import archinfo
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
        self.CPU = self._detect_cpu()

        self._define_specs()

        self._apply_symbolic_masks()

    @classmethod
    def _detect_cpu(cls):
        if isinstance(cls.ANGR_ARCH, archinfo.ArchARMCortexM):
            from project.cores.cortex_m.cortex_m import CortexM

            return CortexM()
        return None

    def _define_specs(self):
        pass

    def _apply_symbolic_masks(self):
        for memory_region in self.MEMORY_REGIONS.values():
            memory_region.set_symbolic_mask(self.SYMBOLIC_MASKS)

    def precondition(self, state):
        return True

    def postcondition(self, simgr):
        pass


class BaseCustomGlobals(angr.SimStatePlugin):
    """
    angr 的 globals 不會自己做 deepcopy，如果有必須要 deepcopy 的 globals (e.g., mutable object) 就要放 custom_globals
    """

    def __init__(self, irq=None):
        super().__init__()

        self.irq = {} if irq is None else irq

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        new_plugin = super().copy(memo)

        new_plugin.irq = copy.deepcopy(self.irq, memo)

        return new_plugin
