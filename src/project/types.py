import copy
from dataclasses import dataclass
from enum import Enum, auto

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


class AccessType(Enum):
    RW = auto()
    R = auto()
    RC_W0 = auto()  # read or clear on write 0


@dataclass(frozen=True)
class BitField:
    bit: int
    access_type: AccessType
    size: int = 1

    @property
    def mask(self) -> int:
        return ((1 << self.size) - 1) << self.bit


class BaseRegister:
    OFFSET = -1


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

    def pre_read(self, state):
        raise NotImplementedError("Call abstract method")

    def pre_write(self, state):
        raise NotImplementedError("Call abstract method")

    def post_read_spec(self, state, offset):
        pass

    def post_write_spec(self, state, offset, value):
        pass

    def post_read(self, state):
        raise NotImplementedError("Call abstract method")

    def post_write(self, state):
        raise NotImplementedError("Call abstract method")

    def in_region(self, addr):
        return self.start <= addr < self.start + self.size

    def in_region_read(self, state):
        try:
            return self.in_region(state.solver.eval(state.inspect.mem_read_address))
        except Exception:
            return False

    def in_region_write(self, state):
        try:
            return self.in_region(state.solver.eval(state.inspect.mem_write_address))
        except Exception:
            return False


class MMIOMemoryRegion(MemoryRegion):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._write_masks = {}  # {offset: (MASK_RW, MASK_R, MASK_RC_W0)}

        for name in dir(self.__class__):
            value = getattr(self.__class__, name)

            if (
                isinstance(value, type)
                and issubclass(value, BaseRegister)
                and getattr(value, "OFFSET") != -1
            ):
                mask_rw, mask_r, mask_rc_w0 = 0, 0, 0

                for _, attr_val in vars(value).items():
                    if isinstance(attr_val, BitField):
                        if attr_val.access_type == AccessType.RW:
                            mask_rw |= attr_val.mask
                        elif attr_val.access_type == AccessType.R:
                            mask_r |= attr_val.mask
                        elif attr_val.access_type == AccessType.RC_W0:
                            mask_rc_w0 |= attr_val.mask

                self._write_masks[value.OFFSET] = (mask_rw, mask_r, mask_rc_w0)

    def mask_write(self, offset, orig_val, write_val):
        masks = self._write_masks.get(offset)
        if masks:
            mask_rw, mask_r, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_rc_w0
            undefined_mask = ~defined_mask

            return (
                (write_val & mask_rw)
                | (orig_val & mask_r)
                | (orig_val & write_val & mask_rc_w0)
                | (write_val & undefined_mask)
            )
        return write_val

    def get_pending_irqs(self, state):
        """
        回傳此 peripheral 目前可能觸發的 IRQ
        格式: {irq_number: [(trigger_var, trigger_cond), ...]}
        """
        return {}


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

    @classmethod
    def _detect_cpu(cls):
        if isinstance(cls.ANGR_ARCH, archinfo.ArchARMCortexM):
            from project.cores.arm.cortex_m.cortex_m import CortexM

            return CortexM()
        return None

    def _define_specs(self):
        pass

    def init_inspect(self, state):
        pass

    def init_input(self, state):
        pass

    def final(self, simgr):
        pass

    def get_MMIOMemoryRegions(self):
        return [
            r for r in self.MEMORY_REGIONS.values() if isinstance(r, MMIOMemoryRegion)
        ]


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
