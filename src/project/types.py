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

    def __init_subclass__(cls, *args, **kwargs):
        super().__init_subclass__(*args, **kwargs)

        # --- read() wrapper ---
        if getattr(cls, "_read_is_wrapped", False) or "read" not in cls.__dict__:
            return
        orig_read = cls.__dict__["read"]

        def wrapped_read(self, state):
            addr = state.solver.eval(state.inspect.mem_read_address)
            offset = addr - self.start
            orig_read(self, state, offset)
            # if isinstance(self, MMIOMemoryRegion):
            #     self._apply_symbolic(state, offset)

        cls.read = wrapped_read
        cls._read_is_wrapped = True

        # --- write() wrapper ---
        if getattr(cls, "_write_is_wrapped", False) or "write" not in cls.__dict__:
            return
        orig_write = cls.__dict__["write"]

        def wrapped_write(self, state):
            addr = state.solver.eval(state.inspect.mem_write_address)
            offset = addr - self.start
            value = state.inspect.mem_write_expr
            orig_write(self, state, offset, value)

        cls.write = wrapped_write
        cls._write_is_wrapped = True

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

    def read(self, state, offset):
        raise NotImplementedError("Call abstract method")

    def write(self, state, offset, value):
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
