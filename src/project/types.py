from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto

import angr
import archinfo
from angr.engines import (
    HooksMixin,
    SimEngineFailure,
    SimEngineSyscall,
    SimEngineUnicorn,
)
from angr.engines.vex import (
    HeavyResilienceMixin,
    HeavyVEXMixin,
    SimInspectMixin,
    SuperFastpathMixin,
)
from angr.errors import SimEngineError


class CustomEngine(
    SimEngineFailure,
    SimEngineSyscall,
    HooksMixin,
    SuperFastpathMixin,
    # TrackActionsMixin,
    SimInspectMixin,
    HeavyResilienceMixin,
    # SootMixin,
    # AILMixin,
    SimEngineUnicorn,
    HeavyVEXMixin,
):
    pass


class Violation(SimEngineError):
    pass


class AccessType(Enum):
    RW = auto()
    R = auto()
    W = auto()
    RC_W0 = auto()  # read or clear on write 0


@dataclass(frozen=True)
class BitsField:
    bit: int
    access_type: AccessType
    rst_val: int
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
        spec: BaseSpecs,
        physical_addr: int | None = None,
        transfer: bool = True,
        name: str = "",
    ):
        super().__init__()

        self.start = start
        self.size = size
        self.spec = spec
        self.physical_addr = physical_addr if physical_addr is not None else start
        self.transfer = transfer
        self.name = name

    def pre_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        return addr, offset

    def pre_write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        return addr, offset, value

    def post_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start
        readout_value = state.inspect.mem_read_expr

        return addr, offset, readout_value

    def post_write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        return addr, offset, value

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

        self._access_masks = {}  # {offset: (rw mask, r mask, w mask, rc_w0 mask)}
        self._rst_vals = {}  # {offset: rst_val}

        for name in dir(self.__class__):
            value = getattr(self.__class__, name)

            if (
                isinstance(value, type)
                and issubclass(value, BaseRegister)
                and getattr(value, "OFFSET") != -1
            ):
                mask_rw, mask_r, mask_w, mask_rc_w0 = 0, 0, 0, 0
                rst_val = 0

                for _, attr_val in vars(value).items():
                    if isinstance(attr_val, BitsField):
                        if attr_val.access_type == AccessType.RW:
                            mask_rw |= attr_val.mask
                        elif attr_val.access_type == AccessType.R:
                            mask_r |= attr_val.mask
                        elif attr_val.access_type == AccessType.W:
                            mask_w |= attr_val.mask
                        elif attr_val.access_type == AccessType.RC_W0:
                            mask_rc_w0 |= attr_val.mask

                        rst_val |= attr_val.rst_val << attr_val.bit

                self._access_masks[value.OFFSET] = (mask_rw, mask_r, mask_w, mask_rc_w0)
                self._rst_vals[value.OFFSET] = rst_val

    def mask_pre_write(self, offset, orig_val, write_val):
        masks = self._access_masks.get(offset)
        if masks:
            mask_rw, mask_r, mask_w, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_w | mask_rc_w0
            undefined_mask = ~defined_mask

            return (
                (write_val & mask_rw)
                | (orig_val & mask_r)
                | (write_val & mask_w)
                | (orig_val & write_val & mask_rc_w0)
                | (write_val & undefined_mask)
            )
        return write_val

    def mask_post_read(self, offset, val):
        masks = self._access_masks.get(offset)
        if masks:
            mask_rw, mask_r, mask_w, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_w | mask_rc_w0
            undefined_mask = ~defined_mask

            return (
                (val & (mask_rw | mask_r | mask_rc_w0))
                | (
                    self._rst_vals[offset]
                    & (
                        mask_w | undefined_mask
                    )  # TODO: mask_w 也許可改成 base class 用 symbolic、derived class 再依照 reference manual 上的說明實作是否有明說回傳的是 reset value
                )
            )
        return val

    def get_pending_irqs(self, state):
        """
        回傳此 peripheral 目前可能觸發的 IRQ
        格式: {irq_number: [(trigger_var, trigger_cond), ...]}
        """
        return {}

    def set_handlers(self, cpu, proj, cfg, specs):
        return []


class VariableMemoryRegion(MemoryRegion):
    pass


class BaseSpecs:
    LOOP_BOUND = 10
    BOUND_LOOP_FUNCTIONS = []

    def __init__(self, proj):
        super().__init__()

        self.proj = proj
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

    def set_handlers(self, cpu, proj, cfg, specs):
        checkpoints_list = []

        for region in self.get_MMIOMemoryRegions():
            checkpoints_list.extend(
                region.set_handlers(cpu=cpu, proj=proj, cfg=cfg, specs=specs)
            )
        return checkpoints_list


class BaseCustomGlobals(angr.SimStatePlugin):
    """
    angr 的 globals 不會自己做 deepcopy，如果有必須要 deepcopy 的 globals (e.g., mutable object) 就要放 custom_globals
    """

    def __init__(self):
        super().__init__()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        new_plugin = super().copy(memo)

        return new_plugin


class EventForkHandler:
    def get_checkpoints(self):
        """
        Return:
            {address: "inst_before"/"inst_after"}
        """
        return {}

    def get_eligible_events(self, state):
        """
        Return:
            [(event information, trigger conditions), ...]
        """
        return []

    def trigger_event(self, state, event_info):
        """
        對 state 執行該事件的行為
        """
        pass
