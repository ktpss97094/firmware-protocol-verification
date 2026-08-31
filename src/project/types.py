from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from functools import partial
from typing import Any, Callable, Optional

import angr
import archinfo
from angr import SimStatePlugin
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
from angr.sim_state import SimState

from project import utils


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


class CustomSimStatePlugin(SimStatePlugin):
    def _merge_key(self):
        """
        Return the merge key that must match before states containing this plugin may attempt to merge.

        Subclasses can optionally override this method.
        """

        return ()


class AccessType(Enum):
    RW = auto()
    R = auto()
    W = auto()
    RC_W0 = auto()  # read or clear on write 0


@dataclass(frozen=True)
class MemoryEffect:
    operation: str
    start: int
    size: int

    @property
    def end(self):
        return self.start + self.size

    def overlaps(self, other):
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class PluginEffect:
    operation: str
    plugin: str
    fields: tuple[str, ...] = ("*",)

    def overlaps(self, other):
        if self.plugin != other.plugin:
            return False
        return (
            "*" in self.fields
            or "*" in other.fields
            or not set(self.fields).isdisjoint(other.fields)
        )


@dataclass(frozen=True)
class AccessEffects:
    memory: frozenset[MemoryEffect] = frozenset()
    plugins: frozenset[PluginEffect] = frozenset()

    @classmethod
    def memory_access(cls, operation, start, size):
        return cls(
            memory=frozenset(
                {MemoryEffect(operation=operation, start=start, size=max(1, size))}
            )
        )

    def union(self, *others):
        memory = set(self.memory)
        plugins = set(self.plugins)
        for other in others:
            memory.update(other.memory)
            plugins.update(other.plugins)
        return AccessEffects(frozenset(memory), frozenset(plugins))

    def conflicts_with(self, other):
        for left in self.memory:
            for right in other.memory:
                if "write" in (left.operation, right.operation) and left.overlaps(
                    right
                ):
                    return True

        for left in self.plugins:
            for right in other.plugins:
                if "write" in (left.operation, right.operation) and left.overlaps(
                    right
                ):
                    return True

        return False


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
        spec: BaseSpec,
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

    def get_access_effects(self, operation, address, size):
        return AccessEffects.memory_access(operation, address, size)


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

    def pre_write(self, state):
        addr, offset, value = super().pre_write(state)

        byte_offset = offset % state.arch.bytes
        register_addr = addr - byte_offset
        register_value = utils.load(state, register_addr)
        value_bits = value.size()
        bit_offset = byte_offset * state.arch.byte_width
        if state.arch.memory_endness == archinfo.Endness.BE:
            bit_offset = (
                state.arch.bits - value_bits - byte_offset * state.arch.byte_width
            )
        orig_value = register_value[bit_offset + value_bits - 1 : bit_offset]
        masked_value = self.mask_pre_write(offset, orig_value, value)
        state.inspect.mem_write_expr = masked_value
        state.globals[("_mmio_pending_write", id(self))] = (
            addr,
            masked_value,
            state.inspect.mem_write_length,
            state.inspect.mem_write_condition,
            state.inspect.mem_write_endness,
        )

        return addr, offset, state.inspect.mem_write_expr

    def post_write(self, state):
        addr, offset, value = super().post_write(state)
        pending = state.globals.pop(("_mmio_pending_write", id(self)), None)
        if pending is None:
            return addr, offset, value

        pending_addr, masked_value, size, condition, endness = pending
        if pending_addr != addr:
            raise SimEngineError(
                f"Mismatched pending MMIO write: {pending_addr:#x} != {addr:#x}"
            )

        state.memory.store(
            addr,
            masked_value,
            size=size if size is not None else masked_value.length // 8,
            condition=condition,
            endness=endness,
            disable_actions=True,
            inspect=False,
        )
        state.inspect.mem_write_expr = masked_value
        return addr, offset, masked_value

    def _get_access_masks(self, offset, value_bits):
        register_offset = offset - (offset % 4)
        masks = self._access_masks.get(register_offset)
        if masks is None:
            return None

        bit_offset = (offset - register_offset) * 8
        value_mask = (1 << value_bits) - 1
        return tuple((mask >> bit_offset) & value_mask for mask in masks)

    def mask_pre_write(self, offset, orig_val, write_val):
        masks = self._get_access_masks(offset, write_val.size())
        if masks:
            mask_rw, mask_r, mask_w, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_w | mask_rc_w0
            undefined_mask = ((1 << write_val.size()) - 1) ^ defined_mask

            return (
                (write_val & mask_rw)
                | (orig_val & mask_r)
                | (write_val & mask_w)
                | (orig_val & write_val & mask_rc_w0)
                | (write_val & undefined_mask)
            )
        return write_val

    def mask_post_read(self, offset, val):
        masks = self._get_access_masks(offset, val.size())
        if masks:
            mask_rw, mask_r, mask_w, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_w | mask_rc_w0
            undefined_mask = ((1 << val.size()) - 1) ^ defined_mask
            register_offset = offset - (offset % 4)
            bit_offset = (offset - register_offset) * 8
            reset_value = (self._rst_vals[register_offset] >> bit_offset) & (
                (1 << val.size()) - 1
            )

            return (
                (val & (mask_rw | mask_r | mask_rc_w0))
                | (
                    reset_value
                    & (
                        mask_w | undefined_mask
                    )  # TODO: mask_w 也許可改成 base class 用 symbolic、derived class 再依照 reference manual 上的說明實作是否有明說回傳的是 reset value
                )
            )
        return val

    def get_pending_irqs(self, state):
        """
        回傳此 peripheral 目前可能觸發的 IRQ
        格式: [(trigger condition, kwargs), ...]
        """
        return []

    def set_handlers(self, cpu, state, cfg, specs):
        return


class VariableMemoryRegion(MemoryRegion):
    pass


class BaseSpec:
    BOUND_LOOPS = {}
    PROPERTY_NAMES = []

    def __init__(self, proj):
        super().__init__()

        self.proj = proj
        self.MEMORY_REGIONS = {}
        self.BEGIN_ADDR = None
        self.END_ADDRS = []
        self.API_PROTOTYPE = None
        self.API_ARGS = []
        self.CPU = self.ARCH()

        self._define_specs()

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

    def get_DMAs(self):
        from project.cores.base import BaseDMA

        return [r for r in self.MEMORY_REGIONS.values() if isinstance(r, BaseDMA)]

    def get_memory_region(self, address):
        matches = [
            region
            for region in self.MEMORY_REGIONS.values()
            if region.in_region(address)
        ]
        return min(matches, key=lambda region: region.size) if matches else None

    def get_access_effects(self, operation, address, size):
        region = self.get_memory_region(address)
        if region is None:
            return AccessEffects.memory_access(operation, address, size)
        return region.get_access_effects(operation, address, size)

    def set_handlers(self, cpu, state, cfg, specs):
        for region in self.get_MMIOMemoryRegions():
            region.set_handlers(cpu=cpu, state=state, cfg=cfg, specs=specs)


class EventForkHandler:
    NO_EVENT_CONSTRAINS_STATE = True

    def get_checkpoints(self):
        return set()

    def get_eligible_events(self, state):
        """
        Return:
            [(trigger conditions, handler kwargs), ...]
        """
        return []

    def trigger_event(self, state, **kwargs):
        """
        對 state 執行該事件的行為
        """
        pass


class BPConfig:
    def __init__(
        self,
        event_type: str,
        when: str = angr.BP_BEFORE,
        enabled: bool = True,
        condition: Optional[Callable[[SimState], bool]] = None,
        **kwargs: Any,
    ):
        self.event_type = event_type
        self.when = when
        self.enabled = enabled
        self.condition = condition
        self.action = self._bp_action
        self.kwargs = kwargs

    def __eq__(self, other):
        if not isinstance(other, BPConfig):
            return False
        return (
            self.event_type == other.event_type
            and self.when == other.when
            and self.enabled == other.enabled
            and self.kwargs == other.kwargs
        )

    def __hash__(self):
        kwargs_signature = tuple(sorted(self.kwargs.items()))

        return hash((self.event_type, self.when, self.enabled, kwargs_signature))

    def apply_to(self, state: SimState, handler: EventForkHandler):
        state.inspect.b(
            self.event_type,
            when=self.when,
            enabled=self.enabled,
            condition=self.condition,
            action=partial(self.action, handler=handler),
            **self.kwargs,
        )

    def _bp_action(self, state, handler):
        match self.when:
            case angr.BP_BEFORE:
                if handler not in state.asynevt_globals.prev_after_check_handlers:
                    state.asynevt_globals.before_check_handlers.add(handler)
            case angr.BP_AFTER:
                state.asynevt_globals.after_check_handlers.add(handler)
