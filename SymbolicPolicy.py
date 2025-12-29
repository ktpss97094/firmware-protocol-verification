from __future__ import annotations
import claripy
from dataclasses import dataclass
from typing import Dict, Optional
from angr.sim_type import SimTypeInt, SimTypeFunction
from EFSM import I2C


@dataclass(frozen=True)
class BoundedSymbolicInt:
    name: str
    bits: int
    lo: int
    hi: int

    def build(self):
        sym = claripy.BVS(self.name, self.bits)
        constraints = [sym >= self.lo, sym <= self.hi]
        return sym, constraints


class SymbolicPolicy:
    """
    集中管理 symbolic 來源

    1. MMIO bits symbolic
    2. Function args symbolic
    """

    def __init__(
        self,
        *,
        mmio_state_symbolic,
    ):
        self._mmio_state_symbolic = (
            mmio_state_symbolic if mmio_state_symbolic is not None else {}
        )
        self._arg_symbolic = {}

    @classmethod
    def get_state_symbolic_cls(cls) -> SymbolicPolicy:
        return cls(
            mmio_state_symbolic={
                "IDLE": {},
                "SB_WAIT": {I2C.SR1_OFFSET: I2C.SR1_SB_MASK},
                "ADDR_WAIT": {I2C.SR1_OFFSET: I2C.SR1_ADDR_MASK},
                "TXE_SET_SRE_WRITE_DR": {
                    I2C.SR1_OFFSET: I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK
                },
                "TXE_SET_SRNE_WRITE_DR": {
                    I2C.SR1_OFFSET: I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK
                },
                "BTF_SET": {},
            }
        )

    def mmio_symbolic_mask(self, fsm_state, offset):
        return self._mmio_state_symbolic.get(fsm_state, {}).get(offset, 0)

    def add_mmio_symbolic(self, fsm_state, offset, mask) -> None:
        state_map = self._mmio_state_symbolic.setdefault(fsm_state, {})
        state_map[offset] = state_map.get(offset, 0) | mask

    def set_bounded_arg(self, *, index, name, bits, lo, hi):
        self._arg_symbolic[index] = BoundedSymbolicInt(
            name=name, bits=bits, lo=lo, hi=hi
        )

    def apply_function_args(self, *, proj, state, arg_count):
        """
        把 function 參數設為 symbolic
        """

        if not self._arg_symbolic:
            return

        cc = proj.factory.cc()
        prototype = SimTypeFunction([SimTypeInt()] * arg_count, SimTypeInt())
        arg_locs = cc.arg_locs(prototype)

        for index, spec in self._arg_symbolic.items():
            if index < 0 or index >= arg_count:
                raise ValueError(
                    f"Arg index {index} out of range for arg_count={arg_count}"
                )

            sym, constraints = spec.build()
            state.add_constraints(*constraints)
            arg_locs[index].set_value(state, sym)
