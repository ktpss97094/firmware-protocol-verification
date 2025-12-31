from __future__ import annotations
import claripy
from dataclasses import dataclass
from angr.sim_type import SimTypeInt, SimTypeFunction


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

    def __init__(self):
        self._arg_symbolic = {}

    @classmethod
    def get_cls(cls) -> SymbolicPolicy:
        return cls()

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
