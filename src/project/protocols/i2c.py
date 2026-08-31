import inspect

import claripy

from project import utils
from project.types import CustomSimStatePlugin


class I2CBus(CustomSimStatePlugin):
    prev_scl_in: claripy.ast.Bool
    prev_sda_in: claripy.ast.Bool
    prev_scl_out: claripy.ast.Bool
    prev_sda_out: claripy.ast.Bool
    arbitration_lost: claripy.ast.Bool
    bit_count: claripy.ast.BV
    arbitration_lost_byte_end: claripy.ast.Bool
    wait_state: claripy.ast.Bool

    def __init__(
        self,
        prev_scl_in=None,
        prev_sda_in=None,
        prev_scl_out=None,
        prev_sda_out=None,
        arbitration_lost=None,
        bit_count=None,
        arbitration_lost_byte_end=None,
        wait_state=None,
    ):
        super().__init__()

        self.prev_scl_in = claripy.true() if prev_scl_in is None else prev_scl_in
        self.prev_sda_in = claripy.true() if prev_sda_in is None else prev_sda_in
        self.prev_scl_out = claripy.true() if prev_scl_out is None else prev_scl_out
        self.prev_sda_out = claripy.true() if prev_sda_out is None else prev_sda_out
        self.arbitration_lost = (
            claripy.false() if arbitration_lost is None else arbitration_lost
        )
        self.bit_count = claripy.BVV(0, 4) if bit_count is None else bit_count
        self.arbitration_lost_byte_end = (
            claripy.false()
            if arbitration_lost_byte_end is None
            else arbitration_lost_byte_end
        )
        self.wait_state = claripy.false() if wait_state is None else wait_state

    def copy(self, memo):
        o = super().copy(memo)

        for field in inspect.get_annotations(type(self)):
            setattr(o, field, getattr(self, field))

        return o

    def merge(self, others, merge_conditions, common_ancestor=None):
        del common_ancestor

        changed = False

        for field in inspect.get_annotations(type(self)):
            value = getattr(self, field)

            merged_value = utils.merge_ast_values(
                self.state,
                value,
                (getattr(other, field) for other in others),
                merge_conditions,
            )

            if not utils.same_ast(value, merged_value):
                setattr(self, field, merged_value)
                changed = True

        return changed
