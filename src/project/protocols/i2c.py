import claripy
from angr.state_plugins.plugin import SimStatePlugin

from project import utils


class I2CBus(SimStatePlugin):
    _MERGE_FIELDS = (
        "prev_scl_in",
        "prev_sda_in",
        "prev_scl_out",
        "prev_sda_out",
        "arbitration_lost",
        "bit_count",
        "arbitration_lost_byte_end",
        "wait_state",
    )

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

        o.prev_scl_in = self.prev_scl_in
        o.prev_sda_in = self.prev_sda_in
        o.prev_scl_out = self.prev_scl_out
        o.prev_sda_out = self.prev_sda_out
        o.arbitration_lost = self.arbitration_lost
        o.bit_count = self.bit_count
        o.arbitration_lost_byte_end = self.arbitration_lost_byte_end
        o.wait_state = self.wait_state

        return o

    def merge_key(self):
        return ()

    def merge(self, others, merge_conditions, common_ancestor=None):
        del common_ancestor

        changed = False

        for field in self._MERGE_FIELDS:
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
