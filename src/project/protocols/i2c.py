import claripy
from angr.errors import SimMergeError
from angr.state_plugins.plugin import SimStatePlugin

from project import utils


class I2CBus(SimStatePlugin):
    def __init__(
        self,
        prev_scl_out=None,
        arbitration_lost=None,
        bit_count=None,
        arbitration_lost_byte_end=None,
        wait_state=None,
    ):
        super().__init__()

        self.prev_scl_out = claripy.true() if prev_scl_out is None else prev_scl_out
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

        o.prev_scl_out = self.prev_scl_out
        o.arbitration_lost = self.arbitration_lost
        o.bit_count = self.bit_count
        o.arbitration_lost_byte_end = self.arbitration_lost_byte_end
        o.wait_state = self.wait_state

        return o

    def merge_key(self):
        return (self.bit_count.hash(), self.prev_scl_out.hash())

    def merge(self, others, merge_conditions, common_ancestor=None):
        del common_ancestor

        if any(
            not utils.same_ast(self.bit_count, other.bit_count)
            or not utils.same_ast(self.prev_scl_out, other.prev_scl_out)
            for other in others
        ):
            raise SimMergeError(
                "Cannot merge STM32F4 I2CBus (bit_count or prev_scl_out)"
            )

        changed = False

        if merge_conditions is None:
            merged_arbitration_lost = self.state.solver.union(
                [self.arbitration_lost] + [other.arbitration_lost for other in others]
            )
            merged_arbitration_lost_byte_end = self.state.solver.union(
                [self.arbitration_lost_byte_end]
                + [other.arbitration_lost_byte_end for other in others]
            )
            merged_wait_state = self.state.solver.union(
                [self.wait_state] + [other.wait_state for other in others]
            )
        else:
            merged_arbitration_lost = claripy.ite_cases(
                zip(merge_conditions[1:], [other.arbitration_lost for other in others]),
                self.arbitration_lost,
            )
            merged_arbitration_lost_byte_end = claripy.ite_cases(
                zip(
                    merge_conditions[1:],
                    [other.arbitration_lost_byte_end for other in others],
                ),
                self.arbitration_lost_byte_end,
            )
            merged_wait_state = claripy.ite_cases(
                zip(merge_conditions[1:], [other.wait_state for other in others]),
                self.wait_state,
            )

        if not utils.same_ast(self.arbitration_lost, merged_arbitration_lost):
            self.arbitration_lost = merged_arbitration_lost
            changed = True

        if not utils.same_ast(
            self.arbitration_lost_byte_end, merged_arbitration_lost_byte_end
        ):
            self.arbitration_lost_byte_end = merged_arbitration_lost_byte_end
            changed = True

        if not utils.same_ast(self.wait_state, merged_wait_state):
            self.wait_state = merged_wait_state
            changed = True

        return changed
