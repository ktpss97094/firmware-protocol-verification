import claripy
from angr.state_plugins.plugin import SimStatePlugin


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

    def merge(self, others, merge_conditions, common_ancestor=None):
        del common_ancestor

        fields = (
            "prev_scl_out",
            "arbitration_lost",
            "bit_count",
            "arbitration_lost_byte_end",
            "wait_state",
        )

        for field in fields:
            current_value = getattr(self, field)
            other_values = [getattr(other, field) for other in others]

            if merge_conditions is None:
                merged_value = current_value
                for other_value in other_values:
                    merged_value = claripy.If(
                        claripy.BoolS(f"i2c_bus_merge_{field}"),
                        other_value,
                        merged_value,
                    )
            else:
                merged_value = claripy.ite_cases(
                    zip(merge_conditions[1:], other_values), current_value
                )

            setattr(self, field, merged_value)

        return True
