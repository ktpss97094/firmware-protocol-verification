import claripy
from angr.state_plugins.plugin import SimStatePlugin


class I2CBus(SimStatePlugin):
    def __init__(
        self,
        prev_scl_out=None,
        ext_sda=None,
        arbitration_lost=None,
        bit_count=None,
        arbitration_lost_byte_end=None,
    ):
        super().__init__()

        self.prev_scl_out = True if prev_scl_out is None else prev_scl_out
        self.ext_sda = self.produce_external_sda() if ext_sda is None else ext_sda
        self.arbitration_lost = False if arbitration_lost is None else arbitration_lost
        self.bit_count = 0 if bit_count is None else bit_count
        self.arbitration_lost_byte_end = (
            False if arbitration_lost_byte_end is None else arbitration_lost_byte_end
        )

    def copy(self, memo):
        o = super().copy(memo)

        o.prev_scl_out = self.prev_scl_out
        o.ext_sda = self.ext_sda
        o.arbitration_lost = self.arbitration_lost
        o.bit_count = self.bit_count
        o.arbitration_lost_byte_end = self.arbitration_lost_byte_end

        return o

    def produce_external_sda(self):
        return claripy.BVS("external_sda", 1)
