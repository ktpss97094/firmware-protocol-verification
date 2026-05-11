from project import utils
from project.types import AccessType, BaseRegister, BitsField, MMIOMemoryRegion


class DWT(MMIOMemoryRegion):
    class DWT_CYCCNT(BaseRegister):
        OFFSET = 0x4

        CYCCNT = BitsField(
            0, AccessType.RW, 0
        )  # FIXME: CYCCNT 的 reset value 為 unknown

    def post_read(self, state):
        addr, offset, readout_value = super().post_read(state)

        match offset:
            case DWT.DWT_CYCCNT.OFFSET:
                new_val = utils.generate_symbolic(state, f"{self.name}_CYCCNT")

                state.add_constraints(new_val > readout_value)
                utils.store(state, addr, new_val)
