from project import utils
from project.types import (
    AccessEffects,
    AccessType,
    BaseRegister,
    BitsField,
    MMIOMemoryRegion,
)


class DWT(MMIOMemoryRegion):
    class DWT_CYCCNT(BaseRegister):
        OFFSET = 0x4

        CYCCNT = BitsField(
            0, AccessType.RW, 0
        )  # FIXME: CYCCNT 的 reset value 為 unknown

    def get_access_effects(self, operation, address, size):
        effects = super().get_access_effects(operation, address, size)
        if operation == "read" and address - self.start == DWT.DWT_CYCCNT.OFFSET:
            effects = effects.union(
                AccessEffects.memory_access("write", address, size)
            )
        return effects

    def post_read(self, state):
        addr, offset, readout_value = super().post_read(state)

        match offset:
            case DWT.DWT_CYCCNT.OFFSET:
                new_val = utils.generate_symbolic(state, f"{self.name}_CYCCNT")

                state.add_constraints(new_val > readout_value)
                utils.store(state, addr, new_val)
