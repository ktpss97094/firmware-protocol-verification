from project import utils
from project.types import AccessEffects, VariableMemoryRegion


class SysTickVariable(VariableMemoryRegion):
    def get_access_effects(self, operation, address, size):
        effects = super().get_access_effects(operation, address, size)
        if operation == "read":
            effects = effects.union(
                AccessEffects.memory_access("write", address, size)
            )
        return effects

    def post_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)

        origin_val = utils.load(state, addr)

        new_val = utils.generate_symbolic(state, self.name)
        state.add_constraints(new_val > origin_val)

        # delta = 1
        # new_val = origin_val + delta

        utils.store(state, addr, new_val)
