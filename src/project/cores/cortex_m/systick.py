from project import utils
from project.types import VariableMemoryRegion


class SysTickVariable(VariableMemoryRegion):
    def post_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)

        origin_val = utils.load(state, addr)

        new_val = utils.generate_symbolic(state, self.name)
        state.add_constraints(new_val > origin_val)

        # delta = 1
        # new_val = origin_val + delta

        utils.store(state, addr, new_val)
