from angr import SimState
from angr.errors import SimEngineError

from project.exploration import ExplorationTermination
from project.types import BaseSpec


class Violation(SimEngineError):
    pass


class VerificationSession:
    def __init__(self, spec: BaseSpec):
        if not spec.PROPERTY_NAMES:
            raise ValueError("The number of verified properties cannot be 0.")

        self.spec = spec
        self.violation_names: set[str] = set()

    @property
    def violated_count(self) -> int:
        return len(self.violation_names)

    def verify(self, state: SimState, property_name: str, extra_constraints=()):
        if property_name in self.violation_names:
            return

        if state.solver.satisfiable(extra_constraints=extra_constraints):
            self.violation_names.add(property_name)

            # Method 1: Only print the message, do not terminate the state
            print(f"{property_name} violation (instruction address: {hex(state.addr)})")

            # Method 2: Print the message and terminate the state
            # raise Violation(violation_name)

            if self.spec.PROPERTY_NAMES == self.violation_names:
                raise ExplorationTermination(
                    "All violations triggered. Stopping analysis."
                )
