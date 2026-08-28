import logging
from typing import Callable

from angr import SimulationManager

logger = logging.getLogger(__name__)


class ExplorationMonitor:
    def __init__(self, violated_count_func: Callable[[], int]):
        self.step_count = 0
        self.found_count = 0
        self._violated_count = violated_count_func

    def step(self, simgr: SimulationManager) -> SimulationManager:
        # Method 2 violation exception handing
        # for err in simgr.errored.copy():
        #     if isinstance(err.error, Violation):
        #         print(
        #             err.error.args[0]
        #             + f" violation (instruction address: {hex(err.error.ins_addr)})"
        #         )
        #         simgr.violated.append(err.state)
        #         simgr.errored.remove(err)
        # simgr.stashes["violated"].clear()

        self.found_count += len(simgr.found)
        simgr.stashes["found"].clear()

        simgr.stashes["loopseer"].clear()

        self.step_count += 1
        if self.step_count == 1 or self.step_count % 64 == 0 or not simgr.active:
            logger.info(
                f"Step {self.step_count}: active={len(simgr.active)} found={self.found_count} violate={self._violated_count()}"
            )

        return simgr
