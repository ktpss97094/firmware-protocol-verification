import claripy

from project import utils
from project.types import MMIOMemoryRegion


class TWI(MMIOMemoryRegion):
    class TASKS_STARTTX:
        OFFSET = 0x008

    class TASKS_STOP:
        OFFSET = 0x014

    class EVENTS_STOPPED:
        OFFSET = 0x104

        EVENTS_STOPPED = 0

    class EVENTS_TXDSENT:
        OFFSET = 0x11C

        EVENTS_TXDSENT = 0

    class EVENTS_ERROR:
        OFFSET = 0x124

        EVENTS_ERROR = 0

    class TXD:
        OFFSET = 0x51C

    def read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        self.pre_read(state, offset)

        events_txdsent = utils.load(state, self.start + TWI.EVENTS_TXDSENT.OFFSET)
        events_stopped = utils.load(state, self.start + TWI.EVENTS_STOPPED.OFFSET)
        events_error = utils.load(state, self.start + TWI.EVENTS_ERROR.OFFSET)
        new_events_txdsent = events_txdsent
        new_events_stopped = events_stopped
        new_events_error = events_error

        match offset:
            case TWI.EVENTS_TXDSENT.OFFSET:
                if events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT].symbolic:
                    new_events_txdsent = utils.replace_bit(
                        new_events_txdsent,
                        TWI.EVENTS_TXDSENT.EVENTS_TXDSENT,
                        claripy.If(
                            events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT] == 1,
                            events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{TWI.EVENTS_TXDSENT.OFFSET:#x}_EVENTS_TXDSENT",
                                size=1,
                            ),
                        ),
                    )
                    state.globals[f"{self.name}_EVENTS_TXD_SENT_set"] = claripy.Or(
                        state.globals.get(f"{self.name}_EVENTS_TXD_SENT_set", False),
                        new_events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT] == 1,
                    )

            case TWI.EVENTS_STOPPED.OFFSET:
                if events_stopped[TWI.EVENTS_STOPPED.EVENTS_STOPPED].symbolic:
                    new_events_stopped = utils.replace_bit(
                        new_events_stopped,
                        TWI.EVENTS_STOPPED.EVENTS_STOPPED,
                        claripy.If(
                            events_stopped[TWI.EVENTS_STOPPED.EVENTS_STOPPED] == 1,
                            events_stopped[TWI.EVENTS_STOPPED.EVENTS_STOPPED],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{TWI.EVENTS_STOPPED.OFFSET:#x}_EVENTS_STOPPED",
                                size=1,
                            ),
                        ),
                    )

            case TWI.EVENTS_ERROR.OFFSET:
                if events_error[TWI.EVENTS_ERROR.EVENTS_ERROR].symbolic:
                    new_events_error = utils.replace_bit(
                        new_events_error,
                        TWI.EVENTS_ERROR.EVENTS_ERROR,
                        claripy.If(
                            events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1,
                            events_error[TWI.EVENTS_ERROR.EVENTS_ERROR],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                                size=1,
                            ),
                        ),
                    )
                    state.globals[f"{self.name}_EVENTS_ERROR_set"] = claripy.Or(
                        state.globals.get(f"{self.name}_EVENTS_ERROR_set", False),
                        new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1,
                    )

        utils.store(state, self.start + TWI.EVENTS_TXDSENT.OFFSET, new_events_txdsent)
        utils.store(state, self.start + TWI.EVENTS_STOPPED.OFFSET, new_events_stopped)
        utils.store(state, self.start + TWI.EVENTS_ERROR.OFFSET, new_events_error)

    def write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        self.pre_write(state, offset, value)

        events_txdsent = utils.load(state, self.start + TWI.EVENTS_TXDSENT.OFFSET)
        events_stopped = utils.load(state, self.start + TWI.EVENTS_STOPPED.OFFSET)
        events_error = utils.load(state, self.start + TWI.EVENTS_ERROR.OFFSET)
        new_events_txdsent = events_txdsent
        new_events_stopped = events_stopped
        new_events_error = events_error

        match offset:
            case TWI.TXD.OFFSET:
                new_events_txdsent = utils.symbolic_bit(
                    state,
                    events_txdsent,
                    TWI.EVENTS_TXDSENT.EVENTS_TXDSENT,
                    f"{self.name}_{TWI.EVENTS_TXDSENT.OFFSET:#x}_EVENTS_TXDSENT",
                )
                state.globals[f"{self.name}_EVENTS_TXD_SENT_set"] = claripy.Or(
                    state.globals.get(f"{self.name}_EVENTS_TXD_SENT_set", False),
                    new_events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT] == 1,
                )
                state.globals[f"{self.name}_TXD_written"] = True

                new_events_error = utils.symbolic_bit(
                    state,
                    events_error,
                    TWI.EVENTS_ERROR.EVENTS_ERROR,
                    f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                )
                state.globals[f"{self.name}_EVENTS_ERROR_set"] = claripy.Or(
                    state.globals.get(f"{self.name}_EVENTS_ERROR_set", False),
                    new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1,
                )

            case TWI.TASKS_STOP.OFFSET:
                new_events_stopped = utils.symbolic_bit(
                    state,
                    events_stopped,
                    TWI.EVENTS_STOPPED.EVENTS_STOPPED,
                    f"{self.name}_{TWI.EVENTS_STOPPED.OFFSET:#x}_EVENTS_STOPPED",
                )

            case TWI.TASKS_STARTTX.OFFSET:
                if state.solver.is_true(value == 1):
                    new_events_error = utils.symbolic_bit(
                        state,
                        events_error,
                        TWI.EVENTS_ERROR.EVENTS_ERROR,
                        f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                    )
                    state.globals[f"{self.name}_EVENTS_ERROR_set"] = claripy.Or(
                        state.globals.get(f"{self.name}_EVENTS_ERROR_set", False),
                        new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1,
                    )

        utils.store(state, self.start + TWI.EVENTS_TXDSENT.OFFSET, new_events_txdsent)
        utils.store(state, self.start + TWI.EVENTS_STOPPED.OFFSET, new_events_stopped)
        utils.store(state, self.start + TWI.EVENTS_ERROR.OFFSET, new_events_error)
