import claripy

from project import utils
from project.types import MMIOMemoryRegion


class TWI(MMIOMemoryRegion):
    IRQ_NUMBER = 3

    class TASKS_STARTRX:
        OFFSET = 0x000

    class TASKS_STARTTX:
        OFFSET = 0x008

    class TASKS_STOP:
        OFFSET = 0x014

        TASKS_STOP = 0

    class EVENTS_STOPPED:
        OFFSET = 0x104

        EVENTS_STOPPED = 0

    class EVENTS_RXDREADY:
        OFFSET = 0x108

        EVENTS_RXDREADY = 0

    class EVENTS_TXDSENT:
        OFFSET = 0x11C

        EVENTS_TXDSENT = 0

    class EVENTS_ERROR:
        OFFSET = 0x124

        EVENTS_ERROR = 0

    class INTENSET:
        OFFSET = 0x304

        STOPPED = 1
        RXDREADY = 2
        TXDSENT = 7
        ERROR = 9
        BB = 14
        SUSPENDED = 18

    class RXD:
        OFFSET = 0x518

    class TXD:
        OFFSET = 0x51C

    def read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        self.pre_read(state, offset)

        tasks_stop = utils.load(state, self.start + TWI.TASKS_STOP.OFFSET)
        events_stopped = utils.load(state, self.start + TWI.EVENTS_STOPPED.OFFSET)
        events_rxdready = utils.load(state, self.start + TWI.EVENTS_RXDREADY.OFFSET)
        events_txdsent = utils.load(state, self.start + TWI.EVENTS_TXDSENT.OFFSET)
        events_error = utils.load(state, self.start + TWI.EVENTS_ERROR.OFFSET)
        rxd = utils.load(state, self.start + TWI.RXD.OFFSET)
        new_events_stopped = events_stopped
        new_events_rxdready = events_rxdready
        new_events_txdsent = events_txdsent
        new_events_error = events_error
        new_rxd = rxd

        match offset:
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

            case TWI.EVENTS_RXDREADY.OFFSET:
                if events_rxdready[TWI.EVENTS_RXDREADY.EVENTS_RXDREADY].symbolic:
                    new_events_rxdready = utils.replace_bit(
                        new_events_rxdready,
                        TWI.EVENTS_RXDREADY.EVENTS_RXDREADY,
                        claripy.If(
                            events_rxdready[TWI.EVENTS_RXDREADY.EVENTS_RXDREADY] == 1,
                            events_rxdready[TWI.EVENTS_RXDREADY.EVENTS_RXDREADY],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{TWI.EVENTS_RXDREADY.OFFSET:#x}_EVENTS_RXDREADY",
                                size=1,
                            ),
                        ),
                    )
                    state.globals[f"{self.name}_EVENTS_RXDREADY_set"] = claripy.Or(
                        state.globals.get(f"{self.name}_EVENTS_RXDREADY_set", False),
                        new_events_rxdready[TWI.EVENTS_RXDREADY.EVENTS_RXDREADY] == 1,
                    )

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
                    state.globals[f"{self.name}_EVENTS_TXDSENT_set"] = claripy.Or(
                        state.globals.get(f"{self.name}_EVENTS_TXDSENT_set", False),
                        new_events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT] == 1,
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

            case TWI.RXD.OFFSET:
                # 在 set TASKS_STOP 後並 read RXD，會送出 NACK 表示 read 結束
                if state.solver.is_true(tasks_stop[TWI.TASKS_STOP.TASKS_STOP] != 1):
                    new_events_rxdready = utils.symbolic_bit(
                        state,
                        events_rxdready,
                        TWI.EVENTS_RXDREADY.EVENTS_RXDREADY,
                        f"{self.name}_{TWI.EVENTS_RXDREADY.OFFSET:#x}_EVENTS_RXDREADY",
                    )
                    state.globals[f"{self.name}_EVENTS_RXDREADY_set"] = (
                        new_events_rxdready[TWI.EVENTS_RXDREADY.EVENTS_RXDREADY] == 1
                    )

                    new_events_error = utils.symbolic_bit(
                        state,
                        events_error,
                        TWI.EVENTS_ERROR.EVENTS_ERROR,
                        f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                    )
                    state.globals[f"{self.name}_EVENTS_ERROR_set"] = (
                        new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1
                    )

                # Product Specification: Register is cleared on read
                new_rxd = claripy.BVV(0, state.arch.bits)

        utils.store(state, self.start + TWI.EVENTS_STOPPED.OFFSET, new_events_stopped)
        utils.store(state, self.start + TWI.EVENTS_RXDREADY.OFFSET, new_events_rxdready)
        utils.store(state, self.start + TWI.EVENTS_TXDSENT.OFFSET, new_events_txdsent)
        utils.store(state, self.start + TWI.EVENTS_ERROR.OFFSET, new_events_error)
        utils.store(state, self.start + TWI.RXD.OFFSET, new_rxd)

    def write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        self.pre_write(state, offset, value)

        events_stopped = utils.load(state, self.start + TWI.EVENTS_STOPPED.OFFSET)
        events_rxdready = utils.load(state, self.start + TWI.EVENTS_RXDREADY.OFFSET)
        events_txdsent = utils.load(state, self.start + TWI.EVENTS_TXDSENT.OFFSET)
        events_error = utils.load(state, self.start + TWI.EVENTS_ERROR.OFFSET)
        new_events_stopped = events_stopped
        new_events_rxdready = events_rxdready
        new_events_txdsent = events_txdsent
        new_events_error = events_error

        match offset:
            case TWI.TASKS_STARTRX.OFFSET:
                if state.solver.is_true(value == 1):
                    new_events_rxdready = utils.symbolic_bit(
                        state,
                        events_rxdready,
                        TWI.EVENTS_RXDREADY.EVENTS_RXDREADY,
                        f"{self.name}_{TWI.EVENTS_RXDREADY.OFFSET:#x}_EVENTS_RXDREADY",
                    )
                    state.globals[f"{self.name}_EVENTS_RXDREADY_set"] = (
                        new_events_rxdready[TWI.EVENTS_RXDREADY.EVENTS_RXDREADY] == 1
                    )

                    new_events_error = utils.symbolic_bit(
                        state,
                        events_error,
                        TWI.EVENTS_ERROR.EVENTS_ERROR,
                        f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                    )
                    state.globals[f"{self.name}_EVENTS_ERROR_set"] = (
                        new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1
                    )

            case TWI.TASKS_STARTTX.OFFSET:
                if state.solver.is_true(value == 1):
                    new_events_error = utils.symbolic_bit(
                        state,
                        events_error,
                        TWI.EVENTS_ERROR.EVENTS_ERROR,
                        f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                    )
                    state.globals[f"{self.name}_EVENTS_ERROR_set"] = (
                        new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1
                    )

            case TWI.TASKS_STOP.OFFSET:
                if state.solver.is_true(value == 1):
                    new_events_stopped = utils.symbolic_bit(
                        state,
                        events_stopped,
                        TWI.EVENTS_STOPPED.EVENTS_STOPPED,
                        f"{self.name}_{TWI.EVENTS_STOPPED.OFFSET:#x}_EVENTS_STOPPED",
                    )

            case TWI.TXD.OFFSET:
                new_events_txdsent = utils.symbolic_bit(
                    state,
                    events_txdsent,
                    TWI.EVENTS_TXDSENT.EVENTS_TXDSENT,
                    f"{self.name}_{TWI.EVENTS_TXDSENT.OFFSET:#x}_EVENTS_TXDSENT",
                )
                state.globals[f"{self.name}_EVENTS_TXDSENT_set"] = (
                    new_events_txdsent[TWI.EVENTS_TXDSENT.EVENTS_TXDSENT] == 1
                )
                state.globals[f"{self.name}_TXD_written"] = True

                new_events_error = utils.symbolic_bit(
                    state,
                    events_error,
                    TWI.EVENTS_ERROR.EVENTS_ERROR,
                    f"{self.name}_{TWI.EVENTS_ERROR.OFFSET:#x}_EVENTS_ERROR",
                )
                state.globals[f"{self.name}_EVENTS_ERROR_set"] = (
                    new_events_error[TWI.EVENTS_ERROR.EVENTS_ERROR] == 1
                )

        utils.store(state, self.start + TWI.EVENTS_STOPPED.OFFSET, new_events_stopped)
        utils.store(state, self.start + TWI.EVENTS_RXDREADY.OFFSET, new_events_rxdready)
        utils.store(state, self.start + TWI.EVENTS_TXDSENT.OFFSET, new_events_txdsent)
        utils.store(state, self.start + TWI.EVENTS_ERROR.OFFSET, new_events_error)

    def get_pending_irqs(self, state):
        """
        回傳此 peripheral 目前可能觸發的 IRQ
        格式: {irq_number: [(trigger_var, trigger_cond), ...]}
        """

        if self.IRQ_NUMBER not in state.custom_globals.irq:
            state.custom_globals.irq[self.IRQ_NUMBER] = {"handled_hashes": frozenset()}

        triggers = []
        intenset = utils.load(state, self.start + TWI.INTENSET.OFFSET)

        event_checks = [
            (
                TWI.INTENSET.STOPPED,
                TWI.EVENTS_STOPPED.OFFSET,
                TWI.EVENTS_STOPPED.EVENTS_STOPPED,
            ),
            (
                TWI.INTENSET.RXDREADY,
                TWI.EVENTS_RXDREADY.OFFSET,
                TWI.EVENTS_RXDREADY.EVENTS_RXDREADY,
            ),
            (
                TWI.INTENSET.TXDSENT,
                TWI.EVENTS_TXDSENT.OFFSET,
                TWI.EVENTS_TXDSENT.EVENTS_TXDSENT,
            ),
            (
                TWI.INTENSET.ERROR,
                TWI.EVENTS_ERROR.OFFSET,
                TWI.EVENTS_ERROR.EVENTS_ERROR,
            ),
        ]

        for intenset_bit, event_offset, event_bit in event_checks:
            if state.solver.is_true(intenset[intenset_bit] == 1):
                event_val = utils.load(state, self.start + event_offset)[event_bit]
                trigger_cond = event_val != 0
                if hash(event_val) not in state.custom_globals.irq[self.IRQ_NUMBER][
                    "handled_hashes"
                ] and state.solver.satisfiable(extra_constraints=[trigger_cond]):
                    triggers.append((event_val, trigger_cond))

        return {self.IRQ_NUMBER: triggers} if triggers else {}
