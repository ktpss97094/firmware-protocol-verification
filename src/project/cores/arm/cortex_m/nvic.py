from project import utils


class NVIC:
    # NVIC Interrupt Priority Registers base address
    NVIC_IPR_BASE = 0xE000E400

    @staticmethod
    def get_irq_priority(state, irq_number):
        return state.solver.eval(
            utils.load(state, NVIC.NVIC_IPR_BASE + irq_number, size=1)[7:4]
        )

    @staticmethod
    def is_in_handler_mode(state):
        ipsr = state.regs.iepsr & 0x1FF
        return state.solver.is_true(ipsr > 0)
