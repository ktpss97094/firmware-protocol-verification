from project import utils


class NVIC:
    NVIC_IPR = 0xE000E400  # Interrupt Priority Registers

    @staticmethod
    def get_irq_priority(state, irq_number):
        return state.solver.eval(
            utils.load(state, NVIC.NVIC_IPR + irq_number, size=1)[7:4]
        )

    @staticmethod
    def is_in_handler_mode(state):
        ipsr = state.regs.iepsr & 0x1FF
        return state.solver.is_true(ipsr > 0)
