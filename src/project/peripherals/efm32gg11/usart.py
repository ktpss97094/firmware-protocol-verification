import claripy

from project import utils
from project.types import MMIOMemoryRegion


class USART(MMIOMemoryRegion):
    class USARTn_STATUS:
        OFFSET = 0x010

        TXBL = 6  # 1 means TX buffer empty

    class USARTn_TXDATA:
        OFFSET = 0x034

    def post_read(self, state, offset):
        self.post_read_spec(state, offset)

        usartn_status = utils.load(state, self.start + USART.USARTn_STATUS.OFFSET)
        new_usartn_status = usartn_status

        match offset:
            case USART.USARTn_STATUS.OFFSET:
                # There is no need to first determine whether TXBL is symbolic. This differs from cases such as the STM32 I2C ADDR, where the replace_bit rule applies only after ADDR is set to symbolic; however, for TXBL, this rule always applies
                new_usartn_status = utils.replace_bit(
                    new_usartn_status,
                    USART.USARTn_STATUS.TXBL,
                    claripy.If(
                        new_usartn_status[USART.USARTn_STATUS.TXBL] == 1,
                        new_usartn_status[USART.USARTn_STATUS.TXBL],
                        utils.generate_symbolic(
                            state,
                            f"{self.name}_{USART.USARTn_STATUS.OFFSET:#x}_TXBL",
                            size=1,
                        ),
                    ),
                )

        utils.store(state, self.start + USART.USARTn_STATUS.OFFSET, new_usartn_status)

    def post_write(self, state, offset, value):
        self.post_write_spec(state, offset, value)

        usartn_status = utils.load(state, self.start + USART.USARTn_STATUS.OFFSET)
        new_usartn_status = usartn_status

        match offset:
            case USART.USARTn_TXDATA.OFFSET:
                new_usartn_status = utils.replace_bit(
                    new_usartn_status,
                    USART.USARTn_STATUS.TXBL,
                    utils.generate_symbolic(state, f"{self.name}_TXBL", size=1),
                )

        utils.store(state, self.start + USART.USARTn_STATUS.OFFSET, new_usartn_status)
