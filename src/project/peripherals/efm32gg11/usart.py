import claripy

from project import utils
from project.types import MMIOMemoryRegion


class USART(MMIOMemoryRegion):
    class USARTn_STATUS:
        OFFSET = 0x010

        TXBL = 6  # 1 為 TX buffer empty

    class USARTn_TXDATA:
        OFFSET = 0x034

    def read(self, state, offset):
        self.pre_read(state, offset)

        usartn_status = utils.load(state, self.start + USART.USARTn_STATUS.OFFSET)
        new_usartn_status = usartn_status

        match offset:
            case USART.USARTn_STATUS.OFFSET:
                # 不需要先判斷 TXBL 是不是 symbolic，這跟 STM32 I2C ADDR 等狀況不同，ADDR 是在設為 symbolic 後才有這個 replace_bit 規則，但 TXBL 是任何時候這個規則都成立
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

    def write(self, state, offset, value):
        self.pre_write(state, offset, value)

        usartn_status = utils.load(state, self.start + USART.USARTn_STATUS.OFFSET)
        new_usartn_status = usartn_status

        match offset:
            case USART.USARTn_TXDATA.OFFSET:
                new_usartn_status = utils.symbolic_bit(
                    state,
                    new_usartn_status,
                    USART.USARTn_STATUS.TXBL,
                    f"{self.name}_{USART.USARTn_STATUS.OFFSET:#x}_TXBL",
                )

        utils.store(state, self.start + USART.USARTn_STATUS.OFFSET, new_usartn_status)
