from typing import NamedTuple


class MemoryRegion(NamedTuple):
    start: int
    size: int


class I2C(MemoryRegion):
    CR1_OFFSET = 0x00
    CR2_OFFSET = 0x04
    DR_OFFSET = 0x10
    SR1_OFFSET = 0x14
    SR2_OFFSET = 0x18

    CR1_STOP_MASK = 1 << 9
    CR1_START_MASK = 1 << 8

    CR2_ITEVTEN_MASK = 1 << 9

    SR1_AF_MASK = 1 << 10
    SR1_TXE_MASK = 1 << 7
    SR1_BTF_MASK = 1 << 2
    SR1_ADDR_MASK = 1 << 1
    SR1_SB_MASK = 1 << 0

    @property
    def CR1(self):
        return self.start + self.CR1_OFFSET

    @property
    def CR2(self):
        return self.start + self.CR2_OFFSET

    @property
    def DR(self):
        return self.start + self.DR_OFFSET

    @property
    def SR1(self):
        return self.start + self.SR1_OFFSET

    @property
    def SR2(self):
        return self.start + self.SR2_OFFSET


def get_efsm_rules():
    """
    state 內的規則順序會影響執行結果。需先放 特例/嚴格 再放通例/寬鬆

    WARNING: 檢查 bit 是 1 還是 0 用 != 0 跟 == 0，不要用 == 1 !!! (== 1 只會檢查最低位元)
    """

    return {
        "IDLE": [
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_START_MASK) != 0,
                "actions": [
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # reference manual p870: Cleared ... or by hardware after a start or a stop condition
                ],
                "next_state": "SB_WAIT",
            }
        ],
        # EV5
        "SB_WAIT": [
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: s.internal_state_vars["sr1_read_pending"],
                "actions": [
                    ("set_var", "sr1_read_pending", False),
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_SB_MASK,
                    ),  # reference manual p871: Cleared by software by reading the SR1 register followed by writing the DR register
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # reference manual p870: Cleared by software writing to the DR register
                ],
                "next_state": "ADDR_WAIT",
            },
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "actions": [("set_var", "sr1_read_pending", True)],
                "next_state": "SB_WAIT",
            },
        ],
        # EV6
        "ADDR_WAIT": [
            # [Spec 1]
            {
                "trigger_type": "read",
                "offset": I2C.SR2_OFFSET,
                "guard": lambda val, s: (s.internal_state_vars["sr1_read_pending"])
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_ADDR_MASK) == 0),
                "actions": [],
                "next_state": "VIOLATION",
                "error_msg": "Spec 1 Violation: Clearing ADDR but ADDR bit is 0",
            },
            {
                "trigger_type": "read",
                "offset": I2C.SR2_OFFSET,
                "guard": lambda val, s: s.internal_state_vars["sr1_read_pending"],
                "actions": [
                    ("set_var", "sr1_read_pending", False),
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_ADDR_MASK,
                    ),  # reference manual p871: This bit is cleared by software reading SR1 register followed reading SR2
                    (
                        "set_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # reference manual p870: Set when DR is empty in transmission. TxE is not set during address phase
                ],
                "next_state": "TXE_SET_SRE_WRITE_DR",
            },
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "actions": [("set_var", "sr1_read_pending", True)],
                "next_state": "ADDR_WAIT",
            },
        ],
        # EV8_1
        "TXE_SET_SRE_WRITE_DR": [
            # [Spec 2]
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: (
                    s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_TXE_MASK
                )
                == 0,
                "actions": [],
                "next_state": "VIOLATION",
                "error_msg": "Spec 2 Violation: Write DR when TxE is 0 (in TXE_SET_SRE_WRITE_DR)",
            },
            # [Spec 3]
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: ((val & I2C.CR1_STOP_MASK) != 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK) == 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_AF_MASK) == 0),
                "actions": [],
                "next_state": "VIOLATION",
                "error_msg": "Spec 3 Violation: Set STOP when BTF is 0 and AF is 0 (in TXE_SET_SRE_WRITE_DR)",
            },
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: (
                    s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK
                )
                != 0,
                "actions": [],
                "next_state": "BTF_SET",
            },
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: True,
                "actions": [
                    # reference manual p870: TxE is not cleared by writing the first data being transmitted
                ],
                "next_state": "TXE_SET_SRNE_WRITE_DR",
            },
        ],
        # EV8
        "TXE_SET_SRNE_WRITE_DR": [
            # [Spec 2]
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: (
                    s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_TXE_MASK
                )
                == 0,
                "actions": [],
                "next_state": "VIOLATION",
                "error_msg": "Spec 2 Violation: Write DR when TxE is 0 (in TXE_SET_SRNE_WRITE_DR)",
            },
            # [Spec 3]
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: ((val & I2C.CR1_STOP_MASK) != 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK) == 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_AF_MASK) == 0),
                "actions": [],
                "next_state": "VIOLATION",
                "error_msg": "Spec 3 Violation: Set STOP when BTF is 0 and AF is 0 (in TXE_SET_SRNE_WRITE_DR)",
            },
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: True,
                "actions": [
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),
                ],  # reference manual p870: Cleared by software writing to the DR register
                "next_state": "TXE_SET_SRNE_WRITE_DR",
            },
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: (
                    s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK
                )
                != 0,
                "actions": [],
                "next_state": "BTF_SET",
            },
        ],
        # EV8_2
        "BTF_SET": [
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: True,
                "actions": [
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_BTF_MASK,
                    ),  # reference manual p871: Cleared by software by either a read or write in the DR register
                    # 不會 clear TxE，因為寫入 DR 後資料會直接進入 shift register (reference manual p870: TxE is not cleared ... or by writing data when BTF is set)
                ],
                "next_state": "TXE_SET_SRNE_WRITE_DR",
            },
            # Stop condition OK
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_STOP_MASK) != 0,
                "actions": [
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_BTF_MASK,
                    ),  # reference manual p871: Cleared ... or by hardware after a start or a stop condition in transmission
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # reference manual p870: Cleared ... or by hardware after a start or a stop condition
                ],
                "next_state": "IDLE",
            },
            # Repeated Start
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_START_MASK) != 0,
                "actions": [
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_BTF_MASK,
                    ),  # reference manual p871: Cleared ... or by hardware after a start or a stop condition in transmission
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # reference manual p870: Cleared ... or by hardware after a start or a stop condition
                ],
                "next_state": "SB_WAIT",
            },
        ],
    }
