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

    # 定義在哪個 state 下哪些 bits 要設為 symbolic
    STATE_SYMBOLIC = {
        "IDLE": {},
        "SB_WAIT": {SR1_OFFSET: SR1_SB_MASK},
        "ADDR_WAIT": {SR1_OFFSET: SR1_ADDR_MASK},
        "MASTER_TX": {SR1_OFFSET: SR1_TXE_MASK | SR1_BTF_MASK},
        "TX_BUSY": {SR1_OFFSET: SR1_TXE_MASK | SR1_BTF_MASK},
        "BTF_WAIT": {SR1_OFFSET: SR1_BTF_MASK},
    }

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
    """

    return {
        "IDLE": [
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_START_MASK) != 0,
                "actions": [],
                "next_state": "SB_WAIT",
            }
        ],
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
                "next_state": "MASTER_TX",
            },
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "actions": [("set_var", "sr1_read_pending", True)],
                "next_state": "ADDR_WAIT",
            },
        ],
        "MASTER_TX": [
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
                "error_msg": "Spec 2 Violation: Write DR when TxE is 0",
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
                "error_msg": "Spec 3 Violation: Set STOP when BTF is 0 and AF is 0 (in MASTER_TX)",
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
                    ),  # reference manual p870: Cleared by software writing to the DR register
                ],
                "next_state": "TX_BUSY",
            },
        ],
        # TX_BUSY state 代表剛寫入 DR，但尚未轉移到 shift register 的暫態
        "TX_BUSY": [
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "actions": [],
                "next_state": "MASTER_TX",
            }
        ],
        "BTF_WAIT": [
            # [Spec 3]
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: ((val & I2C.CR1_STOP_MASK) != 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK) == 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_AF_MASK) == 0),
                "actions": [],
                "next_state": "VIOLATION",
                "error_msg": "Spec 3 Violation: Set STOP when BTF is 0 and AF is 0 (in BTF_WAIT)",
            },
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
                    (
                        "clear_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # reference manual p870: Cleared by software writing to the DR register
                ],
                "next_state": "TX_BUSY",
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
