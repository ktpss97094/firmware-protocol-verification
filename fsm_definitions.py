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

    SR1_TXE_MASK = 1 << 7
    SR1_BTF_MASK = 1 << 2
    SR1_ADDR_MASK = 1 << 1
    SR1_SB_MASK = 1 << 0

    # [NEW] 狀態感知易變性定義 (State-Aware Volatility)
    # 定義在各個狀態下，哪些 Bit 是由硬體控制而可能變動的 (White-list)。
    # Plugin 會根據此表自動將這些 Bit 設為符號變數 (Symbolic)，其餘 Status Bit 強制設為 0。
    STATE_VOLATILITY = {
        "IDLE": 0,
        "SB_WAIT": SR1_SB_MASK,  # 只有 SB 會變，ADDR/BTF/TxE 強制為 0
        "ADDR_WAIT": SR1_ADDR_MASK,  # 只有 ADDR 會變
        "MASTER_TX": SR1_TXE_MASK | SR1_BTF_MASK,  # TxE 和 BTF 會跳動
        "TX_BUSY": SR1_TXE_MASK | SR1_BTF_MASK,
        "BTF_WAIT": SR1_BTF_MASK,
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


def get_fsm_rules():
    return {
        "IDLE": [
            # [write CR1.START==1] -> SB_WAIT
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_START_MASK) != 0,
                "next_state": "SB_WAIT",
                # Action: 確定性地清除 SR1 (硬體行為)，SB bit 會由 Volatility 機制自動處理
                "actions": [("set_bit", I2C.SR1_OFFSET, 0)],
            }
        ],
        "SB_WAIT": [
            # [write DR, sr1_read_pending==True] -> ADDR_WAIT
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                # sr1_read_pending 是抽象變數，繼續使用 s.vars
                "guard": lambda val, s: s.vars.get("sr1_read_pending", False),
                "next_state": "ADDR_WAIT",
                "actions": [
                    ("set_var", "sr1_read_pending", False),
                    # ADDR 的設定是確定性的，我們幫硬體先設好，
                    # 之後 Plugin 讀取時會把它變成 Symbolic (如果 Volatility 允許)
                    ("set_bit", I2C.SR1_OFFSET, I2C.SR1_ADDR_MASK),
                ],
            },
            # [read SR1] -> 標記 read pending
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "SB_WAIT",
                "actions": [("set_var", "sr1_read_pending", True)],
            },
        ],
        "ADDR_WAIT": [
            # Spec 1: clear ADDR bit 前，若 ADDR bit 為 0 -> VIOLATION
            {
                "trigger_type": "read",
                "offset": I2C.SR2_OFFSET,
                # [Fix] 使用 & 運算子，並檢查記憶體中的 ADDR bit
                "guard": lambda val, s: (s.vars.get("sr1_read_pending", False))
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_ADDR_MASK) == 0),
                "next_state": "VIOLATION",
                "error_msg": "Spec 1 Violation: Clearing ADDR but ADDR bit is 0",
            },
            # [read SR2, sr1_read_pending==True] -> MASTER_TX
            {
                "trigger_type": "read",
                "offset": I2C.SR2_OFFSET,
                "guard": lambda val, s: s.vars.get("sr1_read_pending", False),
                "next_state": "MASTER_TX",
                "actions": [
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_ADDR_MASK),  # 硬體清除 ADDR
                    ("set_var", "sr1_read_pending", False),
                    (
                        "set_bit",
                        I2C.SR1_OFFSET,
                        I2C.SR1_TXE_MASK,
                    ),  # 進入 Tx 狀態，TxE 預設為 1
                ],
            },
            # [read SR1]
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "ADDR_WAIT",
                "actions": [("set_var", "sr1_read_pending", True)],
            },
        ],
        "MASTER_TX": [
            # Spec 2 Check: Write DR check TxE
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: (
                    s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_TXE_MASK
                )
                == 0,
                "next_state": "VIOLATION",
                "error_msg": "Spec 2 Violation: Write DR when TxE is 0",
            },
            # Spec 3 Check: Write CR1.STOP check BTF
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                # [Fix] 使用 & 運算子，並檢查 BTF
                "guard": lambda val, s: ((val & I2C.CR1_STOP_MASK) != 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK) == 0),
                "next_state": "VIOLATION",
                "error_msg": "Spec 3 Violation: Set STOP when BTF is 0",
            },
            # [write DR] -> TX_BUSY
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "TX_BUSY",
                "actions": [
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_TXE_MASK),
                ],
            },
            # [read SR1] -> MASTER_TX (Looping for polling)
            # 這裡不需要 actions，Plugin 會根據 STATE_VOLATILITY 自動注入 TxE/BTF 的符號值
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "MASTER_TX",
                "actions": [],
            },
        ],
        "TX_BUSY": [
            # [read SR1] -> MASTER_TX
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "MASTER_TX",
                "actions": [
                    ("set_bit", I2C.SR1_OFFSET, I2C.SR1_TXE_MASK),  # 模擬 Shift 完成
                ],
            }
        ],
        "BTF_WAIT": [
            # 1. [write DR] -> TX_BUSY
            {
                "trigger_type": "write",
                "offset": I2C.DR_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "TX_BUSY",
                "actions": [
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_BTF_MASK),
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_TXE_MASK),
                ],
            },
            # 2. [write CR1.STOP==1] -> Check Spec 3
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: ((val & I2C.CR1_STOP_MASK) != 0)
                & ((s.get_reg_value(I2C.SR1_OFFSET) & I2C.SR1_BTF_MASK) == 0),
                "next_state": "VIOLATION",
                "error_msg": "Spec 3 Violation: Set STOP when BTF is 0 (in BTF_WAIT)",
            },
            # Stop condition OK
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_STOP_MASK) != 0,
                "next_state": "IDLE",
                "actions": [
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_BTF_MASK),
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_TXE_MASK),
                ],
            },
            # 3. [write CR1.START==1] -> SB_WAIT
            {
                "trigger_type": "write",
                "offset": I2C.CR1_OFFSET,
                "guard": lambda val, s: (val & I2C.CR1_START_MASK) != 0,
                "next_state": "SB_WAIT",
                "actions": [
                    ("clear_bit", I2C.SR1_OFFSET, I2C.SR1_BTF_MASK),
                    ("set_bit", I2C.SR1_OFFSET, I2C.SR1_SB_MASK),
                ],
            },
            # 4. Polling SR1 -> BTF_WAIT
            {
                "trigger_type": "read",
                "offset": I2C.SR1_OFFSET,
                "guard": lambda val, s: True,
                "next_state": "BTF_WAIT",
                "actions": [],
            },
        ],
    }
