import angr
import claripy
import logging
from fsm_definitions import I2C


class PeripheralRulePlugin(angr.SimStatePlugin):
    def __init__(self, rules=None, internal_vars=None, base_addr=0x40005400):
        super(PeripheralRulePlugin, self).__init__()

        self.rules = rules if rules is not None else {}
        self.base_addr = base_addr

        if internal_vars is not None:
            self.vars = internal_vars
        else:
            self.vars = {
                "internal_state": "IDLE",
                # 抽象變數仍保留用於邏輯判斷，但主要狀態將依賴 Memory 中的值
                "TxE": 0,
                "BTF": 0,
                "ADDR": 0,
                "SB": 0,
                "sr1_read_pending": False,
            }

        self.symbolic_name_cnt = 0

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        new_vars = self.vars.copy()
        return PeripheralRulePlugin(
            rules=self.rules, internal_vars=new_vars, base_addr=self.base_addr
        )

    def get_reg_value(self, offset):
        """Helper: 從 state.memory 讀取目前的暫存器數值"""
        addr = self.base_addr + offset
        try:
            val = self.state.memory.load(
                addr,
                4,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False,
            )
            return val
        except Exception as e:
            print(f"Failed to load register from memory at offset {hex(offset)}: {e}")
            return 0

    def _execute_action(self, action):
        """執行規則中定義的動作 (直接操作 state.memory)"""
        endness = self.state.arch.memory_endness

        if isinstance(action, tuple):
            op = action[0]

            if op == "set_var":
                self.vars[action[1]] = action[2]

            elif op == "set_bit":
                offset, mask = action[1], action[2]
                addr = self.base_addr + offset
                val = self.state.memory.load(
                    addr, 4, endness=endness, disable_actions=True, inspect=False
                )
                new_val = val | mask
                self.state.memory.store(
                    addr, new_val, endness=endness, disable_actions=True, inspect=False
                )

            elif op == "clear_bit":
                offset, mask = action[1], action[2]
                addr = self.base_addr + offset
                val = self.state.memory.load(
                    addr, 4, endness=endness, disable_actions=True, inspect=False
                )
                new_val = val & (~mask)
                self.state.memory.store(
                    addr, new_val, endness=endness, disable_actions=True, inspect=False
                )

    def _inject_volatility_if_needed(self, offset, current_val):
        """
        根據 State-Aware Volatility 表，自動將允許變動的 Bits 轉為 Symbolic，
        其餘 Status Bits 強制設為 0 (或保持原值)。
        """
        # 1. 取得當前狀態
        current_state = self.vars.get("internal_state", "IDLE")

        # 2. 查表決定 Mask
        #    注意：這裡假設 STATE_VOLATILITY 定義的是 SR1 的 Mask
        #    如果是其他 Register (如 SR2)，預設沒有 Volatility (Mask=0)
        allowed_volatile_mask = 0

        if offset == I2C.SR1_OFFSET:
            allowed_volatile_mask = I2C.STATE_VOLATILITY.get(current_state, 0)

        # 如果 Mask 為 0，表示此時硬體不應該變動這個 Register，直接回傳原值
        if allowed_volatile_mask == 0:
            return current_val

        # 3. 檢查 Cache (防止 Loop 中路徑爆炸)
        #    確保在同一個 State 內，只產生一次符號變數
        cache_key = f"sym_injected_{current_state}_{offset}"
        if self.state.globals.get(cache_key, False):
            return current_val

        # 4. 建立符號變數 (Symbolic Variable)
        sym_name = f"hw_{current_state}_{hex(offset)}"
        self.symbolic_name_cnt += 1
        sym_bits = claripy.BVS(sym_name, 32)

        # 5. [核心邏輯] 混合 Symbolic 與 Concrete
        #    - 允許變動的部分 (Mask 內) -> 使用 Symbolic
        #    - 不允許變動的部分 (Mask 外) -> 使用 current_val (通常是 0)
        #      這保證了例如在 SB_WAIT 時，ADDR bit (不在 Mask 內) 會保持為 0，
        #      避免 ISR 誤判。
        final_val = (current_val & ~allowed_volatile_mask) | (
            sym_bits & allowed_volatile_mask
        )

        # 6. 寫回 Memory
        #    這樣後續的 Hook 或程式碼讀取時，就會拿到這個帶有符號的值
        self.state.memory.store(
            self.base_addr + offset,
            final_val,
            endness=self.state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )

        # 7. 標記已注入
        self.state.globals[cache_key] = True
        print(
            f"[Auto-Volatility] Injected symbolic bits {bin(allowed_volatile_mask)} at {hex(offset)} for state {current_state}"
        )

        return final_val

    def handle_mmio(self, access_type, offset, val=None):
        """
        處理 MMIO 存取
        """
        current_state = self.vars.get("internal_state", "IDLE")

        if current_state == "VIOLATION":
            return

        transitions = self.rules.get(current_state, [])
        matched_transition = None

        # 尋找匹配的規則
        for trans in transitions:
            if trans["trigger_type"] != access_type:
                continue
            if trans["offset"] != offset:
                continue

            if "guard" in trans:
                try:
                    guard_result = trans["guard"](val, self)

                    # Default: only match transitions whose guards are provably true
                    # Special-case VIOLATION: match if the guard is satisfiable (i.e., a possible violation)
                    # and constrain the current path accordingly.
                    if isinstance(guard_result, bool):
                        if not guard_result:
                            continue
                    else:
                        if trans.get("next_state") == "VIOLATION":
                            if not self.state.solver.satisfiable(
                                extra_constraints=[guard_result]
                            ):
                                continue
                            self.state.solver.add(guard_result)
                        else:
                            if not self.state.solver.is_true(guard_result):
                                continue
                except Exception as e:
                    print(f"Guard execution failed: {e}")
                    continue

            matched_transition = trans
            break

        # 執行轉移
        if matched_transition:
            new_state = matched_transition["next_state"]
            prev_state = current_state

            # [State Change Logic]
            if new_state != prev_state:
                self.vars["internal_state"] = new_state
                print(f"[FSM] Transition: {prev_state} -> {new_state}")

                # [Important] 狀態改變時，清除 Volatility Cache
                # 這樣進入新狀態後，第一次讀取 SR1 會重新產生符號變數
                keys_to_clear = [
                    k
                    for k in self.state.globals.keys()
                    if k.startswith("sym_injected_")
                ]
                for k in keys_to_clear:
                    del self.state.globals[k]

            if new_state == "VIOLATION":
                msg = matched_transition.get("error_msg", "Unknown violation")
                print(f"[FSM] !!! VIOLATION DETECTED !!! : {msg}")
                self.state.globals["violation_msg"] = msg
                return

            actions = matched_transition.get("actions", [])
            for act in actions:
                self._execute_action(act)

        # [Read Handling] 自動注入 Volatility
        if access_type == "read":
            # 1. 先讀取當前記憶體值 (可能是之前 Write 寫入的，或初始值 0)
            current_val = self.get_reg_value(offset)

            # 2. 嘗試注入符號變數 (如果當前狀態允許)
            #    這會直接修改 state.memory
            self._inject_volatility_if_needed(offset, current_val)

            # 注意：這裡不需要 return 值，因為 avatar2 hook 會再讀一次 memory，
            # 到時候就會讀到我們剛剛寫入的 symbolic value。

        # [Write Handling] Passthrough
        if access_type == "write":
            addr = self.base_addr + offset
            self.state.memory.store(
                addr,
                val,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False,
            )
