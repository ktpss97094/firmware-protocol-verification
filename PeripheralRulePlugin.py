import angr
import claripy
import copy


class PeripheralRulePlugin(angr.SimStatePlugin):
    def __init__(
        self,
        base_addr,
        rules,
        internal_state_vars=None,
        symbolic_policy=None,
    ):
        super(PeripheralRulePlugin, self).__init__()

        self.rules = rules
        self.base_addr = base_addr
        self.symbolic_policy = symbolic_policy
        self.internal_state_vars = (
            {
                "mode": "IDLE",
                "sr1_read_pending": False,
            }
            if internal_state_vars is None
            else internal_state_vars
        )

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return PeripheralRulePlugin(
            rules=self.rules,
            internal_state_vars=copy.deepcopy(self.internal_state_vars),
            base_addr=self.base_addr,
            symbolic_policy=self.symbolic_policy,
        )

    def get_reg_value(self, offset):
        addr = self.base_addr + offset

        try:
            return self.state.memory.load(
                addr,
                4,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False,
            )
        except Exception as e:
            print(f"Failed to load register from memory at offset {hex(offset)}: {e}")
            return 0

    def _execute_action(self, action):
        """執行 EFSM 的 action"""

        if isinstance(action, tuple):
            op = action[0]

            if op == "set_var":
                self.internal_state_vars[action[1]] = action[2]

            elif op == "set_bit":
                offset, mask = action[1], action[2]
                addr = self.base_addr + offset
                val = self.state.memory.load(
                    addr,
                    4,
                    endness=self.state.arch.memory_endness,
                    disable_actions=True,
                    inspect=False,
                )
                self.state.memory.store(
                    addr,
                    val | mask,
                    endness=self.state.arch.memory_endness,
                    disable_actions=True,
                    inspect=False,
                )

            elif op == "clear_bit":
                offset, mask = action[1], action[2]
                addr = self.base_addr + offset
                val = self.state.memory.load(
                    addr,
                    4,
                    endness=self.state.arch.memory_endness,
                    disable_actions=True,
                    inspect=False,
                )
                self.state.memory.store(
                    addr,
                    val & (~mask),
                    endness=self.state.arch.memory_endness,
                    disable_actions=True,
                    inspect=False,
                )

    def _get_symbolic_mask(self, offset):
        """
        智慧型 Mask 計算：
        掃描當前狀態的 Rules，如果發現某個 bit 有 'clear_bit' 的 action，
        且記憶體中已經是 1，則自動將其視為 Sticky Bit 並鎖定 (不再 symbolic)。
        """
        current_state_name = self.internal_state_vars["mode"]

        # 1. 取得該狀態基本的 symbolic 定義 (例如 ADDR_WAIT 中 SR1 要是 symbolic)
        base_mask = (
            0
            if self.symbolic_policy is None
            else self.symbolic_policy.mmio_symbolic_mask(current_state_name, offset)
        )

        if base_mask == 0:
            return 0

        # 2. 掃描當前狀態的所有 Rules，尋找 "Clear Intent"
        bits_pending_clear = 0
        state_rules = self.rules.get(current_state_name, [])

        # 這是一個 List of Rules，我們遍歷它們
        for rule in state_rules:
            # 只關心那些會清除 "當前讀取暫存器" 的 action
            # (雖然通常 clear 是由讀取 SR1 觸發清除 SR1，或是讀取 SR2 清除 SR1)
            # 這裡我們稍微放寬：只要這個 state 有動作會清除這個 offset 的 bit，就納入考量
            for action in rule.get("actions", []):
                if isinstance(action, tuple) and action[0] == "clear_bit":
                    target_offset = action[1]
                    target_mask = action[2]

                    if target_offset == offset:
                        bits_pending_clear |= target_mask

        # 3. 檢查記憶體中的實際數值
        # 這是推斷的核心：如果我們打算清除它，且它現在已經是 1，那它肯定是 Sticky 的
        current_val = self.get_reg_value(offset)

        # 確保是具體數值 (Concrete)
        possible_sticky_bits = current_val & bits_pending_clear
        if self.state.solver.unique(possible_sticky_bits):
            # 找出那些 "既在 memory 中是 1" 且 "又有規則準備清除它" 的 bits
            bits_to_lock = self.state.solver.eval(possible_sticky_bits)

            if bits_to_lock != 0:
                # 從 base_mask 中移除這些 bits -> 它們將不再是 symbolic
                print(
                    f"[SmartPlugin] Inferring Sticky: Locking bits {hex(bits_to_lock)} at {hex(offset)}"
                )
                base_mask &= ~bits_to_lock

        return base_mask

    def _inject_symbolic(self, offset, cur_val):
        """
        將要設為 symbolic 的 bits 設為 symbolic
        """
        current_state = self.internal_state_vars["mode"]
        symbolic_mask = self._get_symbolic_mask(offset)

        if symbolic_mask == 0:
            return cur_val

        # 保持在同一個 state 內，只產生一次 symbolic variable
        # cache_key = f"sym_injected_{current_state}_{offset}"
        # if self.state.globals.get(cache_key, False):
        #     return cur_val

        self.state.memory.store(
            self.base_addr + offset,
            (cur_val & ~symbolic_mask)
            | (
                claripy.BVS(
                    f"hw_{current_state}_{hex(offset)}_{self.state.globals.get('symbolic_cnt', 0)}",
                    32,
                )
                & symbolic_mask
            ),
            endness=self.state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )
        self.state.globals["symbolic_cnt"] = (
            self.state.globals.get("symbolic_cnt", 0) + 1
        )
        # self.state.globals[cache_key] = True
        print(
            f"Injected symbolic (mask: {bin(symbolic_mask)}) at offset {hex(offset)} for state {current_state}"
        )

    def handle_mmio(self, access_type, offset, val=None):
        """
        val: write 時是 firmware 寫入的值；read 時要由此 function 內自行讀取值
        """

        if self.state.globals.get("DEBUG", False):
            pass

        cur_state = self.internal_state_vars["mode"]
        if cur_state == "VIOLATION":
            return

        if access_type == "read":
            val = self.get_reg_value(offset)
        elif access_type == "write":
            # write 時先做 store
            self.state.memory.store(
                self.base_addr + offset,
                val,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False,
            )

        transitions = self.rules.get(cur_state, [])
        matched_transition = None

        # 線性搜尋符合條件的 transition，找到第一個符合的就跳出
        for transition in transitions:
            if (
                transition["trigger_type"] != access_type
                or transition["offset"] != offset
            ):
                continue

            if "guard" in transition:
                try:
                    guard_result = transition["guard"](val, self)

                    if not self.state.solver.satisfiable(
                        extra_constraints=[guard_result]
                    ):
                        continue
                    self.state.solver.add(guard_result)
                except Exception as e:
                    print(f"Guard execution failed: {e}")
                    continue

            matched_transition = transition
            break

        if matched_transition:
            new_state = matched_transition["next_state"]

            if new_state != cur_state:
                self.internal_state_vars["mode"] = new_state
                print(f"[FSM] Transition: {cur_state} -> {new_state}")

                # 清除符號變數 key
                # for key in [
                #     k
                #     for k in self.state.globals.keys()
                #     if k.startswith("sym_injected_")
                # ]:
                #     del self.state.globals[key]

            if new_state == "VIOLATION":
                print(
                    f"!!! VIOLATION DETECTED !!! : {matched_transition.get('error_msg', 'Unknown violation')} (pc: {hex(self.state.solver.eval(self.state.regs.pc))})"
                )
                return

            for action in matched_transition.get("actions", []):
                self._execute_action(action)

        if access_type == "read":
            self._inject_symbolic(offset, self.get_reg_value(offset))
