import angr
import claripy
import copy
from EFSM import I2C


class PeripheralRulePlugin(angr.SimStatePlugin):
    def __init__(self, base_addr, rules, internal_state_vars=None):
        super(PeripheralRulePlugin, self).__init__()

        self.rules = rules
        self.base_addr = base_addr
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

    def _inject_symbolic(self, offset, cur_val):
        """
        將要設為 symbolic 的 bits 設為 symbolic
        """
        current_state = self.internal_state_vars["mode"]
        symbolic_mask = I2C.STATE_SYMBOLIC.get(current_state, 0).get(offset, 0)

        if symbolic_mask == 0:
            return cur_val

        # 保持在同一個 state 內，只產生一次 symbolic variable
        cache_key = f"sym_injected_{current_state}_{offset}"
        if self.state.globals.get(cache_key, False):
            return cur_val

        self.state.memory.store(
            self.base_addr + offset,
            (cur_val & ~symbolic_mask)
            | (claripy.BVS(f"hw_{current_state}_{hex(offset)}", 32) & symbolic_mask),
            endness=self.state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )
        self.state.globals[cache_key] = True
        print(
            f"Injected symbolic (mask: {bin(symbolic_mask)}) at offset {hex(offset)} for state {current_state}"
        )

    def handle_mmio(self, access_type, offset, val=None):
        cur_state = self.internal_state_vars["mode"]

        if cur_state == "VIOLATION":
            return

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
                for key in [
                    k
                    for k in self.state.globals.keys()
                    if k.startswith("sym_injected_")
                ]:
                    del self.state.globals[key]

            if new_state == "VIOLATION":
                print(
                    f"!!! VIOLATION DETECTED !!! : {matched_transition.get('error_msg', 'Unknown violation')}"
                )
                return

            for action in matched_transition.get("actions", []):
                self._execute_action(action)

        if access_type == "read":
            self._inject_symbolic(offset, self.get_reg_value(offset))
        elif access_type == "write":
            self.state.memory.store(
                self.base_addr + offset,
                val,
                endness=self.state.arch.memory_endness,
                disable_actions=True,
                inspect=False,
            )
