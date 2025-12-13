import angr
import claripy


class PeripheralRulePlugin(angr.SimStatePlugin):
    def __init__(self, rules=None, internal_vars=None):
        super(PeripheralRulePlugin, self).__init__()
        self.rules = rules if rules is not None else []
        self.vars = internal_vars if internal_vars is not None else {}

        # 快取: (trigger address, trigger type) -> [rules]
        self.trigger_map = {}
        # 快取: address -> sticky bit mask
        self.sticky_masks = {}

        if self.rules:
            self._preprocess_rules()

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        # 當 state 分支時，複製變數狀態，但規則本身共享
        return PeripheralRulePlugin(rules=self.rules, internal_vars=self.vars.copy())

    def merge(self, others, merge_conditions, common_ancestor=None):
        # 1. 收集所有涉及的變數名稱
        all_keys = set(self.vars.keys())
        for o in others:
            all_keys.update(o.vars.keys())

        # 2. 針對每個變數進行合併
        for key in all_keys:
            # 取得每個 state 的值，若無則預設為 0
            # self 的值對應 merge_conditions[0]
            val_self = self.vars.get(key, 0)

            # others 的值對應 merge_conditions[1:]
            vals_others = [o.vars.get(key, 0) for o in others]

            # 3. 使用 claripy.ite_cases 建立條件數值
            # 邏輯: If condition_1 then val_1, elif condition_2 then val_2 ... else val_self
            # 詳見 Angr 文件關於 Merging
            merged_val = claripy.ite_cases(
                zip(merge_conditions[1:], vals_others), val_self
            )

            self.vars[key] = merged_val

        # 回傳 True 表示合併成功
        return True

    def load_rules(self, json_rules):
        """外部呼叫此函式載入 JSON"""
        self.rules = json_rules
        self._preprocess_rules()

    def _preprocess_rules(self):
        """解析規則，建立查找表與自動推論 Sticky Bits"""
        self.trigger_map = {}
        self.sticky_masks = {}

        for rule in self.rules:
            # 1. 建立 Trigger Map
            trig_addr = int(rule["trigger"]["address"], 16)
            trig_type = rule["trigger"]["type"]  # "R" or "W"
            key = (trig_addr, trig_type)

            if key not in self.trigger_map:
                self.trigger_map[key] = []
            self.trigger_map[key].append(rule)

            # 2. 自動推論 Sticky Bits
            # 掃描所有 Action，如果是 Write Memory (W)，表示該 bit 會被硬體(規則)清除
            # 這些 bit 在沒被清除時，應該保持 Sticky
            actions = rule["action"]
            if isinstance(actions, dict):
                actions = [actions]

            for act in actions:
                if act["type"] == "W":  # Write Memory
                    target_addr = int(act["address"], 16)
                    bit = act.get("bit")
                    if bit is not None:
                        if target_addr not in self.sticky_masks:
                            self.sticky_masks[target_addr] = 0
                        self.sticky_masks[target_addr] |= 1 << bit

    def _check_condition(self, condition):
        """檢查規則的 Condition (支援 VR - Variable Read)"""
        if condition is None:
            return True

        if condition["type"] == "VR":
            # 檢查內部變數是否符合
            current_val = self.vars.get(condition["flag_name"], 0)  # 預設為 0
            return current_val == condition["value"]

        return False

    def _execute_actions(self, actions, state):
        """執行規則的 Actions (支援 VW 和 W)"""
        if isinstance(actions, dict):
            actions = [actions]

        force_clear_mask = 0

        for act in actions:
            if act["type"] == "VW":  # Variable Write
                self.vars[act["flag_name"]] = act["value"]

            elif act["type"] == "W":  # Memory Write (Bit manipulation)
                bit = act.get("bit")
                val = act["value"]

                # 目前只處理 clear bit (val=0) 的情況來做約束
                if bit is not None and val == 0:
                    # 這裡我們不直接寫記憶體，而是回傳 mask 讓外部施加約束
                    # 因為我們正在處理的是符號變數的生成過程
                    force_clear_mask |= 1 << bit

        return force_clear_mask

    def handle_memory_read(self, addr, prev_val, new_val):
        constraints = []

        # 1. 查找是否有觸發規則
        triggered_rules = self.trigger_map.get((addr, "R"), [])

        # force_clear_mask 改為符號變數 (預設為 0)
        force_clear_mask = claripy.BVV(0, 32)

        for rule in triggered_rules:
            # check_condition 現在回傳的是符號布林值 (AST Bool)
            # 例如: (SR1_read == 1)
            cond = self._check_condition(rule["condition"])

            # 計算此規則想要 Clear 的 mask
            rule_mask_val = 0
            actions = rule["action"]
            if isinstance(actions, dict):
                actions = [actions]
            for act in actions:
                if (
                    act["type"] == "W"
                    and act.get("bit") is not None
                    and act["value"] == 0
                ):
                    rule_mask_val |= 1 << act["bit"]

            # [關鍵] 條件式應用 mask: 如果條件成立，則 mask 生效，否則為 0
            # 這樣即使 cond 是符號變數也能運作
            current_rule_mask = claripy.If(
                cond, claripy.BVV(rule_mask_val, 32), claripy.BVV(0, 32)
            )

            # 累積 Mask
            force_clear_mask |= current_rule_mask

            # 處理 Internal Variable Update (VW) 的副作用比較複雜，
            # 在符號化合併下，建議將 VW 視為產生一個新的符號變數，這需要更進階的處理。
            # 簡單驗證場景下，若不需要精確追蹤合併後的變數寫入，可暫時忽略 VW 的符號化副作用。

        # 2. 自動應用 Sticky Logic
        sticky_mask_val = self.sticky_masks.get(addr, 0)

        if sticky_mask_val != 0:
            sticky_mask = claripy.BVV(sticky_mask_val, 32)

            # 有效的 sticky mask = 原始 sticky mask & (非強制清除的部分)
            # 注意: force_clear_mask 是符號變數，所以這裡運算都是符號運算
            effective_sticky_mask = sticky_mask & (~force_clear_mask)

            # 這裡的 If 判斷是針對 mask 是否為 0 (優化用)，可以用 solver.is_true 檢查，或直接加約束
            # 為了保險，直接加約束，讓 solver 去處理
            constraints.append(
                (prev_val & effective_sticky_mask) | (new_val & effective_sticky_mask)
                == (new_val & effective_sticky_mask)
            )

        # 應用強制清除的約束
        constraints.append((new_val & force_clear_mask) == 0)

        return constraints
