"""
I2C Master Clock Stretching Spec

* Blocking Mode
    1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
    2. write DR 前，若 TxE bit 為 0 且 BTF bit 為 0 且 SB bit 非必為 1 且 ADD10 非必為 1，則違反
    3. Precondition: Size > 0
        set STOP bit 前，若 BTF bit 為 0 且回傳 HAL_OK，則違反
    Symbolic Variables:
        SR2 (BUSY)
        uwTick
        SR1 (SB, ADD10, AF, ADDR, TxE, BTF)
* Interrupt Mode
    1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
    2. write DR 前，若 TxE bit 為 0 且 BTF bit 為 0 且 SB bit 非必為 1 且 ADD10 非必為 1，則違反
    3. Precondition: Size > 0
        set STOP bit 前，若 BTF bit 為 0，則違反
    Symbolic Variables:
        SR2 (TRA)
        SR1 (SB, ADD10, ADDR, TxE, BTF)
* DMA Mode
    1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
        > 考慮: I2C_Master_ADDR()
        > 忽略: I2C_Slave_ADDR() (slave mode)
    2. Precondition: Size > 0, DMAEN = 0
        set STOP bit 前，若 BTF bit 為 0，則違反
        > 考慮: I2C_MasterTransmit_BTF()
        > 忽略: I2C_Master_ADDR() (receiver mode 才有 set STOP), I2C_MasterTransmit_TXE() (Size == 0 才有 set STOP), I2C_MemoryTransmit_TXE_BTF() (memory mode), I2C_MasterReceive_BTF() (receiver mode)
    Symbolic Variables:
        SR2 (TRA)
        SR1 (SB, ADD10, ADDR, TxE, BTF)

Stethogram AT Command Escape Sequence Spec

1. send_escape_sequence() 執行時:
    (1) 此次發送距離上一次 UART 傳輸結束的時間間隔必須 >= 1 秒
    (2) 發送內容須為 +++
    (3) 發送結束後，距離下一次 UART 傳輸開始的時間間隔必須 >= 1 秒
"""

import angr
import claripy
from angr.sim_type import SimTypeInt
from enum import IntEnum
from project.types import (
    MemoryRegion,
    MMIOMemoryRegion,
    VariableMemoryRegion,
    BaseSpecs,
)
from project import utils


class I2C(MMIOMemoryRegion):
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
    SR1_ADD10_MASK = 1 << 3
    SR1_BTF_MASK = 1 << 2
    SR1_ADDR_MASK = 1 << 1
    SR1_SB_MASK = 1 << 0

    SR2_TRA_MASK = 1 << 2
    SR2_BUSY_MASK = 1 << 1

    def read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        match offset:
            case self.SR1_OFFSET:
                state.globals[f"{self.name}_SR1_read"] = True

            case self.SR2_OFFSET:
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False
                    sr1 = utils.load(state, self.start + self.SR1_OFFSET)

                    # [Spec 1] MODIFY:
                    violation_condition = sr1[1] == 0
                    if state.solver.satisfiable(
                        extra_constraints=[violation_condition]
                    ):
                        print("Found a violation path")
                        state.globals["violation"] = True

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    utils.clear_bits(
                        state, self.start + self.SR1_OFFSET, I2C.SR1_ADDR_MASK
                    )

            case self.DR_OFFSET:
                # (BTF) Cleared by software by either a read or write in the DR register
                utils.clear_bits(state, self.start + self.SR1_OFFSET, I2C.SR1_BTF_MASK)

        symbolic_mask = self.symbolic_masks.get(self.start + offset, 0)
        prev_val = utils.load(state, self.start + offset)
        for i in range(32):
            mask = symbolic_mask & (1 << i)
            # 如果值是 symbolic，且有被 constraint 過，就不再新增一個新的 symbolic variable
            if (
                mask
                and prev_val[i].symbolic
                and not (
                    state.solver.min(prev_val[i]) == 0
                    and state.solver.max(prev_val[i]) == ((1 << prev_val[i].size()) - 1)
                )
            ):
                symbolic_mask &= ~(1 << i)

        state.inspect.mem_read_expr = utils.set_symbolic(
            state, self.start + offset, symbolic_mask, f"{self.name}_{offset:#x}"
        )

    def write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        val = state.inspect.mem_write_expr
        offset = addr - self.start

        match offset:
            case self.CR1_OFFSET:
                sr1 = utils.load(state, self.start + self.SR1_OFFSET)

                # [Spec 3 (Part 1)] MODIFY:
                if not state.solver.satisfiable(
                    extra_constraints=[val[9] == 0]
                ) and state.solver.satisfiable(extra_constraints=[sr1[2] == 0]):
                    print("Found a violation path")
                    state.globals["violation"] = True

                # set START bit 時進入 address phase
                if not state.solver.satisfiable(extra_constraints=[val[8] == 0]):
                    state.globals["is_address_phase"] = True

                # set START bit
                if not state.solver.satisfiable(extra_constraints=[val[8] == 0]):
                    # (SB) Set when a Start condition generated
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    utils.set_symbolic(
                        state,
                        self.start + self.SR1_OFFSET,
                        I2C.SR1_SB_MASK | I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                        f"{self.name}_{self.SR1_OFFSET:#x}_SB/TxE/BTF",
                    )

                    # (BUSY) Set by hardware on detection of SDA or SCL low
                    # utils.set_symbolic(
                    #     state,
                    #     self.start + self.SR2_OFFSET,
                    #     I2C.SR2_BUSY_MASK,
                    #     f"{self.name}_{self.SR2_OFFSET:#x}_BUSY",
                    # )
                    # (TRA) It is also cleared by hardware after ..., repeated Start condition
                    utils.set_symbolic(
                        state,
                        self.start + self.SR2_OFFSET,
                        I2C.SR2_TRA_MASK,
                        f"{self.name}_{self.SR2_OFFSET:#x}_TRA",
                    )

                # set STOP bit
                if not state.solver.satisfiable(extra_constraints=[val[9] == 0]):
                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    utils.set_symbolic(
                        state,
                        self.start + self.SR1_OFFSET,
                        I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                        f"{self.name}_{self.SR1_OFFSET:#x}_TxE/BTF",
                    )

                    # (BUSY) cleared by hardware on detection of a Stop condition
                    # utils.set_symbolic(
                    #     state,
                    #     self.start + self.SR2_OFFSET,
                    #     I2C.SR2_BUSY_MASK,
                    #     f"{self.name}_{self.SR2_OFFSET:#x}_BUSY",
                    # )
                    # (TRA) It is also cleared by hardware after detection of Stop condition
                    utils.set_symbolic(
                        state,
                        self.start + self.SR2_OFFSET,
                        I2C.SR2_TRA_MASK,
                        f"{self.name}_{self.SR2_OFFSET:#x}_TRA",
                    )

            case self.DR_OFFSET:
                sr1 = utils.load(state, self.start + self.SR1_OFFSET)

                # reference manual p870: TxE is not set during address phase。所以在 address phase 不能檢查 Spec 2
                if state.globals.get("is_address_phase", False):
                    # 10-bit addressing 的 addressing phase 會 write 兩次 DR。第一次 write (header) 時是 11110xxx
                    if not state.solver.satisfiable(
                        extra_constraints=[(val & 0xF8) != 0xF0]
                    ):
                        state.globals["is_10bit"] = True
                    else:
                        state.globals["is_address_phase"] = False

                        # (TRA) This bit is set depending on the R/W bit of the address byte, at the end of total address phase
                        if not state.solver.satisfiable(
                            extra_constraints=[(val & 1) != 0]
                        ):
                            utils.set_bits(
                                state, self.start + self.SR2_OFFSET, I2C.SR2_TRA_MASK
                            )
                        elif not state.solver.satisfiable(
                            extra_constraints=[(val & 1) != 1]
                        ):
                            utils.clear_bits(
                                state, self.start + self.SR2_OFFSET, I2C.SR2_TRA_MASK
                            )

                # [Spec 2] MODIFY:
                if state.solver.satisfiable(
                    extra_constraints=[
                        sr1[7] == 0,
                        sr1[2] == 0,
                        sr1[0] != 1,
                        sr1[3] != 1,
                    ]
                ):
                    print("Found a violation path")
                    state.globals["violation"] = True

                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either a read or write in the DR register
                utils.clear_bits(
                    state,
                    self.start + self.SR1_OFFSET,
                    I2C.SR1_TXE_MASK | I2C.SR1_BTF_MASK,
                )

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    utils.clear_bits(
                        state, self.start + self.SR1_OFFSET, I2C.SR1_SB_MASK
                    )

                    if state.globals.get("is_10bit", False) and not state.globals.get(
                        "is_address_phase", False
                    ):
                        # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                        utils.clear_bits(
                            state, self.start + self.SR1_OFFSET, I2C.SR1_ADD10_MASK
                        )

                if state.globals.get("is_10bit", False) and state.globals.get(
                    "is_address_phase", False
                ):
                    # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                    utils.set_symbolic(
                        state,
                        self.start + self.SR1_OFFSET,
                        I2C.SR1_ADD10_MASK,
                        f"{self.name}_{self.SR1_OFFSET:#x}_ADD10",
                    )


class SysTickVariable(VariableMemoryRegion):
    def read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        origin_val = utils.load(state, addr)

        delta = claripy.BVS(f"{self.name}_sym_{state.globals.get('sym_cnt', 0)}", 32)
        state.globals["sym_cnt"] = state.globals.get("sym_cnt", 0) + 1
        state.add_constraints(delta >= 0)
        new_val = origin_val + delta

        utils.store(state, addr, new_val)
        state.inspect.mem_read_expr = new_val


class Specs(BaseSpecs):
    class HAL_StatusTypeDef(IntEnum):
        HAL_OK = 0x00
        HAL_ERROR = 0x01
        HAL_BUSY = 0x02
        HAL_TIMEOUT = 0x03

    def _define_specs(self):
        # TODO: 自動生成
        # self.SYMBOLIC_MASKS = {
        #     0x40005414: 0b00000000000000000000010010001111,
        #     0x40005418: 0b00000000000000000000000000000010,
        #     self.MEMORY_REGIONS["SysTickVariable"].start: 0b11111111111111111111111111111111,
        # }
        self.SYMBOLIC_MASKS = {
            0x40005414: 0b00000000000000000000000000001011,
            0x40005418: 0b00000000000000000000000000000100,
        }

        self.MEMORY_REGIONS = {
            "RAM": MemoryRegion(start=0x20000000, size=0x30000, name="RAM"),
            "CCMRAM": MemoryRegion(start=0x10000000, size=0x10000, name="CCMRAM"),
            "FLASH": MemoryRegion(
                start=0x08000000, size=0x200000, name="FLASH", transfer=False
            ),
            "VECTOR_TABLE_ALIAS": MemoryRegion(
                start=0x00000000,
                size=0x400,
                name="VECTOR_TABLE_ALIAS",
                physical_addr=0x08000000,
            ),
            "I2C1": I2C(start=0x40005400, size=0x400, name="I2C1"),
            "DMA1": MMIOMemoryRegion(start=0x40026000, size=0x400, name="DMA1"),
            # "SysTickVariable": SysTickVariable(
            #     start=utils.get_symbol_addr(proj, "uwTick", is_variable=True),
            #     size=0x4,
            #     name="SysTickVariable",
            # ),
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj,
            "I2C1_EV_IRQHandler",
            is_variable=False,
        )
        # self.END_ADDRS = [utils.get_symbol_addr(proj, "END_SYMBOLIC_EXECUTION", is_variable=False)]
        self.END_ADDRS = [
            0xFFFFFFE1,
            0xFFFFFFF9,
            0xFFFFFFFD,
        ]  # ARMv7-M Architecture Reference Manual §B1.5.8 Exception return behavior
        # self.DEBUG_FUNC_ADDR = utils.get_symbol_addr(proj, "SYMBOL_FUNCTION", is_variable=False)

    def init_inspect(self, state):
        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_read,
            action=self.MEMORY_REGIONS["I2C1"].read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_BEFORE,
            condition=self.MEMORY_REGIONS["I2C1"].in_region_write,
            action=self.MEMORY_REGIONS["I2C1"].write,
        )

        # state.inspect.b(
        #     "mem_read",
        #     when=angr.BP_AFTER,
        #     condition=self.MEMORY_REGIONS["SysTickVariable"].in_region_read,
        #     action=self.MEMORY_REGIONS["SysTickVariable"].read,
        # )

        # state.inspect.b(
        #     "instruction",
        #     instruction=self.DEBUG_FUNC_ADDR,
        #     action=utils.stop_and_debug,
        # )

    def precondition(self, proj, state):
        # utils.set_func_args_symbolic(proj, state, 5, {3: (1, 3)})

        # cr2_DMAEN = utils.load(
        #     state, self.MEMORY_REGIONS["I2C1"].start + I2C.CR2_OFFSET
        # )[11]
        # if state.solver.satisfiable(extra_constraints=[cr2_DMAEN == 0]):
        #     return False

        return True

    def postcondition(self, proj, simgr):
        # [Spec 3 (Part 2)]
        # for state in simgr.found:
        #     return_val = state.solver.eval(
        #         proj.factory.cc().return_val(SimTypeInt()).get_value(state)
        #     )

        #     if return_val == self.HAL_StatusTypeDef.HAL_OK and state.globals.get(
        #         "spec3_violation_pending", False
        #     ):
        #         print("Found a violation path")
        #         simgr.stashes["violated"].append(state)

        pass
