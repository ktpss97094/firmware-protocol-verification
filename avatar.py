"""
Clock Stretching Spec

* Blocking Mode
    1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
    2. write DR 前，若 TxE bit 為 0，則違反
    3. 最後一個 set STOP bit 前，若 BTF bit 為 0，則違反
* DMA Mode
    1. clear ADDR bit (I2C_Master_ADDR() 內) 前，若 ADDR bit 為 0，則違反
    2. (無法檢查)
    3. set STOP bit (I2C_MasterTransmit_BTF() 內) 前，若 BTF bit 為 0，則違反
"""

import avatar2
import angr
import claripy
from typing import NamedTuple
import archinfo
import json
from PeripheralRulePlugin import PeripheralRulePlugin


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


def get_symbol_addr(symbol_name, is_variable):
    sym = proj.loader.main_object.get_symbol(symbol_name)

    if sym:
        addr = sym.rebased_addr

        # Thumb Mode
        if not is_variable:
            addr = proj.arch.x_addr(addr, thumb=THUMB_MODE)

        return addr
    else:
        raise ValueError(f"Symbol '{symbol_name}' not found in ELF")


OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"
ELF_PATH = "firmwares/STM32/I2C/DMA_Mode/build/clockstretching.elf"
BEGIN_SYMBOL = "HAL_I2C_Master_Transmit_DMA"
END_SYMBOL = "END_SYMBOLIC_EXECUTION"
BEGIN_VERIFICATION_SYMBOL = "BEGIN_VERIFICATION"
END_VERIFICATION_SYMBOL = "END_VERIFICATION"
SYSTICK_VARIABLE_SYMBOL = "uwTick"
THUMB_MODE = True

RAM = MemoryRegion(start=0x20000000, size=0x30000)
CCMRAM = MemoryRegion(start=0x10000000, size=0x10000)
FLASH = MemoryRegion(start=0x08000000, size=0x200000)
I2C1 = I2C(start=0x40005400, size=0x400)
DMA1 = MemoryRegion(start=0x40026000, size=0x400)
VECTOR_TABLE = MemoryRegion(start=0x00000000, size=0x400)

I2C_NAME = [
    "I2C_CR1",
    "I2C_CR2",
    "I2C_OAR1",
    "I2C_OAR2",
    "I2C_DR",
    "I2C_SR1",
    "I2C_SR2",
    "I2C_CCR",
    "I2C_TRISE",
    "I2C_FLTR",
]
I2C_NOT_RESERVED_MASK = {
    "I2C_CR1": 0b00000000000000001011111111111011,
    "I2C_CR2": 0b00000000000000000001111100111111,
    "I2C_OAR1": 0b00000000000000001000001111111111,
    "I2C_OAR2": 0b00000000000000000000000011111111,
    "I2C_DR": 0b00000000000000000000000011111111,
    "I2C_SR1": 0b00000000000000001101111111011111,
    "I2C_SR2": 0b00000000000000001111111111110111,
    "I2C_CCR": 0b00000000000000001100111111111111,
    "I2C_TRISE": 0b00000000000000000000000000111111,
    "I2C_FLTR": 0b00000000000000000000000000011111,
}
# I2C_HARDWARE_DEPENDENT_MASK = {
#     "I2C_CR1": 0b00000000000000000011111100000000,
#     "I2C_CR2": 0b00000000000000000000000000000000,
#     "I2C_OAR1": 0b00000000000000000000000000000000,
#     "I2C_OAR2": 0b00000000000000000000000000000000,
#     "I2C_DR": 0b00000000000000000000000011111111,
#     "I2C_SR1": 0b00000000000000001101111111011111,
#     "I2C_SR2": 0b00000000000000001111111111110111,
#     "I2C_CCR": 0b00000000000000000000000000000000,
#     "I2C_TRISE": 0b00000000000000000000000000000000,
#     "I2C_FLTR": 0b00000000000000000000000000000000,
# }
I2C_HARDWARE_DEPENDENT_MASK = {
    "I2C_CR1": 0b00000000000000000000000000000000,
    "I2C_CR2": 0b00000000000000000000000000000000,
    "I2C_OAR1": 0b00000000000000000000000000000000,
    "I2C_OAR2": 0b00000000000000000000000000000000,
    "I2C_DR": 0b00000000000000000000000011111111,
    "I2C_SR1": 0b00000000000000001101111111011111,
    "I2C_SR2": 0b00000000000000001111111111110111,
    "I2C_CCR": 0b00000000000000000000000000000000,
    "I2C_TRISE": 0b00000000000000000000000000000000,
    "I2C_FLTR": 0b00000000000000000000000000000000,
}
I2C_RESET_VAL = {
    "I2C_CR1": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_CR2": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_OAR1": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_OAR2": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_DR": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_SR1": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_SR2": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_CCR": claripy.BVV(0b00000000000000000000000000000000, 32),
    "I2C_TRISE": claripy.BVV(0b00000000000000000000000000000010, 32),
    "I2C_FLTR": claripy.BVV(0b00000000000000000000000000000000, 32),
}

HAL_OK = 0x00
HAL_ERROR = 0x01
HAL_BUSY = 0x02
HAL_TIMEOUT = 0x03

found_violations = []

avatar = avatar2.Avatar(
    arch=avatar2.archs.arm.ARM_CORTEX_M3, output_directory="./avatar2_output"
)
proj = angr.Project(
    ELF_PATH,
    auto_load_libs=False,
    arch=archinfo.ArchARMCortexM(endness=archinfo.Endness.LE),
)

BEGIN_ADDR = get_symbol_addr(BEGIN_SYMBOL, is_variable=False)
END_ADDR = get_symbol_addr(END_SYMBOL, is_variable=False)
VERIFICATION_BEGIN_ADDR = get_symbol_addr(BEGIN_VERIFICATION_SYMBOL, is_variable=False)
VERIFICATION_END_ADDR = get_symbol_addr(END_VERIFICATION_SYMBOL, is_variable=False)
SYSTICK_VARIABLE_ADDR = get_symbol_addr(SYSTICK_VARIABLE_SYMBOL, is_variable=True)

"""
Avatar2 部分
"""

stm32 = avatar.add_target(
    avatar2.OpenOCDTarget,
    openocd_script=OPENOCD_INTERFACE_SCRIPT_PATH,
    additional_args=["-f", OPENOCD_TARGET_SCRIPT_PATH],
)

avatar.add_memory_range(RAM.start, RAM.size, name="sram", target=stm32)
avatar.add_memory_range(CCMRAM.start, CCMRAM.size, name="ccmram", target=stm32)
avatar.add_memory_range(FLASH.start, FLASH.size, name="flash", target=stm32)
avatar.add_memory_range(I2C1.start, I2C1.size, name="i2c1", target=stm32)
avatar.add_memory_range(DMA1.start, DMA1.size, name="dma1", target=stm32)

avatar.init_targets()
stm32.set_breakpoint(BEGIN_ADDR)
stm32.cont()
stm32.wait()
print("Hardware hit the breakpoint. Extracting state")

# https://developer.arm.com/documentation/100166/0001/Programmers-Model/Processor-core-register-summary?lang=en
# reg_names = list(stm32._arch.registers.keys())
regs = {
    "r0": stm32.read_register("r0"),
    "r1": stm32.read_register("r1"),
    "r2": stm32.read_register("r2"),
    "r3": stm32.read_register("r3"),
    "r4": stm32.read_register("r4"),
    "r5": stm32.read_register("r5"),
    "r6": stm32.read_register("r6"),
    "r7": stm32.read_register("r7"),
    "r8": stm32.read_register("r8"),
    "r9": stm32.read_register("r9"),
    "r10": stm32.read_register("r10"),
    "r11": stm32.read_register("r11"),
    "r12": stm32.read_register("r12"),
    "sp": stm32.read_register("sp"),
    "lr": stm32.read_register("lr"),
    "pc": stm32.read_register("pc"),
    # "xpsr": stm32.read_register("xpsr"),  # avatar2 沒有加入這個 register，但實際上有
}
regs["pc"] = proj.arch.x_addr(regs["pc"], thumb=THUMB_MODE)  # Thumb Mode
sram_dump = stm32.read_memory(RAM.start, size=1, num_words=RAM.size, raw=True)
ccmram_dump = stm32.read_memory(CCMRAM.start, size=1, num_words=CCMRAM.size, raw=True)
vector_table_dump = stm32.read_memory(
    FLASH.start, size=1, num_words=VECTOR_TABLE.size, raw=True
)
i2c1_dump = stm32.read_memory(I2C1.start, size=1, num_words=I2C1.size, raw=True)
dma1_dump = stm32.read_memory(DMA1.start, size=1, num_words=DMA1.size, raw=True)

avatar.shutdown()

"""
Angr 部分
"""

print("Setting up angr state")

state = proj.factory.blank_state(
    addr=regs["pc"],
    add_options={
        # ZERO_FILL_UNCONSTRAINED_MEMORY 及 ZERO_FILL_UNCONSTRAINED_REGISTERS 為指定當 Angr 讀取 Angr 未初始化的記憶體位置時，回傳 0 而不是 symbolic value
        # angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        # angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    },
)

for reg_name, value in regs.items():
    setattr(state.regs, reg_name, value)
state.memory.store(RAM.start, sram_dump)
state.memory.store(CCMRAM.start, ccmram_dump)
# 寫入 Vector Table Alias
try:
    state.memory.store(VECTOR_TABLE.start, vector_table_dump)
    print(f"Mapped Flash alias at {VECTOR_TABLE.start:#x} (Vector Table)")
except Exception as e:
    print(f"Warning: Failed to map Vector Table at {VECTOR_TABLE.start:#x}: {e}")
# 寫入 I2C1 FIXME: 應該不是用 I2C_RESET_VAL 而是用 i2c1_dump 出來的?
state.globals["symbolic_name_cnt"] = 0
for i in range(len(I2C_NAME)):
    value = claripy.BVS(f"{I2C_NAME[i]}_{state.globals['symbolic_name_cnt']}", 32) & (
        I2C_NOT_RESERVED_MASK[I2C_NAME[i]] & I2C_HARDWARE_DEPENDENT_MASK[I2C_NAME[i]]
    ) | (
        I2C_RESET_VAL[I2C_NAME[i]]
        & ~(
            I2C_NOT_RESERVED_MASK[I2C_NAME[i]]
            & I2C_HARDWARE_DEPENDENT_MASK[I2C_NAME[i]]
        )
    )
    state.memory.store(
        I2C1.start + i * 4,
        value,
    )
state.memory.store(DMA1.start, dma1_dump)
state.globals["symbolic_name_cnt"] += 1

"""
設定驗證開始時間點
"""

# state.globals["verification_enabled"] = True


def enable_verification(state):
    state.globals["verification_enabled"] = True


def check_verification_addr(state):
    if THUMB_MODE:
        return (state.inspect.instruction & ~1) == (VERIFICATION_BEGIN_ADDR & ~1)
    else:
        return state.inspect.instruction == VERIFICATION_BEGIN_ADDR


state.inspect.b(
    "instruction",
    when=angr.BP_BEFORE,
    condition=check_verification_addr,
    action=enable_verification,
)

"""
攔截 read/write I2C1 位址的指令
"""


def on_read_I2C1(state):
    addr = state.solver.eval(state.inspect.mem_read_address)
    idx = int((addr - I2C1.start) / 4)

    prev_val = state.memory.load(
        addr,
        4,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )
    val = claripy.BVS(f"{I2C_NAME[idx]}_{state.globals['symbolic_name_cnt']}", 32) & (
        I2C_NOT_RESERVED_MASK[I2C_NAME[idx]]
        & I2C_HARDWARE_DEPENDENT_MASK[I2C_NAME[idx]]
    ) | (
        prev_val
        & ~(
            I2C_NOT_RESERVED_MASK[I2C_NAME[idx]]
            & I2C_HARDWARE_DEPENDENT_MASK[I2C_NAME[idx]]
        )
    )
    state.globals["symbolic_name_cnt"] += 1

    # 額外處理: ADDR set 之後就不能再把 ADDR 設為 symbolic 了，只有 read SR1, SR2 之後才會 clear ADDR，所以 ADDR set 之後不會有 ADDR 0 的可能 (reference manual p871: This bit is cleared by software reading SR1 register followed reading SR2)
    # if addr == I2C1.SR1:
    #     sr1 = state.memory.load(
    #         I2C1.SR1,
    #         4,
    #         endness=state.arch.memory_endness,
    #         disable_actions=True,
    #         inspect=False,
    #     )

    #     # 如果目前的 state ADDR 一定是 1
    #     if not state.solver.satisfiable(
    #         extra_constraints=[claripy.Not((sr1 & I2C1.SR1_ADDR_MASK) != 0)]
    #     ):
    #         state.add_constraints((val & I2C1.SR1_ADDR_MASK) != 0)  # 強制 ADDR bit 為 1

    # if addr == I2C1.SR1:
    #     # 如果先前的 ADDR 是 0，則此 constraint 無意義；如果先前的 ADDR 是 1，則新的 ADDR 一定要是 1
    #     state.add_constraints(
    #         ((prev_val & I2C1.SR1_ADDR_MASK) | (val & I2C1.SR1_ADDR_MASK))
    #         == (val & I2C1.SR1_ADDR_MASK)
    #     )

    #     state.globals["SR1_read"] = True
    # elif addr == I2C1.SR2:
    #     if state.globals.get("SR1_read", False):
    #         # clear ADDR bit
    #         # state.memory.store(
    #         #     I2C1.SR1,
    #         #     state.memory.load(
    #         #         I2C1.SR1,
    #         #         4,
    #         #         endness=state.arch.memory_endness,
    #         #         disable_actions=True,
    #         #         inspect=False,
    #         #     )
    #         #     & ~I2C1.SR1_ADDR_MASK,
    #         #     endness=state.arch.memory_endness,
    #         #     disable_actions=True,
    #         #     inspect=False,
    #         # )

    #         state.globals["SR1_read"] = False
    state.add_constraints(*state.rules.handle_memory_read(addr, prev_val, val))

    state.memory.store(
        addr,
        val,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )

    if state.globals.get("verification_enabled", False):
        if addr == I2C1.SR2:
            sr1 = state.memory.load(
                I2C1.SR1,
                4,
                endness=state.arch.memory_endness,
                disable_actions=True,
                inspect=False,
            )

            # [Spec 1]
            # firmware 並不會直接 clear ADDR (ADDR 為 read only)，是先 read SR1 再 read SR2 時由 hardware 自動清除
            violation_condition = (sr1 & I2C1.SR1_ADDR_MASK) == 0
            if state.solver.satisfiable(extra_constraints=[violation_condition]):
                found_violations.append(True)
                state.add_constraints(claripy.Not(violation_condition))
                print("Found a violation path")


def on_write_I2C1(state):
    addr = state.solver.eval(state.inspect.mem_write_address)
    val = state.solver.eval(state.inspect.mem_write_expr)

    if addr == I2C1.CR1:
        cr2 = state.memory.load(
            I2C1.CR2,
            4,
            endness=state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )

        if (
            state.solver.is_true(cr2 & I2C.CR2_ITEVTEN_MASK != 0)
            and (val & I2C.CR1_START_MASK) != 0
        ):  # FIXME: 錯!!! 要在 SB bit set 時才會觸發 IRQ
            print("[!] Interrupt condition met. Pending IRQ #31...")
            state.globals["pending_irq"] = 31

    if state.globals.get("verification_enabled", False):
        sr1 = state.memory.load(
            I2C1.SR1,
            4,
            endness=state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )

        # [Spec 2]
        # if addr == I2C1.DR:
        #     violation_condition = (sr1 & I2C.SR1_TXE_MASK) == 0
        #     if state.solver.satisfiable(extra_constraints=[violation_condition]):
        #         found_violations.append(True)
        #         state.add_constraints(claripy.Not(violation_condition))
        #         print("Found a violation path")

        # [Spec 3 (Part 1)]
        # if addr == I2C1.CR1 and (val & I2C.CR1_STOP_MASK != 0):
        #     violation_condition = (sr1 & I2C.SR1_BTF_MASK) == 0
        #     if state.solver.satisfiable(extra_constraints=[violation_condition]):
        #         state.globals["spec3_violation_pending"] = True


def read_in_I2C1(state):
    try:
        return (
            I2C1.start
            <= state.solver.eval(state.inspect.mem_read_address)
            < I2C1.start + I2C1.size
        )
    except Exception:
        return False


def write_in_I2C1(state):
    try:
        return (
            I2C1.start
            <= state.solver.eval(state.inspect.mem_write_address)
            < I2C1.start + I2C1.size
        )
    except Exception:
        return False


state.inspect.b(
    "mem_read", when=angr.BP_BEFORE, condition=read_in_I2C1, action=on_read_I2C1
)

state.inspect.b(
    "mem_write", when=angr.BP_BEFORE, condition=write_in_I2C1, action=on_write_I2C1
)

"""
攔截 Arm SysTick
"""


def on_read_SysTick(state):
    addr = state.solver.eval(state.inspect.mem_read_address)
    origin_value = state.memory.load(
        addr,
        4,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )

    new_value = origin_value + 5  # 每讀取一次 SysTick，SysTick 加 5
    state.memory.store(
        addr,
        new_value,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )
    state.inspect.mem_read_expr = new_value


def read_in_SysTick(state):
    try:
        return (
            state.solver.eval(state.inspect.mem_read_address) == SYSTICK_VARIABLE_ADDR
        )
    except Exception:
        return False


state.inspect.b(
    "mem_read", when=angr.BP_BEFORE, condition=read_in_SysTick, action=on_read_SysTick
)

"""
設定 interrupt
"""

MAGIC_RETURN_ADDR = 0xFFFFFFFF  # 特殊地址，用於攔截 ISR 返回


def push_stack(state, value):
    # 模擬 Cortex-M 堆疊操作 (Full Descending)
    state.regs.sp -= 4
    state.memory.store(state.regs.sp, value, endness=state.arch.memory_endness)


def pop_stack(state):
    val = state.memory.load(state.regs.sp, 4, endness=state.arch.memory_endness)
    state.regs.sp += 4
    return val


def fire_interrupt(state, irq_num):
    print(f"\n[!] Triggering IRQ #{irq_num} at PC: {state.addr:#x}")

    # 1. 保存 Context (Cortex-M Exception Frame)
    # 堆疊順序: xPSR, PC, LR, R12, R3, R2, R1, R0
    # 這裡簡化處理 xPSR，設為 0
    xpsr = claripy.BVV(0, 32)
    current_pc = state.regs.pc
    current_lr = state.regs.lr

    push_stack(state, xpsr)
    push_stack(state, current_pc)
    push_stack(state, current_lr)
    push_stack(state, state.regs.r12)
    push_stack(state, state.regs.r3)
    push_stack(state, state.regs.r2)
    push_stack(state, state.regs.r1)
    push_stack(state, state.regs.r0)

    # 2. 設定 LR 為 Magic Return Address
    # 當 ISR 執行 BX LR 時，會跳轉到這個地址，觸發我們的 Hook
    state.regs.lr = MAGIC_RETURN_ADDR

    # 3. 查表並跳轉
    # IRQ #31 (I2C1_EV) 對應 Exception Number 47 (16 + 31)
    isr_ptr_addr = VECTOR_TABLE.start + 4 * (16 + irq_num)

    # 從記憶體讀取 ISR 地址 (注意要處理 Endness)
    isr_addr = state.memory.load(
        isr_ptr_addr,
        4,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )

    print(f"    -> Jumping to ISR at {state.solver.eval(isr_addr):#x}")
    state.regs.pc = isr_addr


def isr_return_hook(state):
    print(f"\n[!] ISR Return triggered at {state.addr:#x}")

    # 恢復 Context (順序與 push 相反)
    state.regs.r0 = pop_stack(state)
    state.regs.r1 = pop_stack(state)
    state.regs.r2 = pop_stack(state)
    state.regs.r3 = pop_stack(state)
    state.regs.r12 = pop_stack(state)
    state.regs.lr = pop_stack(state)
    return_pc = pop_stack(state)
    _ = pop_stack(state)  # Pop xPSR

    print(f"    -> Returning to original context at {state.solver.eval(return_pc):#x}")
    state.regs.pc = return_pc


proj.hook(MAGIC_RETURN_ADDR, isr_return_hook, length=0)

"""
設定 rules
"""

angr.SimState.register_default("rules", PeripheralRulePlugin)
with open("rules.json", "r") as f:
    json_rules = json.load(f)
state.rules.load_rules(json_rules)

"""
設定 simulation_manager
"""

simgr = proj.factory.simgr(state)

# 設定 loop 執行上限次數
simgr.use_technique(
    angr.exploration_techniques.LoopSeer(
        cfg=proj.analyses.CFGFast(normalize=True), bound=10
    )
)


def monitor_exploration(simgr):
    """
    監控 state 的狀況
    """

    for state in simgr.active:
        pending_irq = state.globals.get("pending_irq", None)
        if pending_irq is not None:
            # 清除 Flag
            state.globals.pop("pending_irq")
            # 觸發中斷 (此時 state 已經在一個 Block 執行結束的邊界，PC 是乾淨的下一條指令)
            fire_interrupt(state, pending_irq)

    print(f"Step: Active={len(simgr.active)}, Found={len(simgr.found)}")

    # if n_active > 500:
    #     print("State explosion detected! Aborting exploration.")
    #     simgr.move(from_stash="active", to_stash="exploded")
    #     exit(1)

    return simgr


simgr.explore(
    find=[VERIFICATION_END_ADDR, END_ADDR],
    num_find=float("inf"),
    step_func=monitor_exploration,
)

if len(simgr.errored) > 0:
    print(f"Errors Detected: {len(simgr.errored)} states died")
    for err in simgr.errored:
        print("-" * 30)
        print(f"  Error: {err.error}")
        print(f"  Crashed at (PC): {hex(err.state.addr)}")

        try:
            # 取得執行歷史 (最後 10 個 Basic Blocks)
            history = list(err.state.history.bbl_addrs)[-10:]
            print("  Traceback (Last 10 Basic Blocks):")
            for h_addr in history:
                print(f"    -> {hex(h_addr)}")

            if history:
                last_block_addr = history[-1]
                block = proj.factory.block(last_block_addr)
                print(f"  Last Block Assembly ({hex(last_block_addr)}):")
                block.pp()  # 印出最後執行的組語，讓我們看看它是 POP 還是 BLX

            sp_val = err.state.solver.eval(err.state.regs.sp)
            lr_val = err.state.solver.eval(err.state.regs.lr)
            r0_val = err.state.solver.eval(err.state.regs.r0)
            print("  Registers at crash:")
            print(f"    SP: {hex(sp_val)}")
            print(f"    LR: {hex(lr_val)} (Return Address)")
            print(f"    R0: {hex(r0_val)}")

        except Exception as e:
            print(f"  Could not extract debug info: {e}")
        print("-" * 30)
elif len(found_violations) > 0:
    print(f"Verification FAILURE! Found {len(found_violations)} violation path(s)")
elif len(simgr.found) > 0:
    # [Spec 3 (Part 2)]
    # for state in simgr.found:
    #     r0 = state.solver.eval(state.regs.r0)

    #     print(f"r0 = {r0}")

    #     if r0 == HAL_OK and state.globals.get("spec3_violation_pending", False):
    #         found_violations.append(True)
    #         print("Found a violation path")
    # if len(found_violations) > 0:
    #     print(f"Verification FAILURE! Found {len(found_violations)} violation path(s)")
    # else:
    print(f"Verification SUCCESS! Found {len(simgr.found)} paths that reached the end")
else:
    print("No state reached the end")
