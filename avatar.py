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


class MemoryRegion(NamedTuple):
    start: int
    size: int


class I2C(MemoryRegion):
    CR1_OFFSET = 0x00
    DR_OFFSET = 0x10
    SR1_OFFSET = 0x14
    SR2_OFFSET = 0x18

    CR1_STOP_MASK = 1 << 9

    SR1_TXE_MASK = 1 << 7
    SR1_BTF_MASK = 1 << 2
    SR1_ADDR_MASK = 1 << 1

    @property
    def CR1(self):
        return self.start + self.CR1_OFFSET

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
        if THUMB_MODE and (not is_variable):
            addr |= 1

        return addr
    else:
        raise ValueError(f"Symbol '{symbol_name}' not found in ELF")


OPENOCD_INTERFACE_SCRIPT_PATH = "/usr/share/openocd/scripts/interface/stlink.cfg"
OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/stm32f4x.cfg"
ELF_PATH = "firmwares/STM32/I2C/Blocking_Mode/Hardware/build/clockstretching.elf"
START_SYMBOL = "BEGIN_VERIFICATION"
# VERIFICATION_BEGIN_SYMBOL = "BEGIN_VERIFICATION"
VERIFICATION_END_SYMBOL = "END_VERIFICATION"
SYSTICK_VARIABLE_SYMBOL = "uwTick"
THUMB_MODE = True

RAM = MemoryRegion(start=0x20000000, size=0x30000)
CCMRAM = MemoryRegion(start=0x10000000, size=0x10000)
FLASH = MemoryRegion(start=0x08000000, size=0x200000)
I2C1 = I2C(start=0x40005400, size=0x400)
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
proj = angr.Project(ELF_PATH, auto_load_libs=False)

START_ADDR = get_symbol_addr(START_SYMBOL, is_variable=False)
# VERIFICATION_BEGIN_ADDR = get_symbol_addr(VERIFICATION_BEGIN_SYMBOL, is_variable=False)
VERIFICATION_END_ADDR = get_symbol_addr(VERIFICATION_END_SYMBOL, is_variable=False)
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

avatar.init_targets()
stm32.set_breakpoint(START_ADDR)
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
if THUMB_MODE:
    regs["pc"] |= 1  # Thumb Mode
sram_dump = stm32.read_memory(RAM.start, size=1, num_words=RAM.size, raw=True)
ccmram_dump = stm32.read_memory(CCMRAM.start, size=1, num_words=CCMRAM.size, raw=True)
vector_table_dump = stm32.read_memory(
    FLASH.start, size=1, num_words=VECTOR_TABLE.size, raw=True
)
i2c1_dump = stm32.read_memory(I2C1.start, size=1, num_words=I2C1.size, raw=True)

avatar.shutdown()

"""
Angr 部分
"""

print("Setting up angr state")

state = proj.factory.blank_state(
    addr=regs["pc"],
    add_options={
        angr.options.SYMBOLIC_WRITE_ADDRESSES,
        angr.options.TRACK_MEMORY_ACTIONS,
        # ZERO_FILL_UNCONSTRAINED_MEMORY 及 ZERO_FILL_UNCONSTRAINED_REGISTERS 為指定當 Angr 讀取 Angr 未知的記憶體位置時，回傳 0 而不是 symbolic value
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
# 寫入 I2C1
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
state.globals["symbolic_name_cnt"] += 1

"""
設定驗證開始時間點

絕對不能在 angr 進入點 hook，可能有問題
"""

state.globals["verification_enabled"] = True


# def enable_verification_hook(state):
#     state.globals["verification_enabled"] = True


# proj.hook(
#     VERIFICATION_BEGIN_ADDR, enable_verification_hook, length=0
# )  # length=0 表示執行完 hook 後繼續執行原本的指令

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
    value = claripy.BVS(f"{I2C_NAME[idx]}_{state.globals['symbolic_name_cnt']}", 32) & (
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
    if addr == I2C1.SR1:
        sr1 = state.memory.load(
            I2C1.SR1,
            4,
            endness=state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )

        # 如果目前的 state ADDR 一定是 1
        if not state.solver.satisfiable(
            extra_constraints=[claripy.Not((sr1 & I2C1.SR1_ADDR_MASK) != 0)]
        ):
            state.add_constraints(
                (value & I2C1.SR1_ADDR_MASK) != 0
            )  # 強制 ADDR bit 為 1

    state.memory.store(
        addr,
        value,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )

    # if state.globals.get("verification_enabled", False):
    #     if addr == I2C1.SR2:
    #         sr1 = state.memory.load(
    #             I2C1.SR1,
    #             4,
    #             endness=state.arch.memory_endness,
    #             disable_actions=True,
    #             inspect=False,
    #         )

    #         # [Spec 1]
    #         # firmware 並不會直接 clear ADDR (ADDR 為 read only)，是先 read SR1 再 read SR2 時由 hardware 自動清除
    #         violation_condition = (sr1 & I2C1.SR1_ADDR_MASK) == 0
    #         if state.solver.satisfiable(extra_constraints=[violation_condition]):
    #             found_violations.append(True)
    #             state.add_constraints(claripy.Not(violation_condition))
    #             print("Found a violation path")


def on_write_I2C1(state):
    addr = state.solver.eval(state.inspect.mem_write_address)
    val = state.solver.eval(state.inspect.mem_write_expr)

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
        if addr == I2C1.CR1 and (val & I2C.CR1_STOP_MASK != 0):
            violation_condition = (sr1 & I2C.SR1_BTF_MASK) == 0
            if state.solver.satisfiable(extra_constraints=[violation_condition]):
                state.globals["spec3_violation_pending"] = True


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

    n_active = len(simgr.active)
    n_found = len(simgr.found)

    print(f"Step: Active={n_active}, Found={n_found}")

    # if n_active > 500:
    #     print("State explosion detected! Aborting exploration.")
    #     simgr.move(from_stash="active", to_stash="exploded")
    #     exit(1)

    return simgr


simgr.explore(
    find=VERIFICATION_END_ADDR, num_find=float("inf"), step_func=monitor_exploration
)

if len(found_violations) > 0:
    print(f"Verification FAILURE! Found {len(found_violations)} violation path(s)")
elif len(simgr.found) > 0:
    # [Spec 3 (Part 2)]
    for state in simgr.found:
        r0 = state.solver.eval(state.regs.r0)

        print(f"r0 = {r0}")

        if r0 == HAL_OK and state.globals.get("spec3_violation_pending", False):
            found_violations.append(True)
            print("Found a violation path")
    if len(found_violations) > 0:
        print(f"Verification FAILURE! Found {len(found_violations)} violation path(s)")
    else:
        print(
            f"Verification SUCCESS! Found {len(simgr.found)} paths that reached the end"
        )
elif len(simgr.errored) > 0:
    print(f"Errors Detected: {len(simgr.errored)} states died")
    for err in simgr.errored:
        print(f"  - Error: {err.error}")
        print(f"  - Last Addr: {hex(err.state.addr)}")
        print(f"  - Traceback: {err.traceback}")
else:
    print("No state reached the end")
