import avatar2
import angr
import claripy
from typing import NamedTuple


class MemoryRegion(NamedTuple):
    start: int
    size: int


class I2C(MemoryRegion):
    DR_OFFSET = 0x10
    SR1_OFFSET = 0x14

    SR1_TXE_MASK = 1 << 7

    @property
    def DR(self):
        return self.start + self.DR_OFFSET

    @property
    def SR1(self):
        return self.start + self.SR1_OFFSET


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
ELF_PATH = "firmwares/STM32/HardwareI2C/build/clockstretching.elf"
START_SYMBOL = "HAL_I2C_Master_Transmit"
VERIFICATION_BEGIN_SYMBOL = "BEGIN_VERIFICATION"
VERIFICATION_END_SYMBOL = "END_VERIFICATION"
SYSTICK_VARIABLE_SYMBOL = "uwTick"
THUMB_MODE = True

RAM = MemoryRegion(start=0x20000000, size=0x30000)
CCMRAM = MemoryRegion(start=0x10000000, size=0x10000)
FLASH = MemoryRegion(start=0x8000000, size=0x200000)
I2C1 = I2C(start=0x40005400, size=0x400)
VECTOR_TABLE_BASE_ADDR = MemoryRegion(start=0x00000000, size=0x400)

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
I2C_RESERVED_MASK = {
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
I2C_HARDWARE_DEPENDENT_MASK = {
    "I2C_CR1": 0b00000000000000000011111100000000,
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

HAL_OK = 0x00
HAL_ERROR = 0x01
HAL_BUSY = 0x02
HAL_TIMEOUT = 0x03

found_violations = []

avatar = avatar2.Avatar(
    arch=avatar2.archs.arm.ARM_CORTEX_M3, output_directory="./avatar2_output"
)
proj = angr.Project(ELF_PATH, auto_load_libs=False)

START_ADDR = get_symbol_addr(
    START_SYMBOL, is_variable=False
)  # HAL_I2C_Master_Transmit() 位址
VERIFICATION_BEGIN_ADDR = get_symbol_addr(VERIFICATION_BEGIN_SYMBOL, is_variable=False)
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
stm32.set_breakpoint(VERIFICATION_BEGIN_ADDR)
stm32.cont()
stm32.wait()
print("Hardware hit the breakpoint. Extracting state")

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
    # 'xpsr': stm32.read_register('xpsr'),
}
sram_dump = stm32.read_memory(RAM.start, size=1, num_words=RAM.size, raw=True)
ccmram_dump = stm32.read_memory(CCMRAM.start, size=1, num_words=CCMRAM.size, raw=True)
flash_dump = stm32.read_memory(FLASH.start, size=1, num_words=FLASH.size, raw=True)
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
        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
    },
)

for reg_name, value in regs.items():
    if reg_name == "xpsr":  # Angr 沒有 xpsr 這個 register
        continue

    if reg_name == "pc":  # Thumb Mode
        value |= 1

    setattr(state.regs, reg_name, value)

state.memory.store(RAM.start, sram_dump)
state.memory.store(CCMRAM.start, ccmram_dump)
state.memory.store(FLASH.start, flash_dump)
# 寫入 Vector Table Alias
try:
    state.memory.store(
        VECTOR_TABLE_BASE_ADDR.start, flash_dump[: VECTOR_TABLE_BASE_ADDR.size]
    )
    print(f"Mapped Flash alias at {VECTOR_TABLE_BASE_ADDR.start:#x} (Vector Table)")
except Exception as e:
    print(f"Warning: Failed to map Vector Table at 0x0: {e}")
state.memory.store(I2C1.start, i2c1_dump)

"""
驗證從 VERIFICATION_BEGIN 開始
"""


def enable_verification_hook(state):
    state.globals["verification_enabled"] = True


proj.hook(
    VERIFICATION_BEGIN_ADDR, enable_verification_hook, length=0
)  # length=0 表示執行完 hook 後繼續執行原本的指令

"""
攔截 read/write I2C1 位址的指令
"""


def create_hybrid_val(name, mask, stored_val, width=32):
    """
    生成有 concrete value 及 symbolic value 的數值

    Mask 為 1 的部分: 生成 symbolic value
    Mask 為 0 的部分: 生成 concrete value
    """
    parts = []
    current_bit = width - 1

    while current_bit >= 0:
        is_sym = (mask >> current_bit) & 1

        # 尋找連續相同狀態的長度
        length = 0
        while (current_bit - length) >= 0:
            if ((mask >> (current_bit - length)) & 1) != is_sym:
                break
            length += 1

        high = current_bit
        low = current_bit - length + 1

        if is_sym:
            parts.append(claripy.BVS(f"{name}_{high}_{low}", length))
        else:
            parts.append(stored_val[high:low])

        current_bit -= length

    return claripy.Concat(*parts)


def on_read_I2C1(state):
    addr = state.solver.eval(state.inspect.mem_read_address)
    idx = int((addr - I2C1.start) / 4)

    try:
        value = state.memory.load(
            addr,
            4,
            endness=state.arch.memory_endness,
            disable_actions=True,
            inspect=False,
        )
    except Exception:  # 記憶體還沒被初始化，令預設值為 0
        value = claripy.BVV(0, 32)
    value = create_hybrid_val(
        I2C_NAME[idx],
        I2C_RESERVED_MASK[I2C_NAME[idx]] & I2C_HARDWARE_DEPENDENT_MASK[I2C_NAME[idx]],
        value,
    )
    state.inspect.mem_read_expr = value

    if addr == I2C1.SR1:
        state.globals["SR1"] = value
    #     # FIXME: 要考慮舊 flag 是因為怕之後又有新的 SR1 讀取 (與我要驗證的功能無關)，造成 flag 被覆蓋
    #     old_flag = state.globals.get('verification_flag_0', claripy.BVV(0, 1))
    #     ADDR = value[1:1]
    #     state.globals['verification_flag_0'] = old_flag | ADDR


def on_write_I2C1(state):
    addr = state.solver.eval(state.inspect.mem_write_address)

    if state.globals.get("verification_enabled", False):
        if addr == I2C1.DR:
            sr1 = state.globals.get("SR1")

            # [Spec] DR 寫入前，若 TxE 為 0，則違反
            if sr1 is None or state.solver.satisfiable(
                extra_constraints=[(sr1 & I2C.SR1_TXE_MASK) == 0]
            ):
                found_violations.append(True)
                state.add_constraints(claripy.BoolV(False))  # 殺死這條路徑


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

    new_value = origin_value + 10  # 每讀取一次 SysTick，SysTick 加 10
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

    if n_active > 500:
        print("State explosion detected! Aborting exploration.")
        simgr.move(from_stash="active", to_stash="exploded")

    return simgr


simgr.explore(
    find=VERIFICATION_END_ADDR, num_find=float("inf"), step_func=monitor_exploration
)

if len(found_violations) > 0:
    print(f"Verification FAILURE! Found {len(found_violations)} violation path(s).")
elif len(simgr.found) > 0:
    print(f"Verification SUCCESS! Found {len(simgr.found)} paths that reached the end.")
else:
    print("No state reached the end")
