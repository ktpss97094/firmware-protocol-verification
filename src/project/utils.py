import re
import warnings
import logging
import archinfo
from project import config


logger = logging.getLogger(__name__)


def init_logging():
    logging.config.dictConfig(config.LOGGING_CONFIG)


def get_default_symbolic_mask(name_dict, offset, symbolic_mask):
    return symbolic_mask.get(name_dict[offset // 4], 0)


def normalize_code_addr(proj, addr, target=None, is_executing_pc=False):
    """
    處理 Thumb Mode 等情況

    :param is_executing_pc: 是否為當前正在執行的 pc 值
    """

    # Arm Cortex-M 僅支援 Thumb 指令集
    if isinstance(proj.arch, archinfo.ArchARMCortexM):
        return addr | 1

    if isinstance(proj.arch, archinfo.ArchARM):
        if addr % 2 == 1:
            return addr

        if is_executing_pc and target:
            try:
                cpsr = target.read_register("cpsr")
                if cpsr & 0x20:
                    return addr | 1
            except Exception as e:
                logger.warning(f"Failed to read CPSR for PC normalization: {e}")
                return addr

    return addr


def get_symbol_addr(proj, symbol_name, is_variable):
    sym = proj.loader.main_object.get_symbol(symbol_name)
    if not sym:
        raise ValueError(f"Symbol '{symbol_name}' not found in ELF")

    addr = sym.rebased_addr

    if is_variable:
        return addr

    return normalize_code_addr(proj, addr)


def read_MMIO_renode(avatar_target, base_addr, size):
    """
    避免 Renode peripheral 的 ReadByte() 實作可能有問題，導致 avatar2 read_memory() 失敗
    """

    data = bytearray(size)
    for offset in range(0, size, 4):
        target_addr = base_addr + offset

        try:
            ok, output = avatar_target.protocols.execution.console_command(
                f"monitor sysbus ReadDoubleWord {target_addr:#x}"
            )
            if not ok or not output:
                continue

            matches = re.findall(r"0x[0-9a-fA-F]+", output)
            if not matches:
                continue

            val = int(matches[-1], 16)
            data[offset : offset + 4] = val.to_bytes(4, "little")
        except Exception as e:
            warnings.warn(f"Failed to read reg at {target_addr:#x}: {e}")

    return bytes(data)


def step_explore(simgr, proj, monitor_exploration=None):
    while simgr.active:

        def get_local_var(state, frame_reg_name="r7", offset=-20, size=4):
            fp = getattr(state.regs, frame_reg_name)
            addr = fp + offset
            val = state.memory.load(addr, size, endness=state.arch.memory_endness)
            return val

        pass
        simgr.step()
        for state in simgr.active:
            pc_addr = state.solver.eval(state.regs.pc) & ~1
            addr_map = proj.loader.main_object.addr_to_line

            if pc_addr in addr_map:
                source_info = addr_map[pc_addr]
                print(f"Address: {hex(pc_addr)} maps to: {source_info}")
            else:
                print(f"No debug info found for address {hex(pc_addr)}")
        pass

        def check_find_condition(state):
            return state.addr in [0xFFFFFFE1, 0xFFFFFFF9, 0xFFFFFFFD]

        simgr.move(
            from_stash="active", to_stash="found", filter_func=check_find_condition
        )

        if monitor_exploration:
            monitor_exploration(simgr)
