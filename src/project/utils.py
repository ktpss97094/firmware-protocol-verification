import re
import warnings
import logging
import archinfo
import claripy
from angr.sim_type import SimTypeInt, SimTypeFunction
from project import config


logger = logging.getLogger(__name__)


def init_logging():
    logging.config.dictConfig(config.LOGGING_CONFIG)


def get_default_symbolic_mask(name_dict, offset, symbolic_mask):
    return symbolic_mask.get(name_dict[offset // 4], 0)


def load(state, addr, size=None):
    return state.memory.load(
        addr,
        size if size is not None else state.arch.bytes,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )


def store(state, addr, value, size=None):
    state.memory.store(
        addr,
        value,
        size=size if size is not None else state.arch.bytes,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )


def set_bits(state, addr, mask):
    prev_val = load(state, addr)

    store(state, addr, prev_val | mask)


def clear_bits(state, addr, mask):
    prev_val = load(state, addr)

    store(state, addr, prev_val & ~mask)


def generate_symbolic(state, mask, symbolic_name_prefix, size=None):
    output = (
        claripy.BVS(
            f"{symbolic_name_prefix}_sym_{state.globals.get('sym_cnt', 0)}",
            size if size is not None else state.arch.bits,
        )
        & mask
    )
    state.globals["sym_cnt"] = state.globals.get("sym_cnt", 0) + 1

    return output


def set_symbolic(state, addr, mask, symbolic_name_prefix):
    prev_val = load(state, addr)

    new_val = (prev_val & ~mask) | (
        generate_symbolic(state, mask, symbolic_name_prefix)
    )

    store(state, addr, new_val)

    return new_val


def set_func_args_symbolic(proj, state, arg_num, constraints: dict):
    """
    :param arg_num: function 參數總數
    :param constraints: dict[function 參數 index] = (constraint low, constraint high)
    """

    cc = proj.factory.cc()
    prototype = SimTypeFunction([SimTypeInt()] * arg_num, SimTypeInt())
    arg_locs = cc.arg_locs(prototype)

    for index, (lo, hi) in constraints.items():
        if index < 0 or index >= arg_num:
            raise ValueError(f"Arg index {index} out of range for arg_num={arg_num}")

        new_val = generate_symbolic(state, 0xFFFFFFFF, f"FuncArgs[{index}]")
        state.add_constraints(new_val >= lo, new_val <= hi)

        arg_locs[index].set_value(state, new_val)


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


def get_constraint_info(state, constraint):
    def get_bit_extract_info(constraint):
        if constraint.op == "Extract":
            high_bit = constraint.args[0]
            low_bit = constraint.args[1]
            source_ast = constraint.args[2]
            return (high_bit, low_bit, source_ast)

        for arg in constraint.args:
            if hasattr(arg, "op"):
                result = get_bit_extract_info(arg)
                if result:
                    return result

        return None

    def find_variable_origin(state, target_ast):
        for action in reversed(list(state.history.actions)):
            if action.type == "mem" and action.action == "read":
                if target_ast.variables & action.data.variables:
                    addr = action.addr.ast
                    if not addr.symbolic:
                        return state.solver.eval(addr)
                    return addr

        return None

    result = get_bit_extract_info(constraint)
    if result:
        high, low, source = result
        return find_variable_origin(state, source), (high, low)


def step_explore(simgr, proj, monitor_exploration=None):
    while simgr.active:

        def get_local_var(state, frame_reg_name="r7", offset=-20, size=4):
            fp = getattr(state.regs, frame_reg_name)
            addr = fp + offset
            val = state.memory.load(addr, size, endness=state.arch.memory_endness)
            return val

        simgr.step()
        for state in simgr.active:
            pc_addr = state.solver.eval(state.regs.pc) & ~1
            addr_map = proj.loader.main_object.addr_to_line

            if pc_addr in addr_map:
                source_info = addr_map[pc_addr]
                print(f"Address: {hex(pc_addr)} maps to: {source_info}")
            else:
                print(f"No debug info found for address {hex(pc_addr)}")

        if monitor_exploration:
            monitor_exploration(simgr)


def stop_and_debug(state):
    state.globals["DEBUG"] = True
