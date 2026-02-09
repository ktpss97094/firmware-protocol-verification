import logging

import archinfo
import claripy

logger = logging.getLogger(__name__)


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


def generate_symbolic(state, name, mask=None, size=None):
    size = size if size is not None else state.arch.bits
    mask = mask if mask is not None else claripy.BVV(-1, size)

    return claripy.BVS(name, size) & mask


def replace_bit(bv, index, value):
    size = bv.length

    if isinstance(value, int):
        value = claripy.BVV(value, 1)

    if index == size - 1:
        return claripy.Concat(value, bv[size - 2 : 0])
    elif index == 0:
        return claripy.Concat(bv[size - 1 : 1], value)
    else:
        return claripy.Concat(bv[size - 1 : index + 1], value, bv[index - 1 : 0])


def set_bits(bv, indices: int | list[int]):
    if isinstance(indices, list):
        for index in indices:
            bv = replace_bit(bv, index, 1)
        return bv
    return replace_bit(bv, indices, 1)


def clear_bits(bv, indices: int | list[int]):
    if isinstance(indices, list):
        for index in indices:
            bv = replace_bit(bv, index, 0)
        return bv
    return replace_bit(bv, indices, 0)


def symbolic_bit(state, bv, index, name):
    return replace_bit(bv, index, generate_symbolic(state, name, size=1))


def get_func_arg(state, prototype, index):
    """
    一定要在 function 進入當下呼叫，否則值可能會被覆寫

    TODO: 改寫成繼承 angr.SimProcedure 的方法，可完全避免覆寫問題
    """

    return state.project.factory.cc().arg_locs(prototype)[index].get_value(state)


def get_func_ret(state, prototype):
    """
    一定要在 function return 之後的下一行呼叫，否則值可能會被覆寫

    TODO: 改寫成繼承 angr.SimProcedure 的方法，可完全避免覆寫問題
    """

    return state.project.factory.cc().return_val(prototype.returnty).get_value(state)


def set_func_args_symbolic(state, prototype, constraints: dict):
    """
    Args:
        constraints: dict[function 參數 index] = (constraint low, constraint high)
    """

    arg_locs = state.project.factory.cc().arg_locs(prototype)

    for index, (lo, hi) in constraints.items():
        if index < 0 or index >= len(arg_locs):
            raise ValueError(
                f"Arg index {index} out of range for arg_num={len(arg_locs)}"
            )

        new_val = generate_symbolic(state, f"FuncArgs[{index}]")
        state.add_constraints(new_val >= lo, new_val <= hi)

        arg_locs[index].set_value(state, new_val)


def normalize_code_addr(proj, addr, target=None, is_executing_pc=False):
    """
    處理 Thumb Mode 等情況

    Args:
        is_executing_pc: 是否為當前正在執行的 pc 值
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


def stop_and_debug(state):
    state.globals["DEBUG"] = True
