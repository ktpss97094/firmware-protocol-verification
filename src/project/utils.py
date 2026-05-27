import logging
import pickle
from pathlib import Path

import angr
import archinfo
import claripy
from angr.sim_state import SimState
from angr.sim_type import SimTypeFunction

logger = logging.getLogger(__name__)


def load(state: SimState, addr, size=None):
    return state.memory.load(
        addr,
        size if size is not None else state.arch.bytes,
        endness=state.arch.memory_endness,
        disable_actions=True,
        inspect=False,
    )


def store(state: angr.SimState, addr, value, size=None):
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


def set_func_args_symbolic(state, prototype: SimTypeFunction, constraints: dict):
    """
    處理純數值的參數。無法設定 struct 內的 member 或是 pointer 指向的值

    Args:
        constraints: dict[function 參數 index] = (constraint low, constraint high)。如果不指定 value 則無 constraint
    """

    arg_locs = state.project.factory.cc().arg_locs(prototype)

    for index, constraint_range in constraints.items():
        if index < 0 or index >= len(arg_locs):
            raise ValueError(
                f"Arg index {index} out of range for arg_num={len(arg_locs)}"
            )

        new_val = generate_symbolic(
            state,
            f"FuncArgs[{index}]",
            size=prototype.args[index].with_arch(state.arch).size,
        )

        if constraint_range is not None:
            state.add_constraints(
                new_val >= constraint_range[0], new_val <= constraint_range[1]
            )

        arg_locs[index].set_value(state, new_val)


def convert_thumb_mode(proj, addr, target=None, is_executing_pc=False):
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

    return addr


def loop_entry_block_addrs_to_loops(addrs: list[int], proj, cfg):
    loop_finder = proj.analyses.LoopFinder(kb=cfg.kb, normalize=True)

    return [loop for loop in loop_finder.loops if loop.entry.addr in addrs]


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


def process_cache_file(
    source_file: str | Path, cache_file: str | Path, process_func, **kwargs
):
    source_path = Path(source_file)
    cache_path = Path(cache_file)

    if not source_path.exists():
        raise FileNotFoundError(f"Didn't find source file: {source_path}")

    if (
        not cache_path.exists()
        or source_path.stat().st_mtime > cache_path.stat().st_mtime
    ):
        result_dict = process_func(**kwargs)

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("wb") as f:
            pickle.dump(result_dict, f)

    else:
        with cache_path.open("rb") as f:
            result_dict = pickle.load(f)

    return result_dict


def stop_and_debug(state):
    state.globals["DEBUG"] = True
