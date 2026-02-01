import hashlib
import importlib
import importlib.util
import logging
import re
import warnings
from pathlib import Path
from types import ModuleType
from typing import Any, Type

import archinfo
import claripy

from project import config

logger = logging.getLogger(__name__)


def init_logging():
    logging.config.dictConfig(config.LOGGING_CONFIG)


def load_specs_class(spec_arg: str | None) -> Type[Any]:
    def load_module_from_file(path: Path) -> ModuleType:
        unique_name = (
            "user_specs_" + hashlib.sha256(str(path).encode()).hexdigest()[:16]
        )
        spec = importlib.util.spec_from_file_location(unique_name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Unable to create module spec from file: {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    if spec_arg.endswith(".py"):
        path = Path(spec_arg).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Spec file doesn't exist: {path}")
        mod = load_module_from_file(path)
    else:
        mod = importlib.import_module(spec_arg)

    if not hasattr(mod, "Specs"):
        raise AttributeError(f"Spec file doesn't provide 'Specs' class: {spec_arg}")

    return getattr(mod, "Specs")


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
