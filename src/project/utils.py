import logging

import angr
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


def same_ast(left, right):
    if left is right:
        return True
    if hasattr(left, "structurally_match") and hasattr(right, "structurally_match"):
        return left.structurally_match(right)
    return left == right


def merge_ast_values(state, value, other_values, merge_conditions):
    other_values = list(other_values)
    if not other_values:
        return value
    if merge_conditions is None:
        return state.solver.union([value] + other_values)
    return claripy.ite_cases(zip(merge_conditions[1:], other_values), value)


def get_func_arg(state, prototype, index):
    """Get the value of a function argument at a specific index.

    Note:
        Be sure to call this API at the moment the function is entered, otherwise the value may be overwritten.
    """
    # TODO: Rewriting it as a method that inherits from angr.SimProcedure might avoid the overwriting issue.
    return state.project.factory.cc().arg_locs(prototype)[index].get_value(state)


def get_func_ret(state, prototype):
    """Get the return value of a function.

    Note:
        Be sure to call this API at the moment the function is returned, otherwise the value may be overwritten.
    """
    # TODO: Rewriting it as a method that inherits from angr.SimProcedure might avoid the overwriting issue.
    return state.project.factory.cc().return_val(prototype.returnty).get_value(state)


def set_func_args_symbolic(state, prototype: SimTypeFunction, constraints: dict):
    """Set numeric arguments of a function to symbolic.

    Note:
        This function only handles numeric parameters. It cannot set values of struct members or pointer dereferences.

    Args:
        constraints: dict[<function argument index>] = [<constraint low>, <constraint high>]。If no value is specified, there is no constraint.
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


def get_symbol_addr(proj, symbol_name):
    sym = proj.loader.main_object.get_symbol(symbol_name)
    if not sym:
        raise ValueError(f"Symbol '{symbol_name}' not found in ELF")

    return sym.rebased_addr
