import hashlib
import importlib
import importlib.util
import logging
import logging.config
import re
from datetime import datetime
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Annotated, Any, Type

import angr
import avatar2
import typer
from angr.exploration_techniques import DFS

import project.utils as utils
from project import config
from project.exploration import (
    CustomLoopSeer,
    DFSAutomaticMerge,
    DFSPickFirstSuccessor,
    ExplorationMonitor,
    ExplorationTermination,
    discover_acyclic_merge_plan,
)
from project.types import BaseSpec, CustomEngine, MMIOMemoryRegion, VariableMemoryRegion
from project.verification import VerificationSession

logger = logging.getLogger(__name__)
app = typer.Typer(name="verify")


def init_logging(log_name: Path | None = None) -> None:
    if log_name == "":
        raise typer.BadParameter("Log filename cannot be empty string")
    elif log_name is None:
        log_name = f"{datetime.now().astimezone().strftime('%Y%m%d-%H%M%S%z')}.log"
    config.LOGGING_CONFIG["handlers"]["file"]["filename"] = str(
        config.LOG_DIR / log_name
    )

    logging.config.dictConfig(config.LOGGING_CONFIG)

    # pcode error
    logging.getLogger("angr.engines.pcode.lifter").setLevel(logging.CRITICAL)
    # loop_data is only merged when state_merge_key() proves both copies identical
    logging.getLogger("angr.state_plugins.loop_data").setLevel(logging.ERROR)
    # SimMergeError
    logging.getLogger("angr.sim_manager").setLevel(logging.ERROR)
    #
    # logging.getLogger(
    #     "angr.analyses.calling_convention.fact_collector.SimEngineFactCollectorVEX"
    # ).setLevel(logging.CRITICAL)


def load_spec_class(spec_arg: Path) -> Type[Any]:
    def load_module_from_file(path: Path) -> ModuleType:
        unique_name = "user_spec_" + hashlib.sha256(str(path).encode()).hexdigest()[:16]
        spec = importlib.util.spec_from_file_location(unique_name, str(path))
        if spec is None or spec.loader is None:
            raise ImportError(f"Unable to create module spec from file: {path}")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    if spec_arg.suffix.lower() == ".py":
        path = spec_arg.expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Spec file doesn't exist: {path}")
        mod = load_module_from_file(path)
    else:
        mod = importlib.import_module(spec_arg)

    if not hasattr(mod, "Spec"):
        raise AttributeError(f"Spec file doesn't provide 'Spec' class: {spec_arg}")

    return getattr(mod, "Spec")


def read_renode_mmio(avatar_target: avatar2.Target, base_addr: int, size: int) -> bytes:
    """
    Avoid potential issues with Renode peripheral's ReadByte() implementation that may cause avatar2 read_memory() to fail.
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
            logger.warning(f"Failed to read reg at {target_addr:#x}: {e}")

    return bytes(data)


def LoopSeer_bound_reached_handler(seer, state, bound_loops):
    """Bound k means restrict the number of back-edge traversals for the loop to at most k."""

    loop = state.loop_data.current_loop[-1][0]
    header_addr = loop.entry.addr

    bound = bound_loops.get(header_addr, None)
    if bound is None:
        return

    count_stack = state.loop_data.back_edge_trip_counts.get(header_addr)
    counts = count_stack[-1] if count_stack else 0

    if counts > bound:
        logger.info(
            "Loop bound reached at %s after %d back-edge traversals. Truncating state.",
            hex(state.addr),
            counts,
        )
        seer.cut_succs.append(state)


def gdb_callback(ctx: typer.Context, value: bool | None) -> bool | None:
    if not value:
        return value

    if ctx.params.get("renode"):
        raise typer.BadParameter("--gdb cannot be used with --renode.")

    return value


@app.command()
def main(
    spec: Annotated[Path, typer.Argument(help="Path to the specification file.")],
    renode: Annotated[
        bool, typer.Option(help="Use Renode to extract the initial state.")
    ] = False,
    gdb: Annotated[
        bool,
        typer.Option(
            callback=gdb_callback,
            help="Connect to a GDB server. This can be used to extract the initial state from a remote OpenOCD process.",
        ),
    ] = False,
    deterministic_dfs: Annotated[
        bool, typer.Option(help="Always pick the first successor on a DFS.")
    ] = False,
    automatic_merge: Annotated[
        bool, typer.Option(help="Use automatic state-merging mechanism.")
    ] = True,
    log: Annotated[
        Path | None,
        typer.Option(
            help="The log name under the log directory. Uses a timestamp if omitted."
        ),
    ] = None,
):
    spec_class = load_spec_class(spec)
    init_logging(log)

    avatar = avatar2.Avatar(
        arch=spec_class.AVATAR_ARCH, output_directory=config.AVATAR_LOG_PATH
    )
    proj = angr.Project(
        spec_class.FIRMWARE_PATH,
        auto_load_libs=False,
        arch=spec_class.ANGR_ARCH,
        engine=CustomEngine,
    )
    spec_obj: BaseSpec = spec_class(proj)
    proj.verification = VerificationSession(spec_obj)
    exploration_monitor = ExplorationMonitor(
        violated_count_func=lambda: proj.verification.violated_count
    )

    """
    avatar2
    """
    avatar_target: avatar2.Target | None = None
    if renode:
        avatar_target = avatar.add_target(
            avatar2.GDBTarget,
            gdb_port=config.RENODE_GDB_PORT,
            gdb_serial_device="127.0.0.1",
            serial=False,
            gdb_additional_args=[spec_class.FIRMWARE_PATH],
        )
    elif gdb:
        avatar_target = avatar.add_target(
            avatar2.GDBTarget, gdb_port=3333, gdb_serial_device="127.0.0.1"
        )
    else:
        avatar_target = avatar.add_target(
            avatar2.OpenOCDTarget, openocd_script=spec_class.OPENOCD_SCRIPT_PATH
        )

    # Filter out the memory regions that need to be transfered
    map_memory_regions = {}
    for memory_region_name, memory_region in spec_obj.MEMORY_REGIONS.items():
        if isinstance(memory_region, VariableMemoryRegion):
            logger.info(
                f"Skip transfer memory region {memory_region_name}: belongs to class VariableMemoryRegion"
            )
            continue

        map_memory_regions[memory_region_name] = memory_region

    for memory_region in map_memory_regions.values():
        avatar.add_memory_range(
            memory_region.start,
            memory_region.size,
            name=memory_region.name,
            target=avatar_target,
        )

    avatar.init_targets()

    if gdb:
        try:
            avatar_target.protocols.execution.console_command("monitor reset halt")
        except Exception as e:
            logger.warning(f"Failed to reset/halt GDB target: {e}")
    avatar_target.set_breakpoint(spec_obj.BEGIN_ADDR)
    avatar_target.cont()
    avatar_target.wait()
    logger.info("Hit the breakpoint. Extracting state")

    regs = {}
    for name in avatar_target.protocols.registers.get_register_names():
        if not name:
            continue

        try:
            val = avatar_target.read_register(name)
        except Exception as e:
            logger.warning(f"avatar2 read register {name} exception: {e}")
            continue

        # When reading special_registers, read_register() may return a list or an int
        try:
            regs[name] = val[0]
        except (TypeError, IndexError):
            regs[name] = val
    # Thumb mode
    regs[avatar_target._arch.pc_name] = proj.arch.x_addr(
        regs[avatar_target._arch.pc_name], thumb=spec_obj.CPU.thumb_mode(regs)
    )

    dumps = {}
    for memory_region_name, memory_region in map_memory_regions.items():
        if memory_region.transfer is False:
            logger.info(
                f"Skip transfer memory region {memory_region_name}: transfer argument is set to False"
            )
            continue

        try:
            if renode and isinstance(memory_region, MMIOMemoryRegion):
                dumps[memory_region_name] = read_renode_mmio(
                    avatar_target, memory_region.physical_addr, memory_region.size
                )
            else:
                dumps[memory_region_name] = avatar_target.read_memory(
                    memory_region.physical_addr,
                    size=proj.arch.bytes,
                    num_words=memory_region.size // proj.arch.bytes,
                    raw=True,
                )
        except Exception as e:
            logger.warning(f"avatar2 read memory {memory_region_name} exception: {e}")

    """
    angr
    """
    logger.info("Setting up angr state")
    state = proj.factory.blank_state(
        addr=regs[avatar_target._arch.pc_name],
        add_options={
            angr.options.SIMPLIFY_EXPRS,
            angr.options.SIMPLIFY_MEMORY_WRITES,
            angr.options.SIMPLIFY_REGISTER_WRITES,
            angr.options.COMPOSITE_SOLVER,
            angr.options.OPTIMIZE_IR,
            angr.options.UNICORN,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
        },
    )
    for opt in {
        angr.options.TRACK_MEMORY_ACTIONS,
        angr.options.TRACK_REGISTER_ACTIONS,
        angr.options.TRACK_TMP_ACTIONS,
        angr.options.TRACK_JMP_ACTIONS,
        angr.options.TRACK_CONSTRAINT_ACTIONS,
    }:
        if opt in state.options:
            state.options.remove(opt)

    # Mapping avatar2 registers to angr registers
    regs = spec_obj.CPU.translate_avatar_registers(regs)
    for reg_name, value in regs.items():
        setattr(state.regs, reg_name, value)

    for memory_region_name in dumps:
        try:
            state.memory.store(
                map_memory_regions[memory_region_name].start, dumps[memory_region_name]
            )
        except Exception as e:
            logger.warning(
                f"Failed to transfer {memory_region_name} at {map_memory_regions[memory_region_name].start:#x} to angr: {e}"
            )

    # Compute API arguments
    if spec_obj.API_PROTOTYPE is not None:
        for index in range(len(spec_obj.API_PROTOTYPE.args)):
            spec_obj.API_ARGS.append(
                utils.get_func_arg(state, spec_obj.API_PROTOTYPE, index)
            )

    spec_obj.init_inspect(state)
    spec_obj.init_input(state)

    if renode:
        try:
            avatar_target.protocols.execution.console_command("monitor quit")
        except Exception as e:
            logger.warning(f"Failed to quit renode: {e}")
    avatar.shutdown()

    simgr = proj.factory.simgr(state)
    simgr.stashes["violated"] = []
    simgr.stashes["loopseer"] = []
    spec_obj.END_ADDRS.append(
        state.solver.eval(spec_obj.CPU.get_current_return_address(state))
    )
    cfg = spec_obj.CPU.setup(state, spec_obj, simgr)
    loop_finder = proj.analyses.LoopFinder(kb=cfg.kb, normalize=True)

    if deterministic_dfs:
        simgr.use_technique(DFSPickFirstSuccessor())
    elif automatic_merge:
        merge_roots = {spec_obj.BEGIN_ADDR}
        merge_roots.update(
            isr.address
            for isr in spec_obj.CPU.get_isr_memory_report(proj, state, spec_obj).isrs
        )
        merge_points, fork_to_join = discover_acyclic_merge_plan(
            cfg, merge_roots, loop_finder.loops
        )
        logger.info(
            f"Discovered {len(merge_points)} acyclic CFG merge points and {len(fork_to_join)} fork instructions from {len(merge_roots)} execution roots: {', '.join(hex(addr) for addr in sorted(merge_points))}"
        )

        simgr.use_technique(
            DFSAutomaticMerge(merge_points=merge_points, fork_to_join=fork_to_join)
        )
    else:
        simgr.use_technique(DFS())
    simgr.use_technique(
        CustomLoopSeer(
            cfg=cfg,
            loops=[
                loop
                for loop in loop_finder.loops
                if loop.entry.addr in spec_class.BOUND_LOOPS
            ],
            bound=0,
            bound_reached=partial(
                LoopSeer_bound_reached_handler, bound_loops=spec_class.BOUND_LOOPS
            ),
            discard_stash="loopseer",
        )
    )

    try:
        simgr.explore(
            num_find=float("inf"), step_func=exploration_monitor.step, num_inst=1
        )
    except ExplorationTermination as e:
        logger.info(e)

    print(simgr)
    if len(simgr.errored) > 0:
        print(f"Errors Detected: {len(simgr.errored)} states died")

        for err in simgr.errored:
            print("-" * 30)
            print(f"  Error: {err.error}")
            print(f"  Crashed at (PC): {hex(err.state.addr)}")

            try:
                history = list(err.state.history.bbl_addrs)[-10:]
                print("  Traceback (Last 10 Basic Blocks):")
                for h_addr in history:
                    print(f"    -> {hex(h_addr)}")

                if history:
                    last_block_addr = history[-1]
                    block = proj.factory.block(last_block_addr)
                    print(f"  Last Block Assembly ({hex(last_block_addr)}):")
                    block.pp()

                print("  Registers at crash:")
                print(f"    SP: {hex(err.state.solver.eval(err.state.regs.sp))}")
                print(
                    f"    LR: {hex(err.state.solver.eval(err.state.regs.lr))} (Return Address)"
                )
                print(f"    R0: {hex(err.state.solver.eval(err.state.regs.r0))}")
            except Exception as e:
                print(f"  Could not extract debug info: {e}")

            print("-" * 30)
    elif exploration_monitor.found_count > 0 or proj.verification.violated_count > 0:
        spec_obj.final(simgr)

        if proj.verification.violated_count > 0:
            print(
                f"Verification FAILURE! Found {proj.verification.violated_count} violation(s): {', '.join(proj.verification.violation_names)}"
            )
        else:
            print(
                f"Verification SUCCESS! Found {exploration_monitor.found_count} terminal state(s)"
            )
    else:
        raise AssertionError("No terminal states found")


if __name__ == "__main__":
    app()
