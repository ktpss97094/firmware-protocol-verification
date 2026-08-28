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


def init_logging(log_name: str | None = None) -> None:
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
    # loop_data is only merged when state_merge_key() proves both copies identical.
    logging.getLogger("angr.state_plugins.loop_data").setLevel(logging.ERROR)
    # SimMergeError
    logging.getLogger("angr.sim_manager").setLevel(logging.ERROR)


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
        str | None,
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
    specs: BaseSpec = spec_class(proj)
    proj.verification = VerificationSession(specs)
    exploration_monitor = ExplorationMonitor(
        violated_count_func=lambda: proj.verification.violated_count
    )

    """
    avatar2 部分
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
            avatar2.OpenOCDTarget,
            openocd_script=spec_class.OPENOCD_INTERFACE_SCRIPT_PATH,
            additional_args=["-f", spec_class.OPENOCD_TARGET_SCRIPT_PATH],
        )

    # 過濾出需要處理的 memory regions
    map_memory_regions = {}
    for memory_region_name, memory_region in specs.MEMORY_REGIONS.items():
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
    avatar_target.set_breakpoint(specs.BEGIN_ADDR)
    avatar_target.cont()
    avatar_target.wait()
    logger.info("Hit the breakpoint. Extracting state")

    # e.g., Arm Cortex-M4: https://developer.arm.com/documentation/100166/0001/Programmers-Model/Processor-core-register-summary?lang=en
    regs = {}
    seen_indices = set()
    for name, idx in avatar_target._arch.registers.items():
        if idx in seen_indices:
            continue

        try:
            val = avatar_target.read_register(name)
        except Exception as e:
            logger.warning(f"avatar2 read register {name} exception: {e}")
            continue

        # 讀取 special_registers 時，read_register() 可能會回傳 list 或一般的 int
        try:
            regs[name] = val[0]
        except (TypeError, IndexError):
            regs[name] = val

        seen_indices.add(idx)
    regs[avatar_target._arch.pc_name] = utils.convert_thumb_mode(
        proj,
        regs[avatar_target._arch.pc_name],
        target=avatar_target,
        is_executing_pc=True,
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
    angr 部分
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

    for reg_name, value in regs.items():
        if reg_name in state.arch.registers:
            setattr(state.regs, reg_name, value)
        elif reg_name == "xpsr":  # xpsr 在 angr 不是單一個 register，需要手動處理
            if "flags" in state.arch.registers:
                state.regs.flags = value & 0xF8000000
                if "cc_op" in state.arch.registers:
                    state.regs.cc_op = 0
            if "iepsr" in state.arch.registers:
                state.regs.iepsr = (value & 0x1FF) | (value & (1 << 24))
            if "itstate" in state.arch.registers:
                it_high = (value >> 10) & 0x3F
                it_low = (value >> 25) & 0x3
                state.regs.itstate = (it_high << 2) | it_low

    for memory_region_name in dumps:
        try:
            state.memory.store(
                map_memory_regions[memory_region_name].start, dumps[memory_region_name]
            )
        except Exception as e:
            logger.warning(
                f"Failed to transfer {memory_region_name} at {map_memory_regions[memory_region_name].start:#x} to angr: {e}"
            )

    # 計算 API 參數
    if specs.API_PROTOTYPE is not None:
        for index in range(len(specs.API_PROTOTYPE.args)):
            specs.API_ARGS.append(utils.get_func_arg(state, specs.API_PROTOTYPE, index))

    specs.init_inspect(state)
    specs.init_input(state)

    # 關閉 renode
    if renode:
        try:
            avatar_target.protocols.execution.console_command("monitor quit")
        except Exception as e:
            logger.warning(f"Failed to quit renode: {e}")
    avatar.shutdown()

    simgr = proj.factory.simgr(state)
    simgr.stashes["violated"] = []
    simgr.stashes["loopseer"] = []
    specs.END_ADDRS.append(
        state.solver.eval(specs.CPU.get_current_return_address(state))
    )
    cfg = specs.CPU.setup(state, specs, simgr)
    loop_finder = proj.analyses.LoopFinder(kb=cfg.kb, normalize=True)

    merge_points = set()
    fork_to_join = {}
    if automatic_merge:
        merge_roots = {specs.BEGIN_ADDR}
        merge_roots.update(
            isr.address
            for isr in specs.CPU.get_isr_memory_report(proj, state, specs).isrs
        )
        merge_points, fork_to_join = discover_acyclic_merge_plan(
            cfg, merge_roots, loop_finder.loops
        )
        logger.info(
            "Discovered %d acyclic CFG merge points and %d fork instructions "
            "from %d execution roots: %s",
            len(merge_points),
            len(fork_to_join),
            len(merge_roots),
            ", ".join(hex(addr) for addr in sorted(merge_points)),
        )
    if deterministic_dfs:
        simgr.use_technique(DFSPickFirstSuccessor())
    elif automatic_merge:
        if not merge_points:
            logger.warning("Automatic merge is enabled, but no merge points can found.")
        else:
            simgr.use_technique(
                DFSAutomaticMerge(
                    merge_points=merge_points,
                    fork_to_join=fork_to_join or {},
                    max_wait_steps=1024,
                    max_waiting_states=32,
                    max_merge_depth=32,
                )
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
        specs.final(simgr)

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
