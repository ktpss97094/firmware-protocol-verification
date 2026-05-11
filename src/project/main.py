import hashlib
import importlib
import importlib.util
import logging
import re
import warnings
from pathlib import Path
from types import ModuleType
from typing import Any, Type

import angr
import avatar2
import typer
from typing_extensions import Annotated

import project.utils as utils
from project import config
from project.types import (
    BaseCustomGlobals,
    BaseSpecs,
    CustomEngine,
    DFSPickFirstSuccessor,
    MMIOMemoryRegion,
    VariableMemoryRegion,
    Violation,
)

logger = logging.getLogger(__name__)
app = typer.Typer(name="verify")
found_cnt, violated_cnt = 0, 0


def init_logging():
    logging.config.dictConfig(config.LOGGING_CONFIG)

    # 關閉 pcode error
    logging.getLogger("angr.engines.pcode.lifter").setLevel(logging.CRITICAL)


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


def explore_step_func(simgr):
    global found_cnt, violated_cnt

    # 取出 violated states
    for err in simgr.errored.copy():
        if isinstance(err.error, Violation):
            print(
                err.error.args[0] + f" violation (ins_addr: {hex(err.error.ins_addr)})"
            )
            simgr.violated.append(err.state)
            simgr.errored.remove(err)

    for state in simgr.active:
        state.history.trim()
    found_cnt += len(simgr.found)
    # 如果需要 found state 做驗證，可以在這裡只取出需要的部分
    violated_cnt += len(simgr.violated)
    simgr.stashes["found"].clear()
    simgr.stashes["violated"].clear()
    simgr.stashes["loopseer"].clear()

    print(
        f"Step: Active={len(simgr.active)}, Found={found_cnt}, Violated={violated_cnt}"
    )
    # print(f"pc: {[hex(state.solver.eval(state.regs.pc)) for state in simgr.active]}")

    return simgr


def LoopSeer_bound_reached_handler(seer, state):
    logger.info(f"Loop bound reached at {hex(state.addr)}. Truncating state.")

    seer.cut_succs.append(state)


@app.command()
def main(
    spec: str,
    search: str = "dfs",
    renode: bool = False,
    debug: Annotated[bool, typer.Option(hidden=True)] = False,
):
    Specs = load_specs_class(spec)

    init_logging()

    avatar = avatar2.Avatar(
        arch=Specs.AVATAR_ARCH, output_directory=config.AVATAR_LOG_PATH
    )
    proj = angr.Project(
        Specs.FIRMWARE_PATH,
        auto_load_libs=False,
        arch=Specs.ANGR_ARCH,
        engine=CustomEngine,
    )

    specs: BaseSpecs = Specs(proj)

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
            gdb_additional_args=[Specs.FIRMWARE_PATH],
        )
    else:
        avatar_target = avatar.add_target(
            avatar2.OpenOCDTarget,
            openocd_script=Specs.OPENOCD_INTERFACE_SCRIPT_PATH,
            additional_args=["-f", Specs.OPENOCD_TARGET_SCRIPT_PATH],
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
                dumps[memory_region_name] = read_MMIO_renode(
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

    # with open("specs/STM32/I2C/Blocking_Mode/Hardware/state.pkl", "wb") as f:
    #     pickle.dump(state, f)
    #     exit(0)

    # 計算 API 參數
    if specs.API_PROTOTYPE is not None:
        for index in range(len(specs.API_PROTOTYPE.args)):
            specs.API_ARGS.append(utils.get_func_arg(state, specs.API_PROTOTYPE, index))

    specs.init_inspect(state)
    specs.init_input(state)
    if not hasattr(state, "custom_globals"):
        BaseCustomGlobals.register_default("custom_globals")

    avatar.shutdown()

    simgr = proj.factory.simgr(state)
    simgr.stashes["violated"] = []
    simgr.stashes["loopseer"] = []
    cfg = specs.CPU.setup(state, specs, simgr)

    if debug:
        simgr.use_technique(DFSPickFirstSuccessor())
    elif search == "dfs":
        simgr.use_technique(angr.exploration_techniques.DFS())
    simgr.use_technique(
        angr.exploration_techniques.LoopSeer(
            cfg=cfg,
            functions=Specs.BOUND_LOOP_FUNCTIONS,
            bound=Specs.LOOP_BOUND,
            bound_reached=LoopSeer_bound_reached_handler,
            discard_stash="loopseer",
        )
    )

    simgr.explore(num_find=float("inf"), step_func=explore_step_func, num_inst=1)
    # step_explore(simgr, proj, monitor_exploration=explore_step_func)

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
    elif found_cnt > 0 or violated_cnt > 0:
        specs.final(simgr)

        if violated_cnt > 0:
            print(f"Verification FAILURE! Found {violated_cnt} violation state(s)")
        else:
            print(
                f"Verification SUCCESS! Found {found_cnt} state(s) that reached the end"
            )
    else:
        raise AssertionError("No valid paths found or no violations detected")


if __name__ == "__main__":
    app()
