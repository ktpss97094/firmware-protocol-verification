import avatar2
import angr
import logging
from project import config
import project.utils as utils
from project.specs import Specs
from project.types import MMIOMemoryRegion, VariableMemoryRegion


logger = logging.getLogger(__name__)


def monitor_exploration(simgr):
    if "violated" not in simgr.stashes:
        simgr.stashes["violated"] = []
    simgr.move(
        from_stash="active",
        to_stash="violated",
        filter_func=lambda s: s.globals.get("violation", False),
    )

    print(f"Step: Active={len(simgr.active)}, Found={len(simgr.found)}")

    # if n_active > 500:
    #     print("State explosion detected! Aborting exploration.")
    #     simgr.move(from_stash="active", to_stash="exploded")
    #     exit(1)

    return simgr


def main():
    utils.init_logging()

    avatar = avatar2.Avatar(
        arch=config.AVATAR_ARCH, output_directory=config.AVATAR_LOG_PATH
    )
    proj = angr.Project(
        config.FIRMWARE_PATH,
        auto_load_libs=False,
        arch=config.ANGR_ARCH,
    )
    specs = Specs(proj)

    # 過濾出需要處理的 memory regions
    map_memory_regions = {}
    for memory_region_name, memory_region in specs.MEMORY_REGIONS.items():
        if isinstance(memory_region, VariableMemoryRegion):
            continue

        map_memory_regions[memory_region_name] = memory_region

    """
    avatar2 部分
    """
    avatar_target: avatar2.Target | None = None
    if config.USE_RENODE:
        avatar_target = avatar.add_target(
            avatar2.GDBTarget,
            gdb_port=config.RENODE_GDB_PORT,
            gdb_serial_device="127.0.0.1",
            serial=False,
            gdb_additional_args=[config.FIRMWARE_PATH],
        )
    else:
        avatar_target = avatar.add_target(
            avatar2.OpenOCDTarget,
            openocd_script=config.OPENOCD_INTERFACE_SCRIPT_PATH,
            additional_args=["-f", config.OPENOCD_TARGET_SCRIPT_PATH],
        )

    for memory_region in map_memory_regions.values():
        avatar.add_memory_range(
            memory_region.start,
            memory_region.size,
            name=memory_region.name,
            target=avatar_target,
        )

    avatar.init_targets()

    avatar_target.set_breakpoint(specs.BEGIN_ADDR)

    if config.USE_RENODE:
        avatar_target.protocols.execution.console_command("monitor start")
    while True:
        avatar_target.cont()
        avatar_target.wait()
        logger.info("Hit the breakpoint. Extracting state")

        # e.g., Arm Cortex-M4: https://developer.arm.com/documentation/100166/0001/Programmers-Model/Processor-core-register-summary?lang=en
        reg_names = list(
            {idx: name for name, idx in avatar_target._arch.registers.items()}.values()
        )
        # avatar2 將一般 register (registers) 與 special register (special_registers) 分開
        for special_register_name in avatar_target._arch.special_registers:
            reg_names.append(special_register_name)
        # Cortex-M 是用 xpsr 不是 cpsr
        if avatar_target._arch.cpu_model.startswith("cortex-m"):
            if "cpsr" in reg_names:
                reg_names.remove("cpsr")
                logger.info("Removing cpsr from register list for Arm Cortex-M")

        regs = {}
        for name in reg_names:
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
        regs[avatar_target._arch.pc_name] = utils.normalize_code_addr(
            proj,
            regs[avatar_target._arch.pc_name],
            target=avatar_target,
            is_executing_pc=True,
        )

        dumps = {}
        for memory_region_name, memory_region in map_memory_regions.items():
            try:
                if config.USE_RENODE and isinstance(memory_region, MMIOMemoryRegion):
                    dumps[memory_region_name] = utils.read_MMIO_renode(
                        avatar_target,
                        memory_region.map_addr,
                        memory_region.size,
                    )
                else:
                    dumps[memory_region_name] = avatar_target.read_memory(
                        memory_region.map_addr,
                        size=config.ANGR_ARCH.bytes,
                        num_words=memory_region.size // config.ANGR_ARCH.bytes,
                        raw=True,
                    )
            except Exception as e:
                logger.warning(
                    f"avatar2 read memory {memory_region_name} exception: {e}"
                )

        """
        angr 部分
        """
        logger.info("Setting up angr state")

        state = proj.factory.blank_state(
            addr=regs[avatar_target._arch.pc_name],
            add_options=angr.options.refs,
            #  | {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY, angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}  # ZERO_FILL_UNCONSTRAINED_MEMORY 及 ZERO_FILL_UNCONSTRAINED_REGISTERS 為指定當 Angr 讀取 Angr 未初始化的記憶體位置時，回傳 0 而不是 symbolic value
        )

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
                    map_memory_regions[memory_region_name].start,
                    dumps[memory_region_name],
                )
            except Exception as e:
                logger.warning(
                    f"Failed to map {memory_region_name} at {map_memory_regions[memory_region_name].start:#x} to angr: {e}"
                )

        specs.init_inspect(state)

        if specs.precondition(proj, state):
            logger.info("Precondition met")
            break
        else:
            logger.info("Precondition not met, resume avatar2 execution")

    avatar.shutdown()

    simgr = proj.factory.simgr(state)
    simgr.use_technique(
        angr.exploration_techniques.LoopSeer(
            cfg=proj.analyses.CFGFast(normalize=True), bound=10
        )
    )  # 設定 loop 執行上限次數
    simgr.explore(
        find=specs.END_ADDRS,
        num_find=float("inf"),
        step_func=monitor_exploration,
    )
    # utils.step_explore(simgr, proj, monitor_exploration=monitor_exploration)

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
    elif len(simgr.found) > 0:
        specs.postcondition(proj, simgr)

        if len(simgr.stashes["violated"]) > 0:
            print(
                f"Verification FAILURE! Found {len(simgr.stashes['violated'])} violation state(s)"
            )
        else:
            print(
                f"Verification SUCCESS! Found {len(simgr.found)} states that reached the end"
            )
    else:
        print("No state reached the end")


if __name__ == "__main__":
    main()
