"""
handle_clock_stretching
1. Trigger: write TXD
    Condition: 第二筆資料 (含) 之後時，EVENTS_TXDSENT 在這個 byte 傳輸時有被 set 或 EVENTS_ERROR 在這個 byte 傳輸時有被 set
2. Trigger: set TASKS_STOP
    Condition: Size > 0 時，EVENTS_TXDSENT 在這個 byte 傳輸時有被 set 或 EVENTS_ERROR 在這個 byte 傳輸時有被 set
(無法驗證 addressing phase，因為沒有對應的 address sent flag。而且 address 並不會存入 TXD register 發送，在寫入 TXD 之後硬體會自動等待 address 發送完才發送，這段期間不會有 clock stretching 問題)

perform_clock_stretching
1. Trigger: read RXD
    Condition: EVENTS_RXDREADY 在這個 byte 接收時有被 set

read_back_verification
(TWI 明確說不支援 multi-master)
"""

import copy
from collections import deque

import angr
import archinfo
import avatar2
import claripy
from angr.sim_type import SimStruct, SimTypeFunction, SimTypeInt, SimTypePointer

from project import config, utils
from project.peripherals.nrf52840.twi import TWI as NRF52840_TWI
from project.types import BaseCustomGlobals, BaseSpecs, MemoryRegion, MMIOMemoryRegion


class CustomGlobals(BaseCustomGlobals):
    def __init__(self, sizes=None, **kwargs):
        super().__init__(**kwargs)

        self.sizes = deque() if sizes is None else sizes

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        new_plugin = super().copy(memo)

        new_plugin.sizes = copy.deepcopy(self.sizes, memo)

        return new_plugin


class TWI(NRF52840_TWI):
    def post_read_spec(self, state, offset):
        match offset:
            case TWI.RXD.OFFSET:
                # --- Spec ---
                if state.solver.satisfiable(
                    extra_constraints=[
                        claripy.Not(
                            state.globals.get(f"{self.name}_EVENTS_RXDREADY_set", False)
                        )
                    ]
                ):
                    print(f"perform_clock_stretching violation (pc: {state.regs.pc})")
                    state.globals["violation"] = True
                    # TODO: 看可以直接丟入 violation stash 之類的，直接終止這個 state 繼續運行，節省之後做 side effect 的時間

    def post_write_spec(self, state, offset, value):
        match offset:
            case TWI.TASKS_STARTTX.OFFSET | TWI.TASKS_STARTRX.OFFSET:
                if state.solver.is_true(value == 1):
                    state.globals["size"] = state.custom_globals.sizes.popleft()

            case TWI.TXD.OFFSET:
                # --- Spec 1 ---
                if state.globals.get(
                    f"{self.name}_TXD_written", False
                ) and state.solver.satisfiable(
                    extra_constraints=[
                        claripy.Not(
                            state.globals.get(f"{self.name}_EVENTS_TXDSENT_set", False)
                        )
                    ]
                ):
                    print(
                        f"handle_clock_stretching (spec 1) violation (pc: {state.regs.pc})"
                    )
                    state.globals["violation"] = True

            case TWI.TASKS_STOP.OFFSET:
                # --- Spec 2 ---
                if state.solver.is_true(value == 1) and state.solver.satisfiable(
                    extra_constraints=[
                        state.globals.get("size") > 0,
                        claripy.Not(
                            claripy.Or(
                                state.globals.get(
                                    f"{self.name}_EVENTS_TXDSENT_set", False
                                ),
                                state.globals.get(
                                    f"{self.name}_EVENTS_ERROR_set", False
                                ),
                            )
                        ),
                    ]
                ):
                    print(
                        f"handle_clock_stretching (spec 2) violation (pc: {state.regs.pc})"
                    )
                    state.globals["violation"] = True


class Specs(BaseSpecs):
    # --- Paths ---
    FIRMWARE_PATH = str(
        config.PROJECT_ROOT
        / "firmwares/nrf52840/build/protocols/TWI/master/Non_DMA_Mode/nrfx/firmware.elf"
    )
    OPENOCD_INTERFACE_SCRIPT_PATH = str(
        config.PROJECT_ROOT / "openocd/scripts/interface/jlink.cfg"
    )
    OPENOCD_TARGET_SCRIPT_PATH = "/usr/share/openocd/scripts/target/nrf52.cfg"

    # --- Architecture ---
    AVATAR_ARCH = avatar2.archs.arm.ARM_CORTEX_M3
    ANGR_ARCH = archinfo.ArchARMCortexM(endness=archinfo.Endness.LE)

    # --- Renode ---
    USE_RENODE = False

    # --- Constants ---

    def _define_specs(self):
        self.MEMORY_REGIONS = {
            "FLASH": MemoryRegion(
                start=0x00000000, size=0x100000, name="FLASH", transfer=False
            ),
            "EXTFLASH": MemoryRegion(
                start=0x12000000, size=0x8000000, name="EXTFLASH", transfer=False
            ),  # Renode 沒有
            "RAM": MemoryRegion(start=0x20000000, size=0x40000, name="RAM"),
            "CODE_RAM": MemoryRegion(start=0x800000, size=0x40000, name="CODE_RAM"),
            "TWI0": TWI(start=0x40003000, size=0x1000, name="TWI0"),
            "NVIC": MMIOMemoryRegion(start=0xE000E000, size=0x1000, name="NVIC"),
        }

        self.BEGIN_ADDR = utils.get_symbol_addr(
            self.proj, "nrfx_twi_xfer", is_variable=False
        )
        self.END_ADDRS = [
            utils.get_symbol_addr(
                self.proj, "END_SYMBOLIC_EXECUTION", is_variable=False
            )
        ]

        nrfx_twi_xfer_desc_t = angr.types.parse_type("""
        struct nrfx_twi_xfer_desc_t {
            uint8_t type;
            uint8_t address;
            size_t primary_length;
            size_t secondary_length;
            uint8_t* p_primary_buf;
            uint8_t* p_secondary_buf;
        }
        """)
        angr.types.register_types(nrfx_twi_xfer_desc_t)
        self.API_PROTOTYPE = SimTypeFunction(
            args=[
                SimTypePointer(SimStruct({}, name="nrfx_twi_t")),
                SimTypePointer(nrfx_twi_xfer_desc_t),
                SimTypeInt(signed=False),
            ],
            returnty=SimTypeInt(),
        )

    def init_inspect(self, state):
        state.inspect.b(
            "mem_read",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["TWI0"].in_region_read,
            action=self.MEMORY_REGIONS["TWI0"].post_read,
        )

        state.inspect.b(
            "mem_write",
            when=angr.BP_AFTER,
            condition=self.MEMORY_REGIONS["TWI0"].in_region_write,
            action=self.MEMORY_REGIONS["TWI0"].post_write,
        )

        # state.inspect.b(
        #     "instruction",
        #     when=angr.BP_BEFORE,
        #     instruction=utils.get_symbol_addr(self.proj, "DEBUG", is_variable=False),
        #     action=utils.stop_and_debug,
        # )

    def init_input(self, state):
        CustomGlobals.register_default("custom_globals")

        size_range = (0, 3)  # 測 size = 0 ~ 3

        # address symbolic
        address = state.mem[self.API_ARGS[1]].struct.nrfx_twi_xfer_desc_t.address
        address.store(claripy.BVS("address", address.resolved.length))

        # data symbolic
        data_ptr = state.mem[self.API_ARGS[1]].struct.nrfx_twi_xfer_desc_t.p_primary_buf
        data = data_ptr.deref.array(size_range[1])
        for idx in range(*size_range):
            data[idx].store(claripy.BVS(f"data[{idx}]", data_ptr._type.pts_to.size))

        # size symbolic
        size = state.mem[self.API_ARGS[1]].struct.nrfx_twi_xfer_desc_t.primary_length
        size_symbolic = claripy.BVS("size", size.resolved.length)
        state.add_constraints(
            size_symbolic >= size_range[0], size_symbolic <= size_range[1]
        )
        size.store(size_symbolic)
        state.custom_globals.sizes.append(size_symbolic)

        # state.globals["sizes"] = [2]

        """
        secondary data and size (for TXRX and TXTX mode)
        """
        # secondary data symbolic
        data_ptr = state.mem[
            self.API_ARGS[1]
        ].struct.nrfx_twi_xfer_desc_t.p_secondary_buf
        data = data_ptr.deref.array(size_range[1])
        for idx in range(*size_range):
            data[idx].store(claripy.BVS(f"data[{idx}]", data_ptr._type.pts_to.size))

        # secondary size symbolic
        size = state.mem[self.API_ARGS[1]].struct.nrfx_twi_xfer_desc_t.secondary_length
        size_symbolic = claripy.BVS("size", size.resolved.length)
        state.add_constraints(
            size_symbolic >= size_range[0], size_symbolic <= size_range[1]
        )
        size.store(size_symbolic)
        state.custom_globals.sizes.append(size_symbolic)

        # flag symbolic
        flags = state.project.factory.cc().arg_locs(self.API_PROTOTYPE)[2]
        flags.set_value(
            state,
            claripy.BVS("flags", self.API_PROTOTYPE.args[2].with_arch(state.arch).size),
        )

        # source code 修改 HW_TIMEOUT 由 100000 為 5 避免 state explosion
