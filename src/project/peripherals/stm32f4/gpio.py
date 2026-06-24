from dataclasses import dataclass

import archinfo
import claripy
from angr.state_plugins.plugin import SimStatePlugin

from project import utils
from project.types import (
    AccessEffects,
    AccessType,
    BaseRegister,
    BitsField,
    MemoryEffect,
    MMIOMemoryRegion,
    PluginEffect,
)


class Globals(SimStatePlugin):
    def __init__(self, bsrr_write_value=None):
        super().__init__()

        self.bsrr_write_value = bsrr_write_value

    def copy(self, memo):
        o = super().copy(memo)

        o.bsrr_write_value = self.bsrr_write_value

        return o

    def merge(self, others, merge_conditions, common_ancestor=None):
        del common_ancestor

        if self.bsrr_write_value is None and all(
            other.bsrr_write_value is None for other in others
        ):
            return False

        if merge_conditions is None:
            merged_bsrr_write_value = self.state.solver.union(
                [self.bsrr_write_value] + [other.bsrr_write_value for other in others]
            )
        else:
            merged_bsrr_write_value = claripy.ite_cases(
                zip(merge_conditions[1:], [other.bsrr_write_value for other in others]),
                self.bsrr_write_value,
            )

        changed = not utils.same_ast(self.bsrr_write_value, merged_bsrr_write_value)
        self.bsrr_write_value = merged_bsrr_write_value
        return changed


class GPIO(MMIOMemoryRegion):
    # FIXME: GPIO register 可以 8-bit, 16-bit, 32-bit 存取，如果是以 8/16-bit 存取時這個 bit 位置可能會有問題

    class GPIO_MODER(BaseRegister):
        OFFSET = 0x00

        # TODO: Port A, Port B 有不同 reset values

        MODER15 = BitsField(30, AccessType.RW, 0, 2)
        MODER13 = BitsField(26, AccessType.RW, 0, 2)

    class GPIO_OTYPER(BaseRegister):
        OFFSET = 0x04

        OT15 = BitsField(15, AccessType.RW, 0)
        OT13 = BitsField(13, AccessType.RW, 0)

    class GPIO_PUPDR(BaseRegister):
        OFFSET = 0x0C

        # TODO: Port A, Port B 有不同 reset values

        PUPDR15 = BitsField(30, AccessType.RW, 0, 2)
        PUPDR13 = BitsField(26, AccessType.RW, 0, 2)

    class GPIO_IDR(BaseRegister):
        OFFSET = 0x10

        IDR15 = BitsField(15, AccessType.R, 0)
        IDR13 = BitsField(13, AccessType.R, 0)

    class GPIO_ODR(BaseRegister):
        OFFSET = 0x14

        ODR15 = BitsField(15, AccessType.RW, 0)
        ODR13 = BitsField(13, AccessType.RW, 0)

    class GPIO_BSRR(BaseRegister):
        OFFSET = 0x18

        BR15 = BitsField(31, AccessType.W, 0)
        BS15 = BitsField(15, AccessType.W, 0)
        BR13 = BitsField(29, AccessType.W, 0)
        BS13 = BitsField(13, AccessType.W, 0)

    def get_idr(self, state):
        moder = utils.load(state, self.start + GPIO.GPIO_MODER.OFFSET)
        otyper = utils.load(state, self.start + GPIO.GPIO_OTYPER.OFFSET)
        odr = utils.load(state, self.start + GPIO.GPIO_ODR.OFFSET)
        pupdr = utils.load(state, self.start + GPIO.GPIO_PUPDR.OFFSET)

        idr = []

        for i in range(15, -1, -1):
            moder_bits = moder[2 * i + 1 : 2 * i]
            otyper_bit = otyper[i]
            odr_bit = odr[i]
            pupdr_bits = pupdr[2 * i + 1 : 2 * i]
            ext_driven = claripy.BVS(
                "ext_driven", 1
            )  # 外部是否有強驅動信號 (1 = 有連接且有強驅動, 0 = 外部浮接/高阻抗)
            ext_val = claripy.BVS(
                "ext_val", 1
            )  # 外部強驅動信號的邏輯值 (只有當 ext_driven == 1 時才有意義)

            alternate_function_possible = (
                state.solver.eval(moder_bits) == 2
                if moder_bits.concrete
                else state.solver.satisfiable(extra_constraints=[moder_bits == 2])
            )
            if alternate_function_possible:
                raise NotImplementedError(
                    "Alternate function mode is not supported yet (Should consider connected peripheral)"
                )

            hi_z_pin_state = claripy.If(
                ext_driven == 1,
                ext_val,
                claripy.If(
                    pupdr_bits == 1,  # pull-up
                    claripy.BVV(1, 1),
                    claripy.If(
                        pupdr_bits == 2,  # pull-down
                        claripy.BVV(0, 1),
                        claripy.BVS("floating", 1),  # no pull-up, pull-down
                    ),
                ),
            )

            idr.append(
                claripy.If(
                    moder_bits == 3,  # analog mode
                    claripy.BVV(0, 1),
                    claripy.If(
                        moder_bits == 1,  # general purpose output mode
                        claripy.If(
                            otyper_bit == 0,  # push-pull
                            odr_bit,
                            claripy.If(
                                odr_bit == 0, claripy.BVV(0, 1), hi_z_pin_state
                            ),  # open-drain
                        ),
                        hi_z_pin_state,  # input mode
                    ),
                )
            )

        idr = claripy.Concat(*idr)
        idr = idr.zero_extend(state.arch.bits - idr.size())
        return idr

    def get_access_effects(self, operation, address, size):
        effects = super().get_access_effects(operation, address, size)
        plugin_name = f"{self.name}_globals"

        if operation == "read":
            return effects.union(
                AccessEffects(
                    memory=frozenset(
                        {
                            MemoryEffect(
                                "read", self.start + offset, self.spec.ANGR_ARCH.bytes
                            )
                            for offset in (
                                GPIO.GPIO_MODER.OFFSET,
                                GPIO.GPIO_OTYPER.OFFSET,
                                GPIO.GPIO_PUPDR.OFFSET,
                                GPIO.GPIO_IDR.OFFSET,
                                GPIO.GPIO_ODR.OFFSET,
                            )
                        }
                        | {
                            MemoryEffect(
                                "write",
                                self.start + GPIO.GPIO_IDR.OFFSET,
                                self.spec.ANGR_ARCH.bytes,
                            )
                        }
                    )
                )
            )

        return effects.union(
            AccessEffects(
                memory=frozenset(
                    {
                        MemoryEffect(
                            "read",
                            self.start + GPIO.GPIO_ODR.OFFSET,
                            self.spec.ANGR_ARCH.bytes,
                        ),
                        MemoryEffect(
                            "write",
                            self.start + GPIO.GPIO_ODR.OFFSET,
                            self.spec.ANGR_ARCH.bytes,
                        ),
                    }
                ),
                plugins=frozenset(
                    {
                        PluginEffect("read", plugin_name, ("bsrr_write_value",)),
                        PluginEffect("write", plugin_name, ("bsrr_write_value",)),
                    }
                ),
            )
        )

    def pre_read(self, state):
        addr, offset = super().pre_read(state)

        match offset:
            case GPIO.GPIO_IDR.OFFSET:
                transaction = GPIOTransaction.begin(self, state)
                transaction.event_idr_read()
                transaction.commit_idr()

        return addr, offset

    def pre_write(self, state):
        addr, offset, value = super().pre_write(state)
        register_offset = self._register_offset(state, offset)

        match register_offset:
            case GPIO.GPIO_BSRR.OFFSET:
                transaction = GPIOTransaction.begin(self, state)
                transaction.event_bsrr_write_captured(
                    self._expand_register_write(state, offset, value)
                )
                transaction.commit_globals()

                # 寫入 BSRR 不會把寫入值存入暫存器
                zero = claripy.BVV(0, value.length)
                pending_key = ("_mmio_pending_write", id(self))
                pending = state.globals.get(pending_key)
                if pending is not None:
                    pending_addr, _, size, condition, endness = pending
                    state.globals[pending_key] = (
                        pending_addr,
                        zero,
                        size,
                        condition,
                        endness,
                    )
                state.inspect.mem_write_expr = zero

        return addr, offset, value

    def post_write(self, state):
        addr, offset, value = super().post_write(state)
        register_offset = self._register_offset(state, offset)

        match register_offset:
            case GPIO.GPIO_BSRR.OFFSET:
                transaction = GPIOTransaction.begin(self, state, load_odr=True)
                transaction.event_bsrr_write_applied()
                transaction.commit_odr_and_globals()

        return addr, offset, value

    def set_handlers(self, cpu, state, cfg, specs):
        Globals.register_default(f"{self.name}_globals")

    @staticmethod
    def _register_offset(state, offset):
        return offset - (offset % state.arch.bytes)

    @staticmethod
    def _expand_register_write(state, offset, value):
        byte_offset = offset % state.arch.bytes
        bit_offset = byte_offset * state.arch.byte_width
        if state.arch.memory_endness == archinfo.Endness.BE:
            bit_offset = state.arch.bits - value.size() - bit_offset

        return value.zero_extend(state.arch.bits - value.size()) << bit_offset


@dataclass
class GPIORegisterState:
    idr: object
    odr: object
    globals: Globals


class GPIOTransaction:
    def __init__(self, gpio, state, old, new):
        self.gpio = gpio
        self.state = state
        self.old = old
        self.new = new

    @classmethod
    def begin(cls, gpio, state, *, load_odr=False):
        globals_name = f"{gpio.name}_globals"
        globals_ = state.get_plugin(globals_name) or Globals()
        new_globals = globals_.copy({})

        snapshot = GPIORegisterState(
            idr=None,
            odr=(
                utils.load(state, gpio.start + GPIO.GPIO_ODR.OFFSET)
                if load_odr
                else None
            ),
            globals=globals_,
        )
        working = GPIORegisterState(
            idr=snapshot.idr, odr=snapshot.odr, globals=new_globals
        )
        return cls(gpio, state, snapshot, working)

    def commit_globals(self):
        self.state.register_plugin(f"{self.gpio.name}_globals", self.new.globals)

    def commit_idr(self):
        utils.store(self.state, self.gpio.start + GPIO.GPIO_IDR.OFFSET, self.new.idr)

    def commit_odr_and_globals(self):
        utils.store(self.state, self.gpio.start + GPIO.GPIO_ODR.OFFSET, self.new.odr)
        self.commit_globals()

    def event_idr_read(self):
        self.new.idr = self.gpio.get_idr(self.state)

    def event_bsrr_write_captured(self, value):
        self.new.globals.bsrr_write_value = value

    def event_bsrr_write_applied(self):
        value = self.old.globals.bsrr_write_value
        if value is None:
            return

        for port in range(16):
            # BS 比 BR 有較高優先權
            self.new.odr = claripy.If(
                value[port] == 1,
                utils.replace_bit(self.new.odr, port, 1),
                claripy.If(
                    value[port + 16] == 1,
                    utils.replace_bit(self.new.odr, port, 0),
                    self.new.odr,
                ),
            )

        self.new.globals.bsrr_write_value = None
