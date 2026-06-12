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

    @property
    def _state_plugin_name(self):
        return f"stm32f4_gpio_{self.start:x}"

    def _state(self, state):
        if not state.has_plugin(self._state_plugin_name):
            state.register_plugin(self._state_plugin_name, Globals())
        return state.get_plugin(self._state_plugin_name)

    def set_handlers(self, cpu, state, cfg, specs):
        self._state(state)
        return super().set_handlers(cpu, state, cfg, specs)

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

            if state.solver.satisfiable(extra_constraints=[moder_bits == 2]):
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

        return claripy.Concat(*idr)

    def get_access_effects(self, operation, address, size):
        effects = super().get_access_effects(operation, address, size)
        register_size = self.spec.ANGR_ARCH.bytes

        if operation == "read":
            return effects.union(
                AccessEffects(
                    memory=frozenset(
                        {
                            MemoryEffect("read", self.start + offset, register_size)
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
                                register_size,
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
                            "read", self.start + GPIO.GPIO_ODR.OFFSET, register_size
                        ),
                        MemoryEffect(
                            "write", self.start + GPIO.GPIO_ODR.OFFSET, register_size
                        ),
                    }
                ),
                plugins=frozenset(
                    {
                        PluginEffect(
                            "read", self._state_plugin_name, ("bsrr_write_value",)
                        ),
                        PluginEffect(
                            "write", self._state_plugin_name, ("bsrr_write_value",)
                        ),
                    }
                ),
            )
        )

    def pre_write(self, state):
        _, offset, value = super().pre_write(state)

        match offset:
            case GPIO.GPIO_BSRR.OFFSET:
                # 寫入 BSRR 不會把寫入值存入暫存器
                self._state(state).bsrr_write_value = value
                state.inspect.mem_write_expr = claripy.BVV(
                    0, state.inspect.mem_write_expr.length
                )

        return _, offset, value

    def post_read(self, state):
        _, offset, readout_value = super().post_read(state)

        new_idr = utils.load(state, self.start + GPIO.GPIO_IDR.OFFSET)

        match offset:
            case GPIO.GPIO_IDR.OFFSET:
                new_idr = self.get_idr(state)

        utils.store(state, self.start + GPIO.GPIO_IDR.OFFSET, new_idr)

        return _, offset, readout_value

    def post_write(self, state):
        _, offset, value = super().post_write(state)

        new_odr = utils.load(state, self.start + GPIO.GPIO_ODR.OFFSET)

        match offset:
            case GPIO.GPIO_BSRR.OFFSET:
                bsrr_write_value = self._state(state).bsrr_write_value
                for port in range(16):
                    # BS 比 BR 有較高優先權
                    new_odr = claripy.If(
                        bsrr_write_value[port] == 1,
                        utils.replace_bit(new_odr, port, 1),
                        claripy.If(
                            bsrr_write_value[port + 16] == 1,
                            utils.replace_bit(new_odr, port, 0),
                            new_odr,
                        ),
                    )

        utils.store(state, self.start + GPIO.GPIO_ODR.OFFSET, new_odr)

        return _, offset, value
