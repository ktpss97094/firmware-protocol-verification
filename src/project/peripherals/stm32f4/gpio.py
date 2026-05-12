import claripy

from project import utils
from project.types import AccessType, BaseRegister, BitsField, MMIOMemoryRegion


class GPIO(MMIOMemoryRegion):
    # FIXME: GPIO register 可以 8-bit, 16-bit, 32-bit 存取，如果是以 8/16-bit 存取時這個 bit 位置可能會有問題

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

    def post_write(self, state):
        _, offset, value = super().post_write(state)

        new_idr = utils.load(state, self.start + GPIO.GPIO_IDR.OFFSET)
        new_odr = utils.load(state, self.start + GPIO.GPIO_ODR.OFFSET)

        match offset:
            case GPIO.GPIO_BSRR.OFFSET:
                if state.solver.is_true(value[GPIO.GPIO_BSRR.BR13.bit]):
                    new_odr = utils.replace_bit(new_odr, GPIO.GPIO_BSRR.BS13.bit, 0)
                if state.solver.is_true(value[GPIO.GPIO_BSRR.BR15.bit]):
                    new_odr = utils.replace_bit(new_odr, GPIO.GPIO_BSRR.BS15.bit, 0)
                if state.solver.is_true(value[GPIO.GPIO_BSRR.BS13.bit]):
                    new_odr = utils.replace_bit(new_odr, GPIO.GPIO_BSRR.BS13.bit, 1)
                if state.solver.is_true(value[GPIO.GPIO_BSRR.BS15.bit]):
                    new_odr = utils.replace_bit(new_odr, GPIO.GPIO_BSRR.BS15.bit, 1)

                # 更新 IDR
                real_scl = claripy.If(
                    claripy.And(
                        new_odr[GPIO.GPIO_ODR.ODR13.bit] == 1,
                        claripy.BVS("external_scl", 1) == 1,
                    ),
                    claripy.BVV(1, 1),
                    claripy.BVV(0, 1),
                )  # wired-and
                new_idr = utils.replace_bit(new_idr, GPIO.GPIO_IDR.IDR13.bit, real_scl)
                real_sda = claripy.If(
                    claripy.And(
                        new_odr[GPIO.GPIO_ODR.ODR15.bit] == 1,
                        claripy.BVS("external_sda", 1) == 1,
                    ),
                    claripy.BVV(1, 1),
                    claripy.BVV(0, 1),
                )  # wired-and
                new_idr = utils.replace_bit(new_idr, GPIO.GPIO_IDR.IDR15.bit, real_sda)

        utils.store(state, self.start + GPIO.GPIO_IDR.OFFSET, new_idr)
        utils.store(state, self.start + GPIO.GPIO_ODR.OFFSET, new_odr)

        return _, offset, value
