from collections import defaultdict

import claripy

from project import utils
from project.types import AccessType, BaseRegister, BitField, MMIOMemoryRegion


class I2C(MMIOMemoryRegion):
    IRQ_NUMBERS = [31, 32]  # I2C1_EV, I2C1_ER

    class I2C_CR1(BaseRegister):
        OFFSET = 0x00

        STOP = BitField(9, AccessType.RW)
        START = BitField(8, AccessType.RW)

    class I2C_CR2(BaseRegister):
        OFFSET = 0x04

        ITBUFEN = BitField(10, AccessType.RW)
        ITEVTEN = BitField(9, AccessType.RW)
        ITERREN = BitField(8, AccessType.RW)

    class I2C_DR(BaseRegister):
        OFFSET = 0x10

        DR = BitField(0, AccessType.RW, size=8)

    class I2C_SR1(BaseRegister):
        OFFSET = 0x14

        SMBALERT = BitField(15, AccessType.RC_W0)
        TIMEOUT = BitField(14, AccessType.RC_W0)
        PECERR = BitField(12, AccessType.RC_W0)
        OVR = BitField(11, AccessType.RC_W0)
        AF = BitField(10, AccessType.RC_W0)
        ARLO = BitField(9, AccessType.RC_W0)
        BERR = BitField(8, AccessType.RC_W0)
        TXE = BitField(7, AccessType.R)
        RXNE = BitField(6, AccessType.R)
        STOPF = BitField(4, AccessType.R)
        ADD10 = BitField(3, AccessType.R)
        BTF = BitField(2, AccessType.R)
        ADDR = BitField(1, AccessType.R)
        SB = BitField(0, AccessType.R)

    class I2C_SR2(BaseRegister):
        OFFSET = 0x18

    def pre_write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr
        orig_value = utils.load(state, addr)

        state.inspect.mem_write_expr = self.mask_write(offset, orig_value, value)

    def post_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        self.post_read_spec(state, offset)

        cr1 = utils.load(state, self.start + I2C.I2C_CR1.OFFSET)
        sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        new_cr1 = cr1
        new_sr1 = sr1

        match offset:
            case I2C.I2C_CR1.OFFSET:
                if cr1[I2C.I2C_CR1.START.bit].symbolic:
                    # (START) This bit is set and cleared by software and cleared by hardware when start is sent
                    new_cr1 = utils.replace_bit(
                        new_cr1,
                        I2C.I2C_CR1.START.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.SB.bit] == 1, 0, cr1[I2C.I2C_CR1.START.bit]
                        ),
                    )

            case I2C.I2C_SR1.OFFSET:
                state.globals[f"{self.name}_SR1_read"] = True

                if sr1[I2C.I2C_SR1.ADDR.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.ADDR.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.ADDR.bit] == 1,
                            sr1[I2C.I2C_SR1.ADDR.bit],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_ADDR",
                                size=1,
                            ),
                        ),
                    )
                if sr1[I2C.I2C_SR1.SB.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.SB.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.SB.bit] == 1,
                            sr1[I2C.I2C_SR1.SB.bit],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_SB", size=1
                            ),
                        ),
                    )

                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.TXE.bit,
                        claripy.If(
                            new_sr1[I2C.I2C_SR1.SB.bit] == 1,
                            0,
                            sr1[I2C.I2C_SR1.TXE.bit],
                        ),
                    )
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.BTF.bit,
                        claripy.If(
                            new_sr1[I2C.I2C_SR1.SB.bit] == 1,
                            0,
                            sr1[I2C.I2C_SR1.BTF.bit],
                        ),
                    )
                if sr1[I2C.I2C_SR1.ADD10.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.ADD10.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.ADD10.bit] == 1,
                            sr1[I2C.I2C_SR1.ADD10.bit],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_ADD10",
                                size=1,
                            ),
                        ),
                    )
                if sr1[I2C.I2C_SR1.AF.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.AF.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.AF.bit] == 1,
                            sr1[I2C.I2C_SR1.AF.bit],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_AF", size=1
                            ),
                        ),
                    )
                if sr1[I2C.I2C_SR1.ARLO.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.ARLO.bit,
                        claripy.If(
                            claripy.Or(
                                new_sr1[I2C.I2C_SR1.BTF.bit] == 1,
                                new_sr1[I2C.I2C_SR1.ADDR.bit] == 1,
                                new_sr1[I2C.I2C_SR1.AF.bit] == 1,
                            ),
                            0,
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_ARLO",
                                size=1,
                            ),
                        ),
                    )
                if sr1[I2C.I2C_SR1.TXE.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.TXE.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.TXE.bit] == 1,
                            sr1[I2C.I2C_SR1.TXE.bit],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_TxE",
                                size=1,
                            ),
                        ),
                    )
                if sr1[I2C.I2C_SR1.BTF.bit].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.BTF.bit,
                        claripy.If(
                            sr1[I2C.I2C_SR1.BTF.bit] == 1,
                            sr1[I2C.I2C_SR1.BTF.bit],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_BTF",
                                size=1,
                            ),
                        ),
                    )

            case I2C.I2C_SR2.OFFSET:
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    new_sr1 = utils.clear_bits(new_sr1, I2C.I2C_SR1.ADDR.bit)
                    # clear ADDR 時結束 address phase
                    state.globals["is_address_phase"] = False

                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_sr1 = utils.set_bits(new_sr1, I2C.I2C_SR1.TXE.bit)

            case I2C.I2C_DR.OFFSET:
                # (BTF) Cleared by software by either a read or write in the DR register
                new_sr1 = utils.clear_bits(new_sr1, I2C.I2C_SR1.BTF.bit)

        utils.store(state, self.start + I2C.I2C_CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.I2C_SR1.OFFSET, new_sr1)

    def post_write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        self.post_write_spec(state, offset, value)

        cr1 = utils.load(state, self.start + I2C.I2C_CR1.OFFSET)
        sr1 = utils.load(state, self.start + I2C.I2C_SR1.OFFSET)
        new_cr1 = cr1
        new_sr1 = sr1

        match offset:
            case I2C.I2C_CR1.OFFSET:
                # set START bit 時進入 address phase
                if state.solver.is_true(value[I2C.I2C_CR1.START.bit] == 1):
                    state.globals["is_address_phase"] = True

                    # (SB) Set when a Start condition generated
                    new_sr1 = utils.symbolic_bit(
                        state,
                        new_sr1,
                        I2C.I2C_SR1.SB.bit,
                        f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_SB",
                    )

                    # (START) This bit is set and cleared by software and cleared by hardware when start is sent
                    new_cr1 = utils.replace_bit(
                        new_cr1,
                        I2C.I2C_CR1.START.bit,
                        claripy.If(
                            new_sr1[I2C.I2C_SR1.SB.bit] == 1,
                            0,
                            cr1[I2C.I2C_CR1.START.bit],
                        ),
                    )

                # set STOP bit
                if state.solver.is_true(value[I2C.I2C_CR1.STOP.bit] == 1):
                    # (STOP) cleared by hardware when a Stop condition is detected
                    new_cr1 = utils.symbolic_bit(
                        state,
                        new_cr1,
                        I2C.I2C_CR1.STOP.bit,
                        f"{self.name}_{I2C.I2C_CR1.OFFSET:#x}_STOP",
                    )

                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.TXE.bit,
                        claripy.If(
                            new_cr1[I2C.I2C_CR1.STOP.bit] == 0,
                            0,
                            sr1[I2C.I2C_SR1.TXE.bit],
                        ),
                    )
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.BTF.bit,
                        claripy.If(
                            new_cr1[I2C.I2C_CR1.STOP.bit] == 0,
                            0,
                            sr1[I2C.I2C_SR1.BTF.bit],
                        ),
                    )

            case I2C.I2C_DR.OFFSET:
                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either a read or write in the DR register
                new_sr1 = utils.clear_bits(
                    new_sr1, [I2C.I2C_SR1.TXE.bit, I2C.I2C_SR1.BTF.bit]
                )

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    new_sr1 = utils.clear_bits(new_sr1, I2C.I2C_SR1.SB.bit)

                if state.globals.get("is_address_phase", False):
                    # 10-bit addressing 的 addressing phase 會 write 兩次 DR。第一次 write (header) 時是 11110xxx
                    if not state.solver.satisfiable(
                        extra_constraints=[(value & 0xF8) != 0xF0]
                    ):
                        state.globals["is_10bit"] = True

                        # (ADD10) Set by hardware when the master has sent the first byte in 10-bit address mode
                        new_sr1 = utils.symbolic_bit(
                            state,
                            new_sr1,
                            I2C.I2C_SR1.ADD10,
                            f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_ADD10",
                        )
                    else:
                        if state.globals.get("is_10bit", False) and state.globals.get(
                            f"{self.name}_SR1_read", False
                        ):
                            state.globals[f"{self.name}_SR1_read"] = False

                            # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                            new_sr1 = utils.clear_bits(new_sr1, I2C.I2C_SR1.ADD10.bit)

                        # (ADDR) For 10-bit addressing, the bit is set after the ACK of the 2nd byte. For 7-bit addressing, the bit is set after the ACK of the byte
                        new_sr1 = utils.symbolic_bit(
                            state,
                            new_sr1,
                            I2C.I2C_SR1.ADDR.bit,
                            f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_ADDR",
                        )
                else:
                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_sr1 = utils.symbolic_bit(
                        state,
                        new_sr1,
                        I2C.I2C_SR1.TXE.bit,
                        f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_TxE",
                    )

                    # (BTF) Set ... In transmission when a new byte should be sent and DR has not been written yet (TxE=1)
                    # 只有 TxE 是 1 時，BTF 才可能是 1
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.I2C_SR1.BTF.bit,
                        claripy.If(
                            new_sr1[I2C.I2C_SR1.TXE.bit] == 0,
                            new_sr1[I2C.I2C_SR1.BTF.bit],
                            utils.generate_symbolic(
                                state,
                                f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_BTF",
                                size=1,
                            ),
                        ),
                    )

                # (AF) Set by hardware when no acknowledge is returned
                new_sr1 = utils.replace_bit(
                    new_sr1,
                    I2C.I2C_SR1.AF.bit,
                    claripy.If(
                        claripy.Or(
                            new_sr1[I2C.I2C_SR1.BTF.bit] == 1,
                            new_sr1[I2C.I2C_SR1.ADDR.bit] == 1,
                        ),
                        0,
                        utils.generate_symbolic(
                            state, f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_AF", size=1
                        ),
                    ),
                )

                # (ARLO)
                new_sr1 = utils.replace_bit(
                    new_sr1,
                    I2C.I2C_SR1.ARLO.bit,
                    claripy.If(
                        claripy.Or(
                            new_sr1[I2C.I2C_SR1.BTF.bit] == 1,
                            new_sr1[I2C.I2C_SR1.ADDR.bit] == 1,
                            new_sr1[I2C.I2C_SR1.AF.bit] == 1,
                        ),
                        0,
                        utils.generate_symbolic(
                            state, f"{self.name}_{I2C.I2C_SR1.OFFSET:#x}_ARLO", size=1
                        ),
                    ),
                )

        utils.store(state, self.start + I2C.I2C_CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.I2C_SR1.OFFSET, new_sr1)

    def get_pending_irqs(self, state):
        for irq_num in self.IRQ_NUMBERS:
            if irq_num not in state.custom_globals.irq:
                state.custom_globals.irq[irq_num] = {"handled_hashes": frozenset()}

        cr2 = utils.load(state, self.start + I2C.I2C_CR2.OFFSET)
        events_to_check = []
        output = defaultdict(list)

        if state.solver.is_true(cr2[I2C.I2C_CR2.ITEVTEN.bit] == 1):
            events_to_check.extend(
                [
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.SB.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.ADDR.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.ADD10.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.BTF.bit, self.IRQ_NUMBERS[0]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.STOPF.bit, self.IRQ_NUMBERS[0]),
                ]
            )

            if state.solver.is_true(cr2[I2C.I2C_CR2.ITBUFEN.bit] == 1):
                events_to_check.extend(
                    [
                        (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.TXE.bit, self.IRQ_NUMBERS[0]),
                        (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.RXNE.bit, self.IRQ_NUMBERS[0]),
                    ]
                )

        if state.solver.is_true(cr2[I2C.I2C_CR2.ITERREN.bit] == 1):
            events_to_check.extend(
                [
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.BERR.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.ARLO.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.AF.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.OVR.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.PECERR.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.TIMEOUT.bit, self.IRQ_NUMBERS[1]),
                    (I2C.I2C_SR1.OFFSET, I2C.I2C_SR1.SMBALERT.bit, self.IRQ_NUMBERS[1]),
                ]
            )

        for event_offset, event_bit, irq_num in events_to_check:
            event_val = utils.load(state, self.start + event_offset)[event_bit]
            trigger_cond = event_val == 1

            if hash(event_val) not in state.custom_globals.irq[irq_num][
                "handled_hashes"
            ] and state.solver.satisfiable(extra_constraints=[trigger_cond]):
                output[irq_num].append((event_val, trigger_cond))

        return output
