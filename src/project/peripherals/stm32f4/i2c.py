import claripy

from project import utils
from project.types import MMIOMemoryRegion


class I2C(MMIOMemoryRegion):
    class CR1:
        OFFSET = 0x00

        STOP = 9
        START = 8

    class CR2:
        OFFSET = 0x04

        ITEVTEN = 9

    class DR:
        OFFSET = 0x10

    class SR1:
        OFFSET = 0x14

        AF = 10
        TXE = 7
        ADD10 = 3
        BTF = 2
        ADDR = 1
        SB = 0

    class SR2:
        OFFSET = 0x18

        TRA = 2
        BUSY = 1

    def read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        self.pre_read(state, offset)

        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)
        sr2 = utils.load(state, self.start + I2C.SR2.OFFSET)
        new_sr1 = sr1
        new_sr2 = sr2

        match offset:
            case I2C.SR1.OFFSET:
                state.globals[f"{self.name}_SR1_read"] = True

                if sr1[I2C.SR1.ADDR].symbolic:
                    """
                    當 ADDR 變成 symbolic (表示可能是 0/1) 後，將新的 ADDR 記憶體值設定成:
                        * 舊值是 0 => 新值是 symbolic variable
                        * 舊值是 1 => 新值不變
                    """
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.ADDR,
                        claripy.If(
                            sr1[I2C.SR1.ADDR] == 1,
                            sr1[I2C.SR1.ADDR],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_ADDR", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.SB].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.SB,
                        claripy.If(
                            sr1[I2C.SR1.SB] == 1,
                            sr1[I2C.SR1.SB],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_SB", size=1
                            ),
                        ),
                    )

                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.TXE,
                        claripy.If(new_sr1[I2C.SR1.SB] == 1, 0, sr1[I2C.SR1.TXE]),
                    )
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(new_sr1[I2C.SR1.SB] == 1, 0, sr1[I2C.SR1.BTF]),
                    )
                if sr1[I2C.SR1.ADD10].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.ADD10,
                        claripy.If(
                            sr1[I2C.SR1.ADD10] == 1,
                            sr1[I2C.SR1.ADD10],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_ADD10", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.AF].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.AF,
                        claripy.If(
                            sr1[I2C.SR1.AF] == 1,
                            sr1[I2C.SR1.AF],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_AF", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.TXE].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.TXE,
                        claripy.If(
                            sr1[I2C.SR1.TXE] == 1,
                            sr1[I2C.SR1.TXE],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_TxE", size=1
                            ),
                        ),
                    )
                if sr1[I2C.SR1.BTF].symbolic:
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(
                            sr1[I2C.SR1.BTF] == 1,
                            sr1[I2C.SR1.BTF],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_BTF", size=1
                            ),
                        ),
                    )

            case I2C.SR2.OFFSET:
                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (ADDR) This bit is cleared by software reading SR1 register followed reading SR2
                    new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.ADDR)
                    # clear ADDR 時結束 address phase
                    state.globals["is_address_phase"] = False

                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_sr1 = utils.set_bits(new_sr1, I2C.SR1.TXE)

            case I2C.DR.OFFSET:
                # (BTF) Cleared by software by either a read or write in the DR register
                new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.BTF)

        utils.store(state, self.start + I2C.SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.SR2.OFFSET, new_sr2)

    def write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        self.pre_write(state, offset, value)

        cr1 = utils.load(state, self.start + I2C.CR1.OFFSET)
        sr1 = utils.load(state, self.start + I2C.SR1.OFFSET)
        sr2 = utils.load(state, self.start + I2C.SR2.OFFSET)
        new_cr1 = cr1
        new_sr1 = sr1
        new_sr2 = sr2

        match offset:
            case I2C.CR1.OFFSET:
                # set START bit 時進入 address phase
                if not state.solver.satisfiable(extra_constraints=[value[8] == 0]):
                    state.globals["is_address_phase"] = True

                    # (SB) Set when a Start condition generated
                    new_sr1 = utils.symbolic_bit(
                        state,
                        new_sr1,
                        I2C.SR1.SB,
                        f"{self.name}_{I2C.SR1.OFFSET:#x}_SB",
                    )

                # set STOP bit
                if not state.solver.satisfiable(extra_constraints=[value[9] == 0]):
                    # (STOP) cleared by hardware when a Stop condition is detected
                    new_cr1 = utils.symbolic_bit(
                        state,
                        new_cr1,
                        I2C.CR1.STOP,
                        f"{self.name}_{I2C.CR1.OFFSET:#x}_STOP",
                    )

                    # (TxE) Cleared ... or by hardware after a start or a stop condition
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.TXE,
                        claripy.If(new_cr1[I2C.CR1.STOP] == 0, 0, sr1[I2C.SR1.TXE]),
                    )
                    # (BTF) Cleared ... or by hardware after a start or a stop condition in transmission
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(new_cr1[I2C.CR1.STOP] == 0, 0, sr1[I2C.SR1.BTF]),
                    )

            case I2C.DR.OFFSET:
                # (TxE) Cleared by software writing to the DR register
                # (BTF) Cleared by software by either a read or write in the DR register
                new_sr1 = utils.clear_bits(new_sr1, [I2C.SR1.TXE, I2C.SR1.BTF])

                if state.globals.get(f"{self.name}_SR1_read", False):
                    state.globals[f"{self.name}_SR1_read"] = False

                    # (SB) Cleared by software by reading the SR1 register followed by writing the DR register
                    new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.SB)

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
                            I2C.SR1.ADD10,
                            f"{self.name}_{I2C.SR1.OFFSET:#x}_ADD10",
                        )
                    else:
                        if state.globals.get("is_10bit", False) and state.globals.get(
                            f"{self.name}_SR1_read", False
                        ):
                            state.globals[f"{self.name}_SR1_read"] = False

                            # (ADD10) Cleared by software reading the SR1 register followed by a write in the DR register of the second address byte
                            new_sr1 = utils.clear_bits(new_sr1, I2C.SR1.ADD10)

                        # (ADDR) For 10-bit addressing, the bit is set after the ACK of the 2nd byte. For 7-bit addressing, the bit is set after the ACK of the byte
                        new_sr1 = utils.symbolic_bit(
                            state,
                            new_sr1,
                            I2C.SR1.ADDR,
                            f"{self.name}_{I2C.SR1.OFFSET:#x}_ADDR",
                        )
                else:
                    # (TxE) Set when DR is empty in transmission. TxE is not set during address phase
                    new_sr1 = utils.symbolic_bit(
                        state,
                        new_sr1,
                        I2C.SR1.TXE,
                        f"{self.name}_{I2C.SR1.OFFSET:#x}_TxE",
                    )

                    # (BTF) Set ... In transmission when a new byte should be sent and DR has not been written yet (TxE=1)
                    # 只有 TxE 是 1 時，BTF 才可能是 1
                    new_sr1 = utils.replace_bit(
                        new_sr1,
                        I2C.SR1.BTF,
                        claripy.If(
                            new_sr1[I2C.SR1.TXE] == 0,
                            new_sr1[I2C.SR1.BTF],
                            utils.generate_symbolic(
                                state, f"{self.name}_{I2C.SR1.OFFSET:#x}_BTF", size=1
                            ),
                        ),
                    )

                # (AF) Set by hardware when no acknowledge is returned
                new_sr1 = utils.replace_bit(
                    new_sr1,
                    I2C.SR1.AF,
                    claripy.If(
                        claripy.Or(
                            new_sr1[I2C.SR1.BTF] == 1, new_sr1[I2C.SR1.ADDR] == 1
                        ),
                        0,
                        utils.generate_symbolic(
                            state, f"{self.name}_{I2C.SR1.OFFSET:#x}_AF", size=1
                        ),
                    ),
                )

        utils.store(state, self.start + I2C.CR1.OFFSET, new_cr1)
        utils.store(state, self.start + I2C.SR1.OFFSET, new_sr1)
        utils.store(state, self.start + I2C.SR2.OFFSET, new_sr2)
