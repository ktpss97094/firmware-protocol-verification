"""
I2C Master Clock Stretching Spec

Precondition: SB, ADDR, ADD10, STOPF, BTF, TxE, RxNE, ITEVFEN, ITBUFEN symbolic
1. clear ADDR bit 前，若 ADDR bit 為 0，則違反
    > 考慮: I2C_Master_ADDR()
    > 忽略: I2C_Slave_ADDR() (slave mode)
2. Precondition: Size > 0, DMAEN = 0
    set STOP bit 前，若 BTF bit 為 0，則違反
    > 考慮: I2C_MasterTransmit_BTF()
    > 忽略: I2C_Master_ADDR() (receiver mode 才有 set STOP), I2C_MasterTransmit_TXE() (Size == 0 才有 set STOP), I2C_MemoryTransmit_TXE_BTF() (memory mode), I2C_MasterReceive_BTF() (receiver mode)

Symbolic Variables:
    SR2 (TRA)
    SR1 (SB, ADD10, ADDR, TxE, BTF)
"""
