MEMORY
{
ram (xrw)      : ORIGIN = 0x20000000, LENGTH = 192K
ccmram (xrw)      : ORIGIN = 0x10000000, LENGTH = 64K
rom (rx)      : ORIGIN = 0x8000000, LENGTH = 2048K
}

INCLUDE cortex-m-generic.ld