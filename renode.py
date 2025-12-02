# -*- coding: utf-8 -*-
import sys
import clr
import System
from Antmicro.Renode.Logging import Logger, LogLevel
from Antmicro.Renode.Peripherals.Bus import SysbusAccessWidth, Access

# --- 取得 sysbus ---
if 'sysbus' not in globals():
    if 'monitor' in globals():
        sysbus = monitor.Machine.SystemBus
    elif 'machine' in globals():
        sysbus = machine.SystemBus

I2C1_BASE = 0x40005400
SR1_OFFSET = 0x14
SR1_ADDR = I2C1_BASE + SR1_OFFSET

context = {
    "is_stretching": True,
    "poll_count": 0,
    "success_threshold": 10
}

def sr1_read_hook(cpu, address, size, value):
    # 【暴力除錯】無條件印出，證明 Hook 活著！
    # 如果你看到這行，代表 Hook 終於接通了
    Logger.Log(LogLevel.Debug, "[Python Hook] Read SR1, Val: 0x{:X}".format(address, value))

    if not context["is_stretching"]:
        return value

    # 檢查 ADDR bit (Bit 1)
    if (value & (1 << 1)):
        context["poll_count"] += 1
        
        Logger.Log(LogLevel.Debug, "[Python Hook] Firmware polling ADDR... Count: {}/{}".format(context['poll_count'], context['success_threshold']))

        if context["poll_count"] >= context["success_threshold"]:
            Logger.Log(LogLevel.Error, "\n[Python Hook] SUCCESS: Clock Stretching Verified! (Polled {} times)\n".format(context['poll_count']))
            context["is_stretching"] = False
            return value # 放行
        
        # 欺騙 Firmware: 回傳 ADDR=0
        return value & ~(1 << 1)
    
    return value

# --- 極致安全的 Enum 建構 ---
# 全部使用 System.Enum.ToObject，不依賴任何 Python 自動轉型
enum_byte = System.Enum.ToObject(SysbusAccessWidth, 1)
enum_halfword = System.Enum.ToObject(SysbusAccessWidth, 2)
enum_word = System.Enum.ToObject(SysbusAccessWidth, 4)
# Access.Read = 1
enum_read = System.Enum.ToObject(Access, 1)

# 註冊所有寬度
sysbus.AddWatchpointHook(SR1_ADDR, enum_byte, enum_read, sr1_read_hook)
sysbus.AddWatchpointHook(SR1_ADDR, enum_halfword, enum_read, sr1_read_hook)
sysbus.AddWatchpointHook(SR1_ADDR, enum_word, enum_read, sr1_read_hook)