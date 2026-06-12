from __future__ import annotations

import unittest
from pathlib import Path

from project.analyses.isr_memory import analyze_isr_memory


ROOT = Path(__file__).resolve().parents[1]
ELF = (
    ROOT
    / "firmwares/stm32f429/build/protocols/I2C/master/Interrupt_Mode"
    / "stm32f4xx-hal-driver/firmware.elf"
)
SVD = (
    ROOT
    / "firmwares/stm32f429/protocols/I2C/master/Interrupt_Mode"
    / "stm32f4xx-hal-driver/STM32F429.svd"
)


class ISRMemoryAnalysisTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_isr_memory(
            ELF,
            ["I2C1_EV_IRQHandler", "I2C1_ER_IRQHandler"],
            svd_path=SVD,
        )

    def test_main_stack_pointer_escape_is_recovered(self):
        facts = {
            (fact.cell.name, fact.value, fact.target)
            for fact in self.report.pointer_facts
        }
        self.assertIn(
            ("hi2c1.Instance", 0x40005400, "I2C1"),
            facts,
        )
        self.assertIn(
            ("hi2c1.pBuffPtr", 0x2001FFF4, "main::data"),
            facts,
        )

    def test_event_isr_resolves_expected_shared_regions(self):
        event = next(
            report
            for report in self.report.isrs
            if report.isr == "I2C1_EV_IRQHandler"
        )
        regions = {region.name: region for region in event.regions}
        self.assertIn("hi2c1", regions)
        self.assertIn("main::data", regions)
        for register in ("I2C1.CR1", "I2C1.CR2", "I2C1.DR", "I2C1.SR1", "I2C1.SR2"):
            self.assertIn(register, regions)
        self.assertEqual(("read", "write"), regions["main::data"].operations)

    def test_error_isr_resolves_buffer_write_and_reports_incompleteness(self):
        error = next(
            report
            for report in self.report.isrs
            if report.isr == "I2C1_ER_IRQHandler"
        )
        regions = {region.name: region for region in error.regions}
        self.assertEqual(("write",), regions["main::data"].operations)
        self.assertTrue(error.unresolved_accesses)
        self.assertTrue(error.unresolved_calls)
        self.assertFalse(error.complete)
        self.assertFalse(self.report.complete)


if __name__ == "__main__":
    unittest.main()
