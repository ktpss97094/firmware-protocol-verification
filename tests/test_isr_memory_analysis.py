from __future__ import annotations

import unittest
from pathlib import Path

import angr

from firmwares.stm32f429.protocols.I2C.spec_hw import Specs
from project.analyses.isr_memory import (
    ISRMemoryRegions,
    RegionAccess,
    analyze_isr_memory,
)


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
        project = angr.Project(
            str(ELF), auto_load_libs=False, arch=Specs.ANGR_ARCH
        )
        specs = Specs(project)
        cls.report = analyze_isr_memory(
            ELF,
            specs,
            svd_path=SVD,
        )

    def test_modeled_mmio_irqs_are_discovered_from_vector_table(self):
        targets = {
            report.irq: (report.address, report.isr) for report in self.report.isrs
        }
        self.assertEqual(
            {11, 12, 13, 14, 15, 16, 17, 31, 32},
            set(targets),
        )
        self.assertEqual((0x08000613, "I2C1_EV_IRQHandler"), targets[31])
        self.assertEqual((0x08000625, "I2C1_ER_IRQHandler"), targets[32])

    def test_identified_regions_support_fast_address_membership(self):
        regions = ISRMemoryRegions.from_report(self.report)
        main_data = next(region for region in regions if region.name == "main::data")

        self.assertIn(main_data.start, regions)
        self.assertIn(main_data.end - 1, regions)
        self.assertNotIn(0xDEADBEEF, regions)

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
            if report.irq == 31
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
            if report.irq == 32
        )
        regions = {region.name: region for region in error.regions}
        self.assertEqual(("write",), regions["main::data"].operations)
        self.assertTrue(error.unresolved_accesses)
        self.assertTrue(error.unresolved_calls)
        self.assertFalse(error.complete)
        self.assertFalse(self.report.complete)


class ISRMemoryRegionsTest(unittest.TestCase):
    def test_overlapping_regions_are_deduplicated_and_indexed(self):
        regions = ISRMemoryRegions(
            [
                RegionAccess("first", "global", 0x1000, 0x10, (), (), ()),
                RegionAccess("first", "global", 0x1000, 0x10, (), (), ()),
                RegionAccess("second", "global", 0x1008, 0x10, (), (), ()),
            ]
        )

        self.assertEqual(2, len(regions))
        self.assertIn(0x1000, regions)
        self.assertIn(0x1017, regions)
        self.assertNotIn(0x1018, regions)


if __name__ == "__main__":
    unittest.main()
