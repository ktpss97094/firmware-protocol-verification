import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import archinfo

from project.main import _run_to_snapshot


class EntrySPCaptureTests(unittest.TestCase):
    def setup_target(self, stops, *, pc=0x8000000, sp=0x20020000, listed=False):
        self.registers = {"pc": pc, "sp": sp}
        target = Mock()
        target._arch = SimpleNamespace(pc_name="pc")
        target.set_breakpoint.return_value = 1
        target.read_register.side_effect = lambda name: (
            [self.registers[name]] if listed else self.registers[name]
        )
        stops = iter(stops)

        def resume():
            pc, sp = next(stops)
            self.registers.update(pc=pc, sp=sp)

        target.cont.side_effect = resume
        project = SimpleNamespace(
            arch=archinfo.ArchARMCortexM(),
            loader=SimpleNamespace(
                find_symbol=Mock(return_value=SimpleNamespace(rebased_addr=0x8000101))
            ),
        )
        return target, project

    def test_captures_entry_sp_before_prologue_and_preserves_snapshot_sp(self):
        target, project = self.setup_target(
            [(0x8000100, 0x2001FFF0), (0x8000200, 0x2001FFC0)]
        )
        entry_sp = _run_to_snapshot(target, project, 0x8000201)
        self.assertEqual(entry_sp, 0x2001FFF0)
        self.assertEqual(self.registers["sp"], 0x2001FFC0)
        self.assertEqual(self.registers["pc"], 0x8000200)
        self.assertEqual(
            target.set_breakpoint.call_args_list,
            [
                unittest.mock.call(0x8000100, temporary=True),
                unittest.mock.call(0x8000200, temporary=True),
            ],
        )

    def test_snapshot_at_main_does_not_execute_prologue(self):
        target, project = self.setup_target([(0x8000100, 0x2001FFF0)], listed=True)
        self.assertEqual(_run_to_snapshot(target, project, 0x8000101), 0x2001FFF0)
        target.cont.assert_called_once()
        target.set_breakpoint.assert_called_once_with(0x8000100, temporary=True)

    def test_already_at_entry_needs_no_resume(self):
        target, project = self.setup_target([], pc=0x8000101, sp=0x2001FFF0)
        self.assertEqual(_run_to_snapshot(target, project, 0x8000100), 0x2001FFF0)
        target.cont.assert_not_called()
        target.set_breakpoint.assert_not_called()

    def test_unexpected_main_stop_does_not_capture_wrong_sp(self):
        target, project = self.setup_target([(0x8000080, 0x2001FFF8)])
        with self.assertRaisesRegex(RuntimeError, "expected 0x8000100"):
            _run_to_snapshot(target, project, 0x8000200)
        self.assertNotIn(unittest.mock.call("sp"), target.read_register.call_args_list)
        target.cont.assert_called_once()

    def test_unexpected_snapshot_stop_fails(self):
        target, project = self.setup_target(
            [(0x8000100, 0x2001FFF0), (0x8000180, 0x2001FFC8)]
        )
        with self.assertRaisesRegex(RuntimeError, "expected 0x8000200"):
            _run_to_snapshot(target, project, 0x8000200)

    def test_missing_main_fails_before_resuming(self):
        target, project = self.setup_target([])
        project.loader.find_symbol.return_value = None
        with self.assertRaisesRegex(ValueError, "no main symbol"):
            _run_to_snapshot(target, project, 0x8000200)
        target.cont.assert_not_called()

    def test_failed_breakpoint_does_not_resume(self):
        for failure in (-1, False, None):
            with self.subTest(failure=failure):
                target, project = self.setup_target([])
                target.set_breakpoint.return_value = failure
                with self.assertRaisesRegex(RuntimeError, "Unable to set breakpoint"):
                    _run_to_snapshot(target, project, 0x8000200)
                target.cont.assert_not_called()


if __name__ == "__main__":
    unittest.main()
