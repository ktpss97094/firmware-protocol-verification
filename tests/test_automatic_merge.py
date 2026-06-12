import unittest

from project.types import AutomaticMerge


class FakeState:
    def __init__(self, key):
        self.key = key


class FakeSimulationManager:
    def __init__(self, states):
        self.stashes = {"active": list(states)}
        self.merge_calls = []

    @staticmethod
    def _merge_key(state):
        return state.key

    def step(self, stash="active", **kwargs):
        del stash, kwargs
        return self

    def merge(self, merge_key=None, stash="active", prune=True):
        states = self.stashes[stash]
        self.merge_calls.append((list(states), prune))

        groups = {}
        for state in states:
            groups.setdefault(merge_key(state), []).append(state)

        merged = []
        for group in groups.values():
            merged.append(FakeState(group[0].key))
        self.stashes[stash] = merged
        return self


class AutomaticMergeTest(unittest.TestCase):
    def test_does_not_call_merge_without_compatible_candidates(self):
        simgr = FakeSimulationManager(FakeState(index) for index in range(21))
        technique = AutomaticMerge(
            max_states=20,
            merge_key=lambda state: state.key,
        )

        technique.step(simgr)

        self.assertEqual(0, len(simgr.merge_calls))
        self.assertEqual(21, len(simgr.stashes["active"]))

    def test_merges_only_candidate_groups(self):
        duplicate_states = [FakeState("join") for _ in range(5)]
        unique_states = [FakeState(index) for index in range(17)]
        simgr = FakeSimulationManager(duplicate_states + unique_states)
        technique = AutomaticMerge(
            max_states=20,
            merge_key=lambda state: state.key,
        )

        technique.step(simgr)

        self.assertEqual(1, len(simgr.merge_calls))
        merged_input, prune = simgr.merge_calls[0]
        self.assertEqual(5, len(merged_input))
        self.assertFalse(prune)
        self.assertEqual(18, len(simgr.stashes["active"]))
        self.assertEqual(4, technique.states_merged)

    def test_cooldown_skips_small_repeated_merges(self):
        technique = AutomaticMerge(
            max_states=4,
            merge_key=lambda state: state.key,
            min_reduction=1,
            merge_interval=4,
            substantial_reduction_ratio=0.75,
        )
        first = FakeSimulationManager(
            [FakeState("join"), FakeState("join")]
            + [FakeState(index) for index in range(3)]
        )
        technique.step(first)
        self.assertEqual(1, len(first.merge_calls))

        second = FakeSimulationManager(
            [FakeState("join"), FakeState("join")]
            + [FakeState(index) for index in range(3)]
        )
        technique.step(second)
        self.assertEqual(0, len(second.merge_calls))

    def test_large_reduction_bypasses_cooldown(self):
        technique = AutomaticMerge(
            max_states=4,
            merge_key=lambda state: state.key,
            min_reduction=1,
            merge_interval=16,
            substantial_reduction_ratio=0.5,
        )
        first = FakeSimulationManager(
            [FakeState("first"), FakeState("first")]
            + [FakeState(index) for index in range(3)]
        )
        technique.step(first)

        second = FakeSimulationManager(
            [FakeState("join") for _ in range(4)] + [FakeState("other")]
        )
        technique.step(second)

        self.assertEqual(1, len(second.merge_calls))
        self.assertEqual(2, technique.merge_attempts)


if __name__ == "__main__":
    unittest.main()
