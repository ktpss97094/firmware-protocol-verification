import unittest

import networkx as nx
from angr.exploration_techniques import DFS

from project.main import configure_search_techniques
from project.types import (
    AutomaticMerge,
    CFGJoinMerge,
    DFSJoinMerge,
    _DFSJoinToken,
    _acyclic_postdominator_merge_points,
    discover_acyclic_merge_plan,
    discover_acyclic_merge_points,
)


class FakeState:
    def __init__(self, key, addr=0):
        self.key = key
        self.addr = addr
        self.globals = {}
        self.regs = type("Regs", (), {"_ip": type("IP", (), {"symbolic": False})()})()


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

    def step_state(self, state, **kwargs):
        del state, kwargs
        return self.step_state_result

    def split(self, from_stash="active", to_stash="deferred", limit=None):
        states = self.stashes[from_stash]
        self.stashes[from_stash] = states[:limit]
        self.stashes.setdefault(to_stash, []).extend(states[limit:])
        return self

    def merge(self, merge_key=None, stash="active", prune=True):
        states = self.stashes[stash]
        self.merge_calls.append((list(states), prune))

        groups = {}
        for state in states:
            groups.setdefault(merge_key(state), []).append(state)

        merged = []
        for group in groups.values():
            merged_state = FakeState(group[0].key, group[0].addr)
            merged_state.globals.update(group[0].globals)
            merged.append(merged_state)
        self.stashes[stash] = merged
        return self


class FakeCFGNode:
    def __init__(self, addr, instruction_addrs=None):
        self.addr = addr
        self.instruction_addrs = instruction_addrs


class FakeFunction:
    def __init__(self, addr, graph):
        self.addr = addr
        self.graph = graph


class FakeFunctionManager(dict):
    def floor_func(self, addr):
        return self.get(addr)


class FakeCFG:
    def __init__(self, functions, callgraph):
        self.kb = type(
            "KnowledgeBase",
            (),
            {
                "functions": FakeFunctionManager(functions),
                "callgraph": callgraph,
            },
        )()


class FakeTechniqueManager:
    def __init__(self):
        self.techniques = []

    def use_technique(self, technique):
        self.techniques.append(technique)


class AutomaticMergeTest(unittest.TestCase):
    def test_dfs_search_installs_lineage_scoped_join_merge(self):
        simgr = FakeTechniqueManager()

        configure_search_techniques(
            simgr,
            search="dfs",
            automatic_merge=True,
            debug=False,
            merge_points={0x107},
            fork_to_join={0x101: 0x107},
        )

        self.assertEqual(1, len(simgr.techniques))
        self.assertIsInstance(simgr.techniques[0], DFSJoinMerge)
        self.assertNotIsInstance(simgr.techniques[0], CFGJoinMerge)

    def test_dfs_search_without_merge_only_installs_dfs(self):
        simgr = FakeTechniqueManager()

        configure_search_techniques(
            simgr,
            search="dfs",
            automatic_merge=False,
            debug=False,
            merge_points={0x107},
            fork_to_join={0x101: 0x107},
        )

        self.assertEqual(1, len(simgr.techniques))
        self.assertIsInstance(simgr.techniques[0], DFS)
        self.assertNotIsInstance(simgr.techniques[0], DFSJoinMerge)

    def test_bfs_search_installs_cfg_join_merge_when_enabled(self):
        simgr = FakeTechniqueManager()

        configure_search_techniques(
            simgr,
            search="bfs",
            automatic_merge=True,
            debug=False,
            merge_points={0x107},
        )

        self.assertEqual(1, len(simgr.techniques))
        self.assertIsInstance(simgr.techniques[0], CFGJoinMerge)

    def test_bfs_search_without_merge_keeps_default_scheduler(self):
        simgr = FakeTechniqueManager()

        configure_search_techniques(
            simgr,
            search="bfs",
            automatic_merge=False,
            debug=False,
            merge_points={0x107},
        )

        self.assertEqual([], simgr.techniques)

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

    def test_large_reduction_respects_cooldown(self):
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

        self.assertEqual(0, len(second.merge_calls))
        self.assertEqual(1, technique.merge_attempts)

    def test_finds_acyclic_diamond_postdominator(self):
        branch = FakeCFGNode(0x101)
        left = FakeCFGNode(0x103)
        right = FakeCFGNode(0x105)
        join = FakeCFGNode(0x107)
        graph = nx.DiGraph(
            [
                (branch, left),
                (branch, right),
                (left, join),
                (right, join),
            ]
        )

        merge_points = _acyclic_postdominator_merge_points(graph, set())

        self.assertEqual({join.addr}, merge_points)
        self.assertEqual(
            set(),
            _acyclic_postdominator_merge_points(graph, {branch.addr}),
        )

    def test_discovers_merge_points_from_multiple_execution_roots(self):
        first_branch = FakeCFGNode(0x101, (0x101, 0x102))
        first_left = FakeCFGNode(0x103)
        first_right = FakeCFGNode(0x105)
        first_join = FakeCFGNode(0x107)
        second_branch = FakeCFGNode(0x201, (0x201, 0x202))
        second_left = FakeCFGNode(0x203)
        second_right = FakeCFGNode(0x205)
        second_join = FakeCFGNode(0x207)
        functions = {
            first_branch.addr: FakeFunction(
                first_branch.addr,
                nx.DiGraph(
                    [
                        (first_branch, first_left),
                        (first_branch, first_right),
                        (first_left, first_join),
                        (first_right, first_join),
                    ]
                ),
            ),
            second_branch.addr: FakeFunction(
                second_branch.addr,
                nx.DiGraph(
                    [
                        (second_branch, second_left),
                        (second_branch, second_right),
                        (second_left, second_join),
                        (second_right, second_join),
                    ]
                ),
            ),
        }
        cfg = FakeCFG(functions, nx.DiGraph())

        merge_points = discover_acyclic_merge_points(
            cfg,
            {first_branch.addr, second_branch.addr},
            loops=(),
        )

        self.assertEqual({first_join.addr, second_join.addr}, merge_points)

        planned_points, fork_to_join = discover_acyclic_merge_plan(
            cfg,
            {first_branch.addr, second_branch.addr},
            loops=(),
        )
        self.assertEqual(merge_points, planned_points)
        self.assertEqual(
            {
                first_branch.instruction_addrs[-1]: first_join.addr,
                second_branch.instruction_addrs[-1]: second_join.addr,
            },
            fork_to_join,
        )

    def test_dfs_join_merges_only_dynamic_fork_siblings(self):
        fork_addr = 0x101
        join_addr = 0x107
        parent = FakeState("compatible", fork_addr)
        left = FakeState("compatible", 0x103)
        right = FakeState("compatible", 0x105)
        simgr = FakeSimulationManager([parent])
        simgr.step_state_result = {None: [left, right]}
        technique = DFSJoinMerge(
            merge_points={join_addr},
            fork_to_join={fork_addr: join_addr},
            merge_key=lambda state: state.key,
        )
        technique.setup(simgr)
        unrelated = FakeState("unrelated", 0x301)
        simgr.stashes["deferred"].append(unrelated)

        successors = technique.step_state(simgr, parent)
        simgr.stashes["active"] = successors[None]
        technique.step(simgr)

        self.assertEqual(1, len(simgr.stashes["active"]))
        self.assertEqual(2, len(simgr.stashes["deferred"]))

        simgr.stashes["active"][0].addr = join_addr
        technique.step(simgr)
        self.assertEqual(1, len(simgr.stashes[technique.waiting_stash]))
        self.assertEqual(1, len(simgr.stashes["active"]))

        simgr.stashes["active"][0].addr = join_addr
        technique.step(simgr)

        self.assertEqual(1, len(simgr.merge_calls))
        self.assertEqual(1, len(simgr.stashes["active"]))
        self.assertEqual([unrelated], simgr.stashes["deferred"])
        self.assertEqual([], simgr.stashes[technique.waiting_stash])
        self.assertEqual(1, technique.states_merged)

    def test_dfs_join_depth_limit_releases_paths_without_merging(self):
        join_addr = 0x107
        technique = DFSJoinMerge(
            merge_points={join_addr},
            fork_to_join={},
            merge_key=lambda state: state.key,
            max_merge_depth=1,
        )
        first = FakeState("compatible", join_addr)
        second = FakeState("compatible", join_addr)
        for state in (first, second):
            state.globals[technique._TOKEN_STACK_KEY] = (0,)
            state.globals[technique._MERGE_DEPTH_KEY] = 1

        simgr = FakeSimulationManager([])
        technique.setup(simgr)
        technique._tokens[0] = _DFSJoinToken(
            join_addr=join_addr,
            outstanding=2,
            created_step=0,
            arrivals=2,
        )
        simgr.stashes[technique.waiting_stash] = [first, second]

        technique._finish_token(simgr, 0, "active")

        self.assertEqual([], simgr.merge_calls)
        self.assertEqual([first, second], simgr.stashes["active"])
        self.assertEqual(1, technique.depth_limited_groups)

    def test_dfs_join_drops_token_when_all_descendants_terminate(self):
        fork_addr = 0x101
        join_addr = 0x107
        parent = FakeState("compatible", fork_addr)
        left = FakeState("compatible", 0x103)
        right = FakeState("compatible", 0x105)
        simgr = FakeSimulationManager([parent])
        technique = DFSJoinMerge(
            merge_points={join_addr},
            fork_to_join={fork_addr: join_addr},
            merge_key=lambda state: state.key,
        )
        technique.setup(simgr)

        simgr.step_state_result = {None: [left, right]}
        successors = technique.step_state(simgr, parent)
        self.assertEqual(1, len(technique._tokens))

        simgr.step_state_result = {None: []}
        technique.step_state(simgr, successors[None][0])
        technique.step_state(simgr, successors[None][1])
        technique._drop_exhausted_tokens()

        self.assertEqual({}, technique._tokens)

    def test_cfg_join_merges_bfs_siblings(self):
        join_addr = 0x107
        simgr = FakeSimulationManager(
            [
                FakeState("compatible", join_addr),
                FakeState("compatible", join_addr),
            ]
        )
        technique = CFGJoinMerge(
            merge_points={join_addr},
            merge_key=lambda state: state.key,
        )
        technique.setup(simgr)

        technique.step(simgr)

        self.assertEqual(1, len(simgr.merge_calls))
        self.assertEqual(1, len(simgr.stashes["active"]))
        self.assertEqual([], simgr.stashes[technique.waiting_stash])
        self.assertEqual(1, technique.states_merged)

    def test_cfg_join_releases_singleton_after_wait_limit(self):
        join_addr = 0x107
        waiting_state = FakeState("waiting", join_addr)
        runner = FakeState("runner", 0x201)
        simgr = FakeSimulationManager([waiting_state, runner])
        technique = CFGJoinMerge(
            merge_points={join_addr},
            merge_key=lambda state: state.key,
            wait_steps=2,
        )
        technique.setup(simgr)

        technique.step(simgr)
        self.assertEqual(
            [waiting_state], simgr.stashes[technique.waiting_stash]
        )

        technique.step(simgr)
        technique.step(simgr)

        self.assertIn(waiting_state, simgr.stashes["active"])
        self.assertEqual([], simgr.stashes[technique.waiting_stash])
        self.assertEqual(1, technique.states_released)

if __name__ == "__main__":
    unittest.main()
