from collections import defaultdict
import unittest

from project.types import CustomLoopSeer


HEADER = 0x1000
GUARD_BRANCH = 0x1002
BODY = 0x2000
CONTINUE = 0x2004
EXIT = 0x3000


class FakeCFGNode:
    def __init__(self, addr, instruction_addrs=None):
        self.addr = addr
        self.instruction_addrs = instruction_addrs or [addr]


class FakeCFGModel:
    def __init__(self):
        self.nodes = [
            FakeCFGNode(HEADER),
            FakeCFGNode(GUARD_BRANCH),
            FakeCFGNode(BODY),
            FakeCFGNode(CONTINUE),
            FakeCFGNode(EXIT),
        ]

    def get_any_node(self, addr, anyaddr=False):
        for node in self.nodes:
            if node.addr == addr or (anyaddr and addr in node.instruction_addrs):
                return node
        return None


class FakeCFG:
    def __init__(self):
        self.model = FakeCFGModel()


class FakeLoop:
    def __init__(self):
        self.entry = FakeCFGNode(HEADER)
        self.continue_edges = [(FakeCFGNode(CONTINUE), FakeCFGNode(HEADER))]
        self.break_edges = [(FakeCFGNode(GUARD_BRANCH), FakeCFGNode(EXIT))]
        self.body_nodes = [
            FakeCFGNode(HEADER),
            FakeCFGNode(GUARD_BRANCH),
            FakeCFGNode(BODY),
        ]


class FakeLoopData:
    def __init__(self, loop, exits, back_edge_count=0, header_count=1):
        self.current_loop = [(loop, exits)] if loop is not None else []
        self.back_edge_trip_counts = defaultdict(list, {HEADER: [back_edge_count]})
        self.header_trip_counts = defaultdict(list, {HEADER: [header_count]})


class FakeState:
    def __init__(
        self,
        addr,
        loop,
        exits,
        back_edge_count=0,
        header_count=1,
        history_addr=0,
    ):
        self.addr = addr
        self.loop_data = FakeLoopData(loop, exits, back_edge_count, header_count)
        self.history = type("History", (), {"addr": history_addr})()


class FakeSuccessors:
    def __init__(self, successors):
        self.successors = successors


class FakeSimulationManager:
    def __init__(self, successors):
        self._successors = FakeSuccessors(successors)

    def successors(self, state, **kwargs):
        del state, kwargs
        return self._successors


class CustomLoopSeerTest(unittest.TestCase):
    def setUp(self):
        self.loop = FakeLoop()
        self.exits = [EXIT]

    def seer(self, bound):
        return CustomLoopSeer(
            cfg=FakeCFG(),
            loop_bounds={HEADER: bound},
            use_header=True,
            discard_stash="loopseer",
        )

    def state(self, addr, back_edge_count=0, header_count=1, history_addr=0):
        return FakeState(
            addr,
            self.loop,
            self.exits,
            back_edge_count,
            header_count,
            history_addr,
        )

    def test_bound_zero_allows_guard_block_before_branch(self):
        seer = self.seer(bound=0)
        state = self.state(HEADER)
        guard_block = self.state(GUARD_BRANCH)

        seer.successors(FakeSimulationManager([guard_block]), state)

        self.assertNotIn(guard_block, seer.cut_succs)

    def test_bound_zero_cuts_body_successor_but_keeps_exit_successor(self):
        seer = self.seer(bound=0)
        state = self.state(GUARD_BRANCH)
        body = self.state(BODY)
        exit_state = self.state(EXIT)

        seer.successors(FakeSimulationManager([body, exit_state]), state)

        self.assertIn(body, seer.cut_succs)
        self.assertNotIn(exit_state, seer.cut_succs)
        self.assertEqual([], exit_state.loop_data.current_loop)

    def test_allows_body_successor_before_bound(self):
        seer = self.seer(bound=2)
        state = self.state(GUARD_BRANCH, back_edge_count=1)
        body = self.state(BODY, back_edge_count=1)

        seer.successors(FakeSimulationManager([body]), state)

        self.assertNotIn(body, seer.cut_succs)

    def test_cuts_body_successor_after_completed_bound(self):
        seer = self.seer(bound=2)
        state = self.state(GUARD_BRANCH, back_edge_count=2)
        body = self.state(BODY, back_edge_count=2)

        seer.successors(FakeSimulationManager([body]), state)

        self.assertIn(body, seer.cut_succs)

    def test_allows_final_guard_after_last_iteration(self):
        seer = self.seer(bound=1)
        state = self.state(CONTINUE, back_edge_count=0)
        header = self.state(HEADER, back_edge_count=0, history_addr=CONTINUE)

        seer.successors(FakeSimulationManager([header]), state)

        self.assertNotIn(header, seer.cut_succs)
        self.assertEqual([1], header.loop_data.back_edge_trip_counts[HEADER])

    def test_cuts_backedge_after_over_bound(self):
        seer = self.seer(bound=1)
        state = self.state(CONTINUE, back_edge_count=1)
        header = self.state(HEADER, back_edge_count=1, history_addr=CONTINUE)

        seer.successors(FakeSimulationManager([header]), state)

        self.assertIn(header, seer.cut_succs)


if __name__ == "__main__":
    unittest.main()
