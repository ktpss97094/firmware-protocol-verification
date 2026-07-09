from collections import defaultdict
import unittest

from project.types import CustomLoopSeer


HEADER = 0x1000
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
        self.break_edges = [(FakeCFGNode(HEADER), FakeCFGNode(EXIT))]
        self.body_nodes = [FakeCFGNode(HEADER), FakeCFGNode(BODY)]


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
            bound=bound,
            use_header=False,
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

    def test_bound_zero_allows_body_before_first_backedge(self):
        seer = self.seer(bound=0)
        state = self.state(HEADER)
        body = self.state(BODY)

        seer.successors(FakeSimulationManager([body]), state)

        self.assertNotIn(body, seer.cut_succs)

    def test_bound_zero_cuts_first_backedge_traversal(self):
        seer = self.seer(bound=0)
        state = self.state(CONTINUE, back_edge_count=0)
        header = self.state(HEADER, back_edge_count=0, history_addr=CONTINUE)

        seer.successors(FakeSimulationManager([header]), state)

        self.assertEqual([1], header.loop_data.back_edge_trip_counts[HEADER])
        self.assertIn(header, seer.cut_succs)

    def test_bound_one_allows_first_backedge_traversal(self):
        seer = self.seer(bound=1)
        state = self.state(CONTINUE, back_edge_count=0)
        header = self.state(HEADER, back_edge_count=0, history_addr=CONTINUE)

        seer.successors(FakeSimulationManager([header]), state)

        self.assertEqual([1], header.loop_data.back_edge_trip_counts[HEADER])
        self.assertNotIn(header, seer.cut_succs)

    def test_bound_one_cuts_second_backedge_traversal(self):
        seer = self.seer(bound=1)
        state = self.state(CONTINUE, back_edge_count=1)
        header = self.state(HEADER, back_edge_count=1, history_addr=CONTINUE)

        seer.successors(FakeSimulationManager([header]), state)

        self.assertEqual([2], header.loop_data.back_edge_trip_counts[HEADER])
        self.assertIn(header, seer.cut_succs)

    def test_exit_successor_is_not_cut(self):
        seer = self.seer(bound=0)
        state = self.state(HEADER)
        exit_state = self.state(EXIT)

        seer.successors(FakeSimulationManager([exit_state]), state)

        self.assertNotIn(exit_state, seer.cut_succs)
        self.assertEqual([], exit_state.loop_data.current_loop)


if __name__ == "__main__":
    unittest.main()
