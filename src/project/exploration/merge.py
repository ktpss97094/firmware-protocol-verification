from collections import defaultdict
from dataclasses import dataclass

import networkx as nx
from angr.exploration_techniques import DFS


def _acyclic_postdominator_merge_plan(graph, loop_node_addrs):
    if not graph:
        return set(), {}

    graph = nx.DiGraph(graph)
    exits = [node for node in graph if graph.out_degree(node) == 0]
    if not exits:
        return set(), {}

    sink = object()
    graph.add_node(sink)
    graph.add_edges_from((node, sink) for node in exits)
    immediate_postdominators = nx.immediate_dominators(graph.reverse(copy=False), sink)

    merge_points = set()
    fork_to_join = {}
    for branch in graph:
        if branch is sink:
            continue
        if graph.out_degree(branch) <= 1 or branch.addr in loop_node_addrs:
            continue

        join = immediate_postdominators.get(branch)
        if join is not None and join is not sink and join.addr not in loop_node_addrs:
            merge_points.add(join.addr)
            edge_instruction_addrs = {
                edge_data.get("ins_addr")
                for successor in graph.successors(branch)
                if successor is not sink
                for edge_data in (graph.get_edge_data(branch, successor) or {},)
                if edge_data.get("ins_addr") is not None
            }
            instruction_addrs = getattr(branch, "instruction_addrs", None)
            if len(edge_instruction_addrs) == 1:
                fork_addr = edge_instruction_addrs.pop()
            else:
                fork_addr = instruction_addrs[-1] if instruction_addrs else branch.addr
            fork_to_join[fork_addr] = join.addr

    return merge_points, fork_to_join


def discover_acyclic_merge_plan(cfg, start_addrs, loops):
    """Find structured, non-loop branch instructions and their join points.

    Loop joins are excluded because waiting for all loop paths at a barrier can deadlock across different iteration counts.
    """

    if isinstance(start_addrs, int):
        start_addrs = (start_addrs,)

    reachable_function_addrs = set()
    for start_addr in start_addrs:
        start_function = cfg.kb.functions.floor_func(start_addr)
        if start_function is None:
            continue

        reachable_function_addrs.add(start_function.addr)
        if start_function.addr in cfg.kb.callgraph:
            reachable_function_addrs.update(
                nx.descendants(cfg.kb.callgraph, start_function.addr)
            )
    loop_node_addrs = {node.addr for loop in loops for node in loop.body_nodes}

    merge_points = set()
    fork_to_join = {}
    for function_addr in reachable_function_addrs:
        if function_addr not in cfg.kb.functions:
            continue
        function = cfg.kb.functions[function_addr]
        function_merge_points, function_fork_to_join = (
            _acyclic_postdominator_merge_plan(function.graph, loop_node_addrs)
        )
        merge_points.update(function_merge_points)
        fork_to_join.update(function_fork_to_join)

    return merge_points, fork_to_join


def discover_acyclic_merge_points(cfg, start_addrs, loops):
    merge_points, _ = discover_acyclic_merge_plan(cfg, start_addrs, loops)
    return merge_points


@dataclass
class _DFSJoinToken:
    join_addr: int
    outstanding: int
    created_step: int
    arrivals: int = 0


class DFSAutomaticMerge(DFS):
    """DFS with lineage-scoped merging at structured acyclic joins.

    Every real fork gets a dynamic token. A join only waits for descendants of that fork, so unrelated states in the DFS deferred stash cannot retain join states indefinitely. Guardrails release states without merging; they never discard a path.
    """

    _TOKEN_STACK_KEY = "_dfs_join_tokens"
    _MERGE_DEPTH_KEY = "_dfs_join_merge_depth"

    def __init__(
        self,
        merge_points,
        fork_to_join,
        max_wait_steps=1024,
        max_waiting_states=32,
        max_merge_depth=32,
    ):
        super().__init__()

        if max_wait_steps < 1:
            raise ValueError("max_wait_steps must be positive")
        if max_waiting_states < 1:
            raise ValueError("max_waiting_states must be positive")
        if max_merge_depth < 1:
            raise ValueError("max_merge_depth must be positive")

        self.merge_points = frozenset(merge_points)
        self.fork_to_join = dict(fork_to_join)
        self.max_wait_steps = max_wait_steps
        self.max_waiting_states = max_waiting_states
        self.max_merge_depth = max_merge_depth
        self.waiting_stash = "_dfs_join_waiting"
        self.step_count = 0
        self._next_token = 0
        self._tokens = {}
        self.merge_attempts = 0
        self.states_merged = 0
        self.states_released = 0
        self.depth_limited_groups = 0
        self.expired_tokens = 0

    def setup(self, simgr):
        super().setup(simgr)

        simgr.stashes.setdefault(self.waiting_stash, [])

    def _normalize_stack(self, state):
        stack = tuple(state.globals.get(self._TOKEN_STACK_KEY, ()))
        while stack and stack[-1] not in self._tokens:
            stack = stack[:-1]
        state.globals[self._TOKEN_STACK_KEY] = stack
        return stack

    def _adjust_outstanding(self, stack, delta):
        if delta == 0:
            return
        for token_id in stack:
            token = self._tokens.get(token_id)
            if token is not None:
                token.outstanding += delta

    def step_state(self, simgr, state, **kwargs):
        stack = self._normalize_stack(state)
        succ_stashes = simgr.step_state(state, **kwargs)
        active_successors = succ_stashes.get(None, [])

        self._adjust_outstanding(stack, len(active_successors) - 1)

        join_addr = self.fork_to_join.get(state.addr)
        if join_addr is not None and len(active_successors) > 1:
            token_id = self._next_token
            self._next_token += 1
            self._tokens[token_id] = _DFSJoinToken(
                join_addr=join_addr,
                outstanding=len(active_successors),
                created_step=self.step_count,
            )
            successor_stack = stack + (token_id,)
            for successor in active_successors:
                successor.globals[self._TOKEN_STACK_KEY] = successor_stack

        return succ_stashes

    @staticmethod
    def _merge_stash_name(simgr):
        name = "_dfs_join_merge"
        suffix = 0
        while name in simgr.stashes:
            suffix += 1
            name = f"_dfs_join_merge_{suffix}"
        return name

    def _merge_group(self, simgr, group):
        temp_stash = self._merge_stash_name(simgr)
        try:
            simgr.stashes[temp_stash] = list(group)
            simgr.merge(stash=temp_stash, merge_key=lambda _state: None, prune=False)
            return list(simgr.stashes[temp_stash])
        finally:
            simgr.stashes.pop(temp_stash, None)

    @staticmethod
    def _merge_key(state):
        """
        Generate a key for each state that reaches the corresponding join point. If two states have the same key, they can attempt to merge.

        This key currently includes:

        - The current instruction pointer.
        - The current call stack (function addresses, stack pointers, and return addresses).
        - The current loop data (header trip counts, back edge trip counts, and loop stack).
        - The current file descriptors.
        - The merge keys of all plugins that implement a `_merge_key()` method.
        """

        def loop_data_key(state):
            if not state.has_plugin("loop_data"):
                return None

            return (
                tuple(
                    sorted(
                        (addr, tuple(counts))
                        for addr, counts in state.loop_data.header_trip_counts.items()
                    )
                ),
                tuple(
                    sorted(
                        (addr, tuple(counts))
                        for addr, counts in state.loop_data.back_edge_trip_counts.items()
                    )
                ),
                tuple(
                    (loop.entry.addr, tuple(exits))
                    for loop, exits in state.loop_data.current_loop
                ),
            )

        ip = state.regs._ip
        ip_key = ip.hash() if ip.symbolic else state.addr

        plugin_keys = tuple(
            sorted(
                (name, plugin._merge_key())
                for name, plugin in state.plugins.items()
                if callable(getattr(plugin, "_merge_key", None))
            )
        )

        return (
            ip_key,
            tuple(
                (frame.func_addr, frame.stack_ptr, frame.ret_addr)
                for frame in state.callstack
            ),
            loop_data_key(state),
            frozenset(state.posix.fd) if state.has_plugin("posix") else None,
            plugin_keys,
        )

    def _finish_token(self, simgr, token_id, stash, *, expired=False):
        waiting = simgr.stashes[self.waiting_stash]
        token_states = []
        retained = []
        for state in waiting:
            stack = self._normalize_stack(state)
            if stack and stack[-1] == token_id:
                state.globals[self._TOKEN_STACK_KEY] = stack[:-1]
                token_states.append(state)
            else:
                retained.append(state)
        simgr.stashes[self.waiting_stash] = retained

        if not token_states:
            self._tokens.pop(token_id, None)
            return

        merge_key = self._merge_key or simgr._merge_key
        keyed_states = defaultdict(list)
        for state in token_states:
            keyed_states[merge_key(state)].append(state)

        released = []
        for group in keyed_states.values():
            depths = [state.globals.get(self._MERGE_DEPTH_KEY, 0) for state in group]
            before_count = len(group)
            added_depth = before_count - 1
            if before_count > 1 and max(depths) + added_depth <= self.max_merge_depth:
                self.merge_attempts += 1
                merged = self._merge_group(simgr, group)
                if len(merged) < before_count:
                    merge_depth = max(depths) + added_depth
                    for state in merged:
                        state.globals[self._MERGE_DEPTH_KEY] = merge_depth
                released.extend(merged)
            else:
                if before_count > 1:
                    self.depth_limited_groups += 1
                released.extend(group)

        reduction = len(token_states) - len(released)
        self.states_merged += reduction
        self.states_released += len(released)
        if expired:
            self.expired_tokens += 1

        if reduction:
            outer_stack = tuple(token_states[0].globals.get(self._TOKEN_STACK_KEY, ()))
            self._adjust_outstanding(outer_stack, -reduction)

        simgr.stashes[stash].extend(released)
        self._tokens.pop(token_id, None)

    def _collect_join_arrivals(self, simgr, stash):
        runnable = []
        waiting = simgr.stashes[self.waiting_stash]
        for state in simgr.stashes[stash]:
            stack = self._normalize_stack(state)
            if not stack:
                runnable.append(state)
                continue

            token = self._tokens[stack[-1]]
            if state.addr != token.join_addr:
                runnable.append(state)
                continue

            token.arrivals += 1
            waiting.append(state)

        simgr.stashes[stash] = runnable

    def _release_ready_tokens(self, simgr, stash):
        ready = [
            token_id
            for token_id, token in self._tokens.items()
            if token.arrivals > 0 and token.arrivals >= token.outstanding
        ]
        for token_id in ready:
            self._finish_token(simgr, token_id, stash)

    def _drop_exhausted_tokens(self):
        exhausted = [
            token_id
            for token_id, token in self._tokens.items()
            if token.outstanding <= 0 and token.arrivals == 0
        ]
        for token_id in exhausted:
            self._tokens.pop(token_id, None)

    def _enforce_wait_limits(self, simgr, stash):
        waiting_count = len(simgr.stashes[self.waiting_stash])
        waiting_tokens = sorted(
            (
                (token.created_step, token_id)
                for token_id, token in self._tokens.items()
                if token.arrivals > 0
            )
        )
        for created_step, token_id in waiting_tokens:
            token = self._tokens.get(token_id)
            if token is None:
                continue
            over_time = self.step_count - created_step >= self.max_wait_steps
            over_capacity = waiting_count > self.max_waiting_states
            if not over_time and not over_capacity:
                continue
            waiting_count -= token.arrivals
            self._finish_token(simgr, token_id, stash, expired=True)

    def step(self, simgr, stash="active", **kwargs):
        extra_stop_points = set(kwargs.get("extra_stop_points", ()))
        kwargs["extra_stop_points"] = extra_stop_points | self.merge_points
        simgr = simgr.step(stash=stash, **kwargs)
        self.step_count += 1

        self._collect_join_arrivals(simgr, stash)
        self._release_ready_tokens(simgr, stash)
        self._drop_exhausted_tokens()
        self._enforce_wait_limits(simgr, stash)

        if len(simgr.stashes[stash]) > 1:
            self._random.shuffle(simgr.stashes[stash])
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        if not simgr.stashes[stash] and simgr.stashes[self.deferred_stash]:
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())

        if (
            not simgr.stashes[stash]
            and not simgr.stashes[self.deferred_stash]
            and simgr.stashes[self.waiting_stash]
        ):
            pending_tokens = set()
            for state in simgr.stashes[self.waiting_stash]:
                stack = self._normalize_stack(state)
                if stack:
                    pending_tokens.add(stack[-1])
            for token_id in pending_tokens:
                self._finish_token(simgr, token_id, stash, expired=True)

        return simgr
