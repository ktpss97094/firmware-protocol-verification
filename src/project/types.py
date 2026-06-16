from __future__ import annotations

import ast
import inspect
import logging
import resource
import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum, auto
from functools import partial
from typing import Any, Callable, Optional

import angr
import archinfo
import networkx as nx
from angr.engines import (
    HooksMixin,
    SimEngineFailure,
    SimEngineSyscall,
    SimEngineUnicorn,
)
from angr.engines.vex import (
    HeavyResilienceMixin,
    HeavyVEXMixin,
    SimInspectMixin,
    SuperFastpathMixin,
)
from angr.errors import SimEngineError
from angr.exploration_techniques import DFS, ExplorationTechnique, LoopSeer
from angr.sim_state import SimState

from project import utils

l = logging.getLogger(name=__name__)


class CustomEngine(
    SimEngineFailure,
    SimEngineSyscall,
    HooksMixin,
    SuperFastpathMixin,
    # TrackActionsMixin,
    SimInspectMixin,
    HeavyResilienceMixin,
    # SootMixin,
    # AILMixin,
    SimEngineUnicorn,
    HeavyVEXMixin,
):
    pass


class DFSPickFirstSuccessor(DFS):
    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        if len(simgr.stashes[stash]) > 1:
            # self._random.shuffle(simgr.stashes[stash])
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)

        if len(simgr.stashes[stash]) == 0:
            if len(simgr.stashes[self.deferred_stash]) == 0:
                return simgr
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())

        return simgr


class CustomLoopSeer(LoopSeer):
    """
    支援 num_inst=1 (單步執行) 的 LoopSeer
    """

    def successors(self, simgr, state, **kwargs):
        node = self.cfg.model.get_any_node(state.addr, anyaddr=True)
        if node is not None:
            kwargs["num_inst"] = min(
                kwargs.get("num_inst", float("inf")), len(node.instruction_addrs)
            )

        succs = simgr.successors(state, **kwargs)

        at_loop_exit = False
        for succ_state in succs.successors:
            if (
                succ_state.loop_data.current_loop
                and succ_state.addr in succ_state.loop_data.current_loop[-1][1]
            ):
                at_loop_exit = True

        for succ_state in succs.successors:
            if succ_state.loop_data.current_loop:
                loop = succ_state.loop_data.current_loop[-1][0]
                header = loop.entry.addr

                if succ_state.addr == header:
                    continue_addrs = [e[0].addr for e in loop.continue_edges]

                    if self.limit_concrete_loops or len(succs.successors) > 1:
                        # 利用 CFG 找出上一條指令所屬的 Basic Block 起始地址
                        prev_node = self.cfg.model.get_any_node(
                            succ_state.history.addr, anyaddr=True
                        )
                        prev_block_addr = (
                            prev_node.addr if prev_node else succ_state.history.addr
                        )

                        # 改用 prev_block_addr 來判斷是否經過 continue edge
                        if prev_block_addr in continue_addrs:
                            l.debug(
                                "Continue edge traversed, incrementing back_edge_trip_counts"
                            )
                            succ_state.loop_data.back_edge_trip_counts[succ_state.addr][
                                -1
                            ] += 1

                        succ_state.loop_data.header_trip_counts[succ_state.addr][
                            -1
                        ] += 1

                elif succ_state.addr in succ_state.loop_data.current_loop[-1][1]:
                    succ_state.loop_data.current_loop.pop()

                elif at_loop_exit:
                    if not self.limit_concrete_loops and len(succs.successors) > 1:
                        succ_state.loop_data.back_edge_trip_counts[succ_state.addr][
                            -1
                        ] += 1

                if self.bound is not None and succ_state.loop_data.current_loop:
                    counts = 0
                    if self.use_header:
                        counts = succ_state.loop_data.header_trip_counts[header][-1]
                    else:
                        if (
                            succ_state.addr
                            in succ_state.loop_data.back_edge_trip_counts
                        ):
                            counts = succ_state.loop_data.back_edge_trip_counts[
                                succ_state.addr
                            ][-1]

                    if counts > self.bound:
                        if self.bound_reached is not None:
                            self.bound_reached(self, succ_state)
                        else:
                            self.cut_succs.append(succ_state)

            else:
                if succ_state.addr in self.loops and not self._inside_current_loops(
                    succ_state
                ):
                    loop = self.loops[succ_state.addr]
                    header = loop.entry.addr
                    exits = [e[1].addr for e in loop.break_edges]

                    succ_state.loop_data.back_edge_trip_counts[header].append(0)
                    if not self.limit_concrete_loops:
                        for node in loop.body_nodes:
                            succ_state.loop_data.back_edge_trip_counts[
                                node.addr
                            ].append(0)

                    succ_state.loop_data.header_trip_counts[header].append(1)
                    succ_state.loop_data.current_loop.append((loop, exits))

        return succs


class AutomaticMerge(ExplorationTechnique):
    """
    Merge only states that already share a conservative merge key.

    Candidate detection is linear in the stash size. Expensive state merging is
    rate-limited unless the merge would remove a substantial fraction of the
    stash. ``hard_limit`` relaxes the minimum reduction requirement, but not the
    rate limit.
    """

    def __init__(
        self,
        max_states=20,
        merge_key: Callable[[SimState], Any] | None = None,
        min_reduction=4,
        merge_interval=16,
        substantial_reduction_ratio=0.25,
        hard_limit: int | None = None,
    ):
        super().__init__()

        if max_states < 1:
            raise ValueError("max_states must be positive")
        if min_reduction < 1:
            raise ValueError("min_reduction must be positive")
        if merge_interval < 1:
            raise ValueError("merge_interval must be positive")
        if not 0 < substantial_reduction_ratio <= 1:
            raise ValueError(
                "substantial_reduction_ratio must be greater than 0 and at most 1"
            )

        self.max_states = max_states
        self.merge_key = merge_key
        self.min_reduction = min_reduction
        self.merge_interval = merge_interval
        self.substantial_reduction_ratio = substantial_reduction_ratio
        self.hard_limit = max_states * 4 if hard_limit is None else hard_limit
        if self.hard_limit < max_states:
            raise ValueError("hard_limit must be at least max_states")

        self.step_count = 0
        self.last_merge_step = -merge_interval
        self.merge_attempts = 0
        self.states_merged = 0

    def _merge_candidate_groups(self, simgr, stash, groups):
        original_states = list(simgr.stashes[stash])
        group_member_ids = set()
        replacements = {}
        temp_stash = "_automatic_merge"
        suffix = 0
        while temp_stash in simgr.stashes:
            suffix += 1
            temp_stash = f"_automatic_merge_{suffix}"

        try:
            for group in groups:
                group_member_ids.update(id(state) for state in group)
                simgr.stashes[temp_stash] = list(group)
                simgr.merge(
                    stash=temp_stash, merge_key=lambda _state: None, prune=False
                )
                replacements[id(group[0])] = list(simgr.stashes[temp_stash])
        finally:
            simgr.stashes.pop(temp_stash, None)

        merged_states = []
        for state in original_states:
            state_id = id(state)
            if state_id in replacements:
                merged_states.extend(replacements[state_id])
            elif state_id not in group_member_ids:
                merged_states.append(state)

        simgr.stashes[stash] = merged_states

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        self.step_count += 1

        states = simgr.stashes[stash]
        state_count = len(states)
        if state_count <= self.max_states:
            return simgr

        merge_key = self.merge_key or simgr._merge_key
        keyed_states = defaultdict(list)
        for state in states:
            keyed_states[merge_key(state)].append(state)

        candidate_groups = [group for group in keyed_states.values() if len(group) > 1]
        potential_reduction = sum(len(group) - 1 for group in candidate_groups)
        if potential_reduction == 0:
            return simgr

        reduction_ratio = potential_reduction / state_count
        substantial_reduction = reduction_ratio >= self.substantial_reduction_ratio
        interval_elapsed = self.step_count - self.last_merge_step >= self.merge_interval
        under_hard_pressure = state_count >= self.hard_limit

        if not interval_elapsed:
            return simgr
        if (
            potential_reduction < self.min_reduction
            and not substantial_reduction
            and not under_hard_pressure
        ):
            return simgr

        self.last_merge_step = self.step_count
        self.merge_attempts += len(candidate_groups)
        started_at = time.monotonic()
        l.info(
            "AutomaticMerge starting on %s with %d states, %d candidate groups, "
            "and potential reduction %d",
            stash,
            state_count,
            len(candidate_groups),
            potential_reduction,
        )
        self._merge_candidate_groups(simgr, stash, candidate_groups)

        merged_count = state_count - len(simgr.stashes[stash])
        self.states_merged += merged_count
        max_rss_mib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        l.info(
            "AutomaticMerge finished %s from %d to %d states "
            "(%d candidate groups) in %.2fs; MaxRSS=%.1f MiB",
            stash,
            state_count,
            len(simgr.stashes[stash]),
            len(candidate_groups),
            time.monotonic() - started_at,
            max_rss_mib,
        )

        return simgr


def _acyclic_postdominator_merge_points(graph, loop_node_addrs):
    merge_points, _ = _acyclic_postdominator_merge_plan(graph, loop_node_addrs)
    return merge_points


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
    """
    Find structured, non-loop branch instructions and their join points.

    Loop joins are excluded because waiting for all loop paths at a barrier can
    deadlock across different iteration counts.
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


class DFSJoinMerge(DFS):
    """
    DFS with lineage-scoped merging at structured acyclic joins.

    Every real fork gets a dynamic token. A join only waits for descendants of
    that fork, so unrelated states in the DFS deferred stash cannot retain join
    states indefinitely. Guardrails release states without merging; they never
    discard a path.
    """

    _TOKEN_STACK_KEY = "_dfs_join_tokens"
    _MERGE_DEPTH_KEY = "_dfs_join_merge_depth"

    def __init__(
        self,
        merge_points,
        fork_to_join,
        merge_key: Callable[[SimState], Any] | None = None,
        deferred_stash="deferred",
        max_wait_steps=4096,
        max_waiting_states=64,
        max_merge_depth=32,
    ):
        super().__init__(deferred_stash=deferred_stash)
        if max_wait_steps < 1:
            raise ValueError("max_wait_steps must be positive")
        if max_waiting_states < 1:
            raise ValueError("max_waiting_states must be positive")
        if max_merge_depth < 1:
            raise ValueError("max_merge_depth must be positive")

        self.merge_points = frozenset(merge_points)
        self.fork_to_join = dict(fork_to_join)
        self.merge_key = merge_key
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

        merge_key = self.merge_key or simgr._merge_key
        keyed_states = defaultdict(list)
        for state in token_states:
            keyed_states[merge_key(state)].append(state)

        released = []
        for group in keyed_states.values():
            depths = [
                state.globals.get(self._MERGE_DEPTH_KEY, 0) for state in group
            ]
            before_count = len(group)
            added_depth = before_count - 1
            if (
                before_count > 1
                and max(depths) + added_depth <= self.max_merge_depth
            ):
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
            outer_stack = tuple(
                token_states[0].globals.get(self._TOKEN_STACK_KEY, ())
            )
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


class CFGJoinMerge(ExplorationTechnique):
    """
    Briefly hold compatible states at automatically discovered acyclic CFG joins.

    Unlike Veritesting, this technique delegates every execution step through
    the existing SimulationManager hook chain, so event and loop techniques
    continue to observe all states. Singleton states are released after
    ``wait_steps`` so a join that only one feasible path reaches cannot retain
    states indefinitely.
    """

    def __init__(
        self,
        merge_points,
        merge_key: Callable[[SimState], Any] | None = None,
        wait_steps=16,
    ):
        super().__init__()
        if wait_steps < 1:
            raise ValueError("wait_steps must be positive")

        self.merge_points = frozenset(merge_points)
        self.merge_key = merge_key
        self.wait_steps = wait_steps
        self.waiting_stash = "_cfg_join_waiting"
        self.step_count = 0
        self._waiting_since = {}
        self.merge_attempts = 0
        self.states_merged = 0
        self.states_released = 0

    def setup(self, simgr):
        simgr.stashes.setdefault(self.waiting_stash, [])

    def _merge_group(self, simgr, group):
        temp_stash = "_cfg_join_merge"
        suffix = 0
        while temp_stash in simgr.stashes:
            suffix += 1
            temp_stash = f"_cfg_join_merge_{suffix}"

        try:
            simgr.stashes[temp_stash] = list(group)
            simgr.merge(stash=temp_stash, merge_key=lambda _state: None, prune=False)
            return list(simgr.stashes[temp_stash])
        finally:
            simgr.stashes.pop(temp_stash, None)

    def step(self, simgr, stash="active", **kwargs):
        extra_stop_points = set(kwargs.get("extra_stop_points", ()))
        kwargs["extra_stop_points"] = extra_stop_points | self.merge_points
        simgr = simgr.step(stash=stash, **kwargs)
        self.step_count += 1

        waiting = simgr.stashes.setdefault(self.waiting_stash, [])
        runnable = []
        for state in simgr.stashes[stash]:
            ip = state.regs._ip
            if not ip.symbolic and state.addr in self.merge_points:
                waiting.append(state)
                self._waiting_since[id(state)] = self.step_count
            else:
                runnable.append(state)
        simgr.stashes[stash] = runnable

        merge_key = self.merge_key or simgr._merge_key
        keyed_states = defaultdict(list)
        for state in waiting:
            keyed_states[merge_key(state)].append(state)

        still_waiting = []
        for group in keyed_states.values():
            if len(group) == 1:
                still_waiting.extend(group)
                continue

            self.merge_attempts += 1
            merged = self._merge_group(simgr, group)
            self.states_merged += len(group) - len(merged)
            for state in group:
                self._waiting_since.pop(id(state), None)
            simgr.stashes[stash].extend(merged)

        expired = []
        retained = []
        for state in still_waiting:
            waiting_since = self._waiting_since[id(state)]
            if self.step_count - waiting_since >= self.wait_steps:
                expired.append(state)
                self._waiting_since.pop(id(state), None)
            else:
                retained.append(state)

        simgr.stashes[stash].extend(expired)
        self.states_released += len(expired)
        simgr.stashes[self.waiting_stash] = retained

        if not simgr.stashes[stash] and retained:
            simgr.stashes[stash].extend(retained)
            simgr.stashes[self.waiting_stash] = []
            for state in retained:
                self._waiting_since.pop(id(state), None)

        return simgr


class Violation(SimEngineError):
    pass


class ExploreTermination(Exception):
    pass


class AccessType(Enum):
    RW = auto()
    R = auto()
    W = auto()
    RC_W0 = auto()  # read or clear on write 0


@dataclass(frozen=True)
class MemoryEffect:
    operation: str
    start: int
    size: int

    @property
    def end(self):
        return self.start + self.size

    def overlaps(self, other):
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True)
class PluginEffect:
    operation: str
    plugin: str
    fields: tuple[str, ...] = ("*",)

    def overlaps(self, other):
        if self.plugin != other.plugin:
            return False
        return (
            "*" in self.fields
            or "*" in other.fields
            or not set(self.fields).isdisjoint(other.fields)
        )


@dataclass(frozen=True)
class AccessEffects:
    memory: frozenset[MemoryEffect] = frozenset()
    plugins: frozenset[PluginEffect] = frozenset()

    @classmethod
    def memory_access(cls, operation, start, size):
        return cls(
            memory=frozenset(
                {MemoryEffect(operation=operation, start=start, size=max(1, size))}
            )
        )

    def union(self, *others):
        memory = set(self.memory)
        plugins = set(self.plugins)
        for other in others:
            memory.update(other.memory)
            plugins.update(other.plugins)
        return AccessEffects(frozenset(memory), frozenset(plugins))

    def conflicts_with(self, other):
        for left in self.memory:
            for right in other.memory:
                if "write" in (left.operation, right.operation) and left.overlaps(
                    right
                ):
                    return True

        for left in self.plugins:
            for right in other.plugins:
                if "write" in (left.operation, right.operation) and left.overlaps(
                    right
                ):
                    return True

        return False


@dataclass(frozen=True)
class BitsField:
    bit: int
    access_type: AccessType
    rst_val: int
    size: int = 1

    @property
    def mask(self) -> int:
        return ((1 << self.size) - 1) << self.bit


class BaseRegister:
    OFFSET = -1


class MemoryRegion:
    def __init__(
        self,
        start: int,
        size: int,
        spec: BaseSpecs,
        physical_addr: int | None = None,
        transfer: bool = True,
        name: str = "",
    ):
        super().__init__()

        self.start = start
        self.size = size
        self.spec = spec
        self.physical_addr = physical_addr if physical_addr is not None else start
        self.transfer = transfer
        self.name = name

    def pre_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start

        return addr, offset

    def pre_write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        return addr, offset, value

    def post_read(self, state):
        addr = state.solver.eval(state.inspect.mem_read_address)
        offset = addr - self.start
        readout_value = state.inspect.mem_read_expr

        return addr, offset, readout_value

    def post_write(self, state):
        addr = state.solver.eval(state.inspect.mem_write_address)
        offset = addr - self.start
        value = state.inspect.mem_write_expr

        return addr, offset, value

    def in_region(self, addr):
        return self.start <= addr < self.start + self.size

    def in_region_read(self, state):
        try:
            return self.in_region(state.solver.eval(state.inspect.mem_read_address))
        except Exception:
            return False

    def in_region_write(self, state):
        try:
            return self.in_region(state.solver.eval(state.inspect.mem_write_address))
        except Exception:
            return False

    def get_access_effects(self, operation, address, size):
        return AccessEffects.memory_access(operation, address, size)


class MMIOMemoryRegion(MemoryRegion):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._access_masks = {}  # {offset: (rw mask, r mask, w mask, rc_w0 mask)}
        self._rst_vals = {}  # {offset: rst_val}

        for name in dir(self.__class__):
            value = getattr(self.__class__, name)

            if (
                isinstance(value, type)
                and issubclass(value, BaseRegister)
                and getattr(value, "OFFSET") != -1
            ):
                mask_rw, mask_r, mask_w, mask_rc_w0 = 0, 0, 0, 0
                rst_val = 0

                for _, attr_val in vars(value).items():
                    if isinstance(attr_val, BitsField):
                        if attr_val.access_type == AccessType.RW:
                            mask_rw |= attr_val.mask
                        elif attr_val.access_type == AccessType.R:
                            mask_r |= attr_val.mask
                        elif attr_val.access_type == AccessType.W:
                            mask_w |= attr_val.mask
                        elif attr_val.access_type == AccessType.RC_W0:
                            mask_rc_w0 |= attr_val.mask

                        rst_val |= attr_val.rst_val << attr_val.bit

                self._access_masks[value.OFFSET] = (mask_rw, mask_r, mask_w, mask_rc_w0)
                self._rst_vals[value.OFFSET] = rst_val

    def pre_write(self, state):
        addr, offset, value = super().pre_write(state)

        byte_offset = offset % state.arch.bytes
        register_addr = addr - byte_offset
        register_value = utils.load(state, register_addr)
        value_bits = value.size()
        bit_offset = byte_offset * state.arch.byte_width
        if state.arch.memory_endness == archinfo.Endness.BE:
            bit_offset = (
                state.arch.bits - value_bits - byte_offset * state.arch.byte_width
            )
        orig_value = register_value[bit_offset + value_bits - 1 : bit_offset]
        masked_value = self.mask_pre_write(offset, orig_value, value)
        state.inspect.mem_write_expr = masked_value
        state.globals[("_mmio_pending_write", id(self))] = (
            addr,
            masked_value,
            state.inspect.mem_write_length,
            state.inspect.mem_write_condition,
            state.inspect.mem_write_endness,
        )

        return addr, offset, state.inspect.mem_write_expr

    def post_write(self, state):
        addr, offset, value = super().post_write(state)
        pending = state.globals.pop(("_mmio_pending_write", id(self)), None)
        if pending is None:
            return addr, offset, value

        pending_addr, masked_value, size, condition, endness = pending
        if pending_addr != addr:
            raise SimEngineError(
                f"Mismatched pending MMIO write: {pending_addr:#x} != {addr:#x}"
            )

        state.memory.store(
            addr,
            masked_value,
            size=size if size is not None else masked_value.length // 8,
            condition=condition,
            endness=endness,
            disable_actions=True,
            inspect=False,
        )
        state.inspect.mem_write_expr = masked_value
        return addr, offset, masked_value

    def _get_access_masks(self, offset, value_bits):
        register_offset = offset - (offset % 4)
        masks = self._access_masks.get(register_offset)
        if masks is None:
            return None

        bit_offset = (offset - register_offset) * 8
        value_mask = (1 << value_bits) - 1
        return tuple((mask >> bit_offset) & value_mask for mask in masks)

    def mask_pre_write(self, offset, orig_val, write_val):
        masks = self._get_access_masks(offset, write_val.size())
        if masks:
            mask_rw, mask_r, mask_w, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_w | mask_rc_w0
            undefined_mask = ((1 << write_val.size()) - 1) ^ defined_mask

            return (
                (write_val & mask_rw)
                | (orig_val & mask_r)
                | (write_val & mask_w)
                | (orig_val & write_val & mask_rc_w0)
                | (write_val & undefined_mask)
            )
        return write_val

    def mask_post_read(self, offset, val):
        masks = self._get_access_masks(offset, val.size())
        if masks:
            mask_rw, mask_r, mask_w, mask_rc_w0 = masks
            defined_mask = mask_rw | mask_r | mask_w | mask_rc_w0
            undefined_mask = ((1 << val.size()) - 1) ^ defined_mask
            register_offset = offset - (offset % 4)
            bit_offset = (offset - register_offset) * 8
            reset_value = (
                self._rst_vals[register_offset] >> bit_offset
            ) & ((1 << val.size()) - 1)

            return (
                (val & (mask_rw | mask_r | mask_rc_w0))
                | (
                    reset_value
                    & (
                        mask_w | undefined_mask
                    )  # TODO: mask_w 也許可改成 base class 用 symbolic、derived class 再依照 reference manual 上的說明實作是否有明說回傳的是 reset value
                )
            )
        return val

    def get_pending_irqs(self, state):
        """
        回傳此 peripheral 目前可能觸發的 IRQ
        格式: [(trigger condition, kwargs), ...]
        """
        return []

    def set_handlers(self, cpu, state, cfg, specs):
        return


class VariableMemoryRegion(MemoryRegion):
    pass


class BaseSpecs:
    BOUND_LOOPS = {}

    def __init__(self, proj):
        super().__init__()

        self.proj = proj
        self.MEMORY_REGIONS = {}
        self.BEGIN_ADDR = None
        self.END_ADDRS = []
        self.API_PROTOTYPE = None
        self.API_ARGS = []
        self.CPU = self._detect_cpu()

        self._define_specs()

    @classmethod
    def _detect_cpu(cls):
        if isinstance(cls.ANGR_ARCH, archinfo.ArchARMCortexM):
            from project.cores.arm.cortex_m.cortex_m import CortexM

            return CortexM()
        return None

    def _define_specs(self):
        pass

    def init_inspect(self, state):
        pass

    def init_input(self, state):
        pass

    def final(self, simgr):
        pass

    def get_MMIOMemoryRegions(self):
        return [
            r for r in self.MEMORY_REGIONS.values() if isinstance(r, MMIOMemoryRegion)
        ]

    def get_DMAs(self):
        from project.cores.base import BaseDMA

        return [r for r in self.MEMORY_REGIONS.values() if isinstance(r, BaseDMA)]

    def get_memory_region(self, address):
        matches = [
            region
            for region in self.MEMORY_REGIONS.values()
            if region.in_region(address)
        ]
        return min(matches, key=lambda region: region.size) if matches else None

    def get_access_effects(self, operation, address, size):
        region = self.get_memory_region(address)
        if region is None:
            return AccessEffects.memory_access(operation, address, size)
        return region.get_access_effects(operation, address, size)

    def set_handlers(self, cpu, state, cfg, specs):
        for region in self.get_MMIOMemoryRegions():
            region.set_handlers(cpu=cpu, state=state, cfg=cfg, specs=specs)


class EventForkHandler:
    def get_checkpoints(self):
        return set()

    def get_eligible_events(self, state):
        """
        Return:
            [(trigger conditions, handler kwargs), ...]
        """
        return []

    def trigger_event(self, state, **kwargs):
        """
        對 state 執行該事件的行為
        """
        pass


class BPConfig:
    def __init__(
        self,
        event_type: str,
        when: str = angr.BP_BEFORE,
        enabled: bool = True,
        condition: Optional[Callable[[SimState], bool]] = None,
        **kwargs: Any,
    ):
        self.event_type = event_type
        self.when = when
        self.enabled = enabled
        self.condition = condition
        self.action = self._bp_action
        self.kwargs = kwargs

    def __eq__(self, other):
        if not isinstance(other, BPConfig):
            return False
        return (
            self.event_type == other.event_type
            and self.when == other.when
            and self.enabled == other.enabled
            and self.kwargs == other.kwargs
        )

    def __hash__(self):
        kwargs_signature = tuple(sorted(self.kwargs.items()))

        return hash((self.event_type, self.when, self.enabled, kwargs_signature))

    def apply_to(self, state: SimState, handler: EventForkHandler):
        state.inspect.b(
            self.event_type,
            when=self.when,
            enabled=self.enabled,
            condition=self.condition,
            action=partial(self.action, handler=handler),
            **self.kwargs,
        )

    def _bp_action(self, state, handler):
        match self.when:
            case angr.BP_BEFORE:
                if handler not in state.asynevt_globals.prev_after_check_handlers:
                    state.asynevt_globals.before_check_handlers.add(handler)
            case angr.BP_AFTER:
                state.asynevt_globals.after_check_handlers.add(handler)


class VerificationManager:
    _registered_functions = []
    all_violations = set()
    triggered_violations = set()
    _is_analyzed = False

    @classmethod
    def register(cls, func):
        cls._registered_functions.append(func)
        return func

    @classmethod
    def analyze_all_violations(cls):
        """自動掃描所有註冊的 function，統計總共有幾種 violation"""

        if cls._is_analyzed:
            return

        for func in cls._registered_functions:
            try:
                source = inspect.getsource(func)
                tree = ast.parse(source)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if (
                            isinstance(node.func, ast.Attribute)
                            and isinstance(node.func.value, ast.Name)
                            and node.func.value.id == cls.__name__
                            and node.func.attr == cls.violation.__name__
                        ):
                            if len(node.args) >= 2 and isinstance(
                                node.args[1], ast.Constant
                            ):
                                cls.all_violations.add(node.args[1].value)
            except Exception as e:
                print(f"Analyze {func.__name__} failed: {e}")

        cls._is_analyzed = True

    @classmethod
    def should_check(cls, violation_name):
        return violation_name not in cls.triggered_violations

    @classmethod
    def violation(cls, state, violation_name):
        if not cls.should_check(violation_name):
            return False

        if not cls._is_analyzed:
            cls.analyze_all_violations()

        cls.triggered_violations.add(violation_name)

        # 方法 1: 只 print 出 message，不砍掉 state
        print(violation_name + f" violation (ins_addr: {hex(state.addr)})")
        from project.main import add_violated_cnt

        add_violated_cnt(1)

        # 方法 2: print 出 message + 砍掉 state
        # raise Violation(violation_name)

        if len(cls.triggered_violations) == len(cls.all_violations):
            raise ExploreTermination("All violations triggered. Stopping analysis.")

        return True
