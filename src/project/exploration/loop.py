import logging

from angr.exploration_techniques import LoopSeer

l = logging.getLogger(name=__name__)


class CustomLoopSeer(LoopSeer):
    """LoopSeer that supports num_inst=1 (single-step execution)."""

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
                        # Use the CFG to find the starting address of the basic block to which the previous instruction belongs
                        prev_node = self.cfg.model.get_any_node(
                            succ_state.history.addr, anyaddr=True
                        )
                        prev_block_addr = (
                            prev_node.addr if prev_node else succ_state.history.addr
                        )

                        # Use prev_block_addr instead to determine whether a continue edge has been encountered
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
