#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from project.analyses.isr_memory import AnalysisReport, analyze_isr_memory


def _format_ops(operations: tuple[str, ...]) -> str:
    return "/".join(operation.upper() for operation in operations)


def _print_report(report: AnalysisReport) -> None:
    print(f"ELF: {report.elf}")
    print(f"Initializer: {report.initializer}")
    print("Pointer facts:")
    for fact in report.pointer_facts:
        site = f" at {fact.instruction:#x}" if fact.instruction is not None else ""
        print(
            f"  {fact.cell.name} ({fact.cell.address:#x}) -> "
            f"{fact.value:#x} ({fact.target}){site}"
        )

    for isr in report.isrs:
        print(f"\n{isr.isr}:")
        for region in isr.regions:
            addresses = ", ".join(f"{address:#x}" for address in region.addresses)
            print(
                f"  {_format_ops(region.operations):10} {region.name:24} "
                f"[{addresses}]"
            )
        print(f"  unresolved memory accesses: {len(isr.unresolved_accesses)}")
        for access in isr.unresolved_accesses[:20]:
            site = (
                f"{access.instruction:#x}"
                if access.instruction is not None
                else "<external>"
            )
            print(
                f"    {access.operation} {access.size} byte(s) at "
                f"{access.function}:{site}: {access.unresolved}"
            )
        if len(isr.unresolved_accesses) > 20:
            print(f"    ... {len(isr.unresolved_accesses) - 20} more")
        print(f"  unresolved indirect calls: {len(isr.unresolved_calls)}")
        for function, callsite in isr.unresolved_calls:
            print(f"    {function}:{callsite:#x}")
        print(f"  complete: {isr.complete}")

    print(f"\nOverall complete: {report.complete}")


def _json_default(value):
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "__dict__"):
        return value.__dict__
    raise TypeError(type(value).__name__)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Conservatively collect ISR memory-access regions from an ELF."
    )
    parser.add_argument("elf", type=Path)
    parser.add_argument("--isr", action="append", required=True)
    parser.add_argument("--initializer", default="main")
    parser.add_argument("--svd", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero status if unresolved accesses or calls remain.",
    )
    args = parser.parse_args()

    report = analyze_isr_memory(
        args.elf,
        args.isr,
        svd_path=args.svd,
        initializer=args.initializer,
    )
    if args.json:
        print(json.dumps(report, default=_json_default, indent=2))
    else:
        _print_report(report)
    return 2 if args.strict and not report.complete else 0


if __name__ == "__main__":
    raise SystemExit(main())

