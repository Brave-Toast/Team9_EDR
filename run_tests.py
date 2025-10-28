#!/usr/bin/env python3
"""
Run the repository unit tests and produce a readable report.

Usage:
  python run_tests.py [--out-dir PATH]

This script discovers tests under the `tests/` directory using unittest discovery,
runs them, and writes a Markdown and JSON summary to the output directory
(default: `test_reports/`). It also prints a concise summary to stdout.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import traceback
import unittest
from typing import Dict, Any


def discover_and_run(tests_dir: str = "tests") -> Dict[str, Any]:
    """
    Custom test discovery that imports test files by path and loads tests from them.
    This avoids unittest.discover import-time issues in some environments.
    """
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    tests_path = os.path.abspath(tests_dir)
    if not os.path.isdir(tests_path):
        # Try common alternate location inside the package
        alt = os.path.abspath(os.path.join(os.curdir, "EDR", "tests"))
        if os.path.isdir(alt):
            tests_path = alt
        else:
            raise FileNotFoundError(f"Tests directory not found: {tests_path}")

    import importlib.util

    import_errors = []

    for fname in sorted(os.listdir(tests_path)):
        if not fname.startswith("test_") or not fname.endswith(".py"):
            continue
        fpath = os.path.join(tests_path, fname)
        mod_name = f"tests.{fname[:-3]}"
        print(f"Attempting to import test file: {fpath}")
        try:
            spec = importlib.util.spec_from_file_location(mod_name, fpath)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)  # type: ignore[attr-defined]
                suite.addTests(loader.loadTestsFromModule(module))
            else:
                import_errors.append((fname, "Could not load spec"))
        except ImportError as e:
            import_errors.append((fname, f"ImportError: {e}\n{traceback.format_exc()}"))
        except Exception:
            import_errors.append((fname, traceback.format_exc()))

    stream = io.StringIO()
    runner = unittest.TextTestRunner(stream=stream, verbosity=2)

    start = time.time()
    result = runner.run(suite)
    elapsed = time.time() - start

    output_text = stream.getvalue()

    # Combine import errors into errors_detail list
    errors_detail = [
        {"test": fname, "traceback": tb} for (fname, tb) in import_errors
    ]

    summary = {
        "total_tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors) + len(import_errors),
        "skipped": len(getattr(result, 'skipped', [])),
        "expectedFailures": len(getattr(result, 'expectedFailures', [])),
        "unexpectedSuccesses": len(getattr(result, 'unexpectedSuccesses', [])),
        "time_seconds": elapsed,
        "success": result.wasSuccessful() and not import_errors,
        "output": output_text,
        "failures_detail": [
            {"test": str(t[0]), "traceback": t[1]} for t in result.failures
        ],
        "errors_detail": [
            {"test": str(t[0]), "traceback": t[1]} for t in result.errors
        ] + errors_detail,
    }

    return summary


def write_reports(summary: Dict[str, Any], out_dir: str) -> None:
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "tests_report.json")
    md_path = os.path.join(out_dir, "tests_report.md")

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(summary, jf, indent=2)

    lines = []
    lines.append(f"# Test Report\n")
    lines.append(f"- Success: {summary['success']}")
    lines.append(f"- Time (s): {summary['time_seconds']:.2f}")
    lines.append(f"- Total tests: {summary['total_tests']}")
    lines.append(f"- Failures: {summary['failures']}")
    lines.append(f"- Errors: {summary['errors']}")
    lines.append(f"- Skipped: {summary['skipped']}")
    lines.append("")
    lines.append("## Failures")
    if summary["failures"]:
        for f in summary["failures_detail"]:
            lines.append(f"### {f['test']}")
            lines.append("```\n" + f['traceback'] + "\n```")
    else:
        lines.append("None")

    lines.append("")
    lines.append("## Errors")
    if summary["errors"]:
        for e in summary["errors_detail"]:
            lines.append(f"### {e['test']}")
            lines.append("```\n" + e['traceback'] + "\n```")
    else:
        lines.append("None")

    lines.append("")
    lines.append("## Full Runner Output")
    lines.append("```\n" + summary['output'] + "\n```")

    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write("\n".join(lines))

    print(f"Reports written: {json_path}, {md_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run test suite and produce reports")
    parser.add_argument("--out-dir", default="test_reports", help="Directory to write reports into")
    parser.add_argument("--tests-dir", default="tests", help="Directory containing tests")
    args = parser.parse_args(argv)

    try:
        summary = discover_and_run(args.tests_dir)
        write_reports(summary, args.out_dir)

        # Print concise summary
        print("\n=== Summary ===")
        print(f"Total: {summary['total_tests']}, Failures: {summary['failures']}, Errors: {summary['errors']}, Skipped: {summary['skipped']}")
        return 0 if summary["success"] else 2
    except Exception as exc:  # unexpected crash while running tests
        print("Error while running test suite:", exc)
        traceback.print_exc()
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
