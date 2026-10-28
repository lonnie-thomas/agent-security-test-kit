"""`agent-sec-kit` command line: run the suite against an agent, or merge result files into a matrix."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent-sec-kit", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="run the security suite against an agent adapter")
    r.add_argument("--agent", default="toy", help="toy | it-service-agent | package.module:AdapterClass")
    r.add_argument("--json", help="write JSON results here")
    r.add_argument("--md", help="write a markdown report here")
    r.add_argument("-k", dest="keyword", help="pytest -k expression to select test functions (e.g. test_tampered)")
    r.add_argument("--tb", default="no", help="pytest traceback style (default: no; try 'short')")
    m = sub.add_parser("matrix", help="merge JSON result files into one results matrix (markdown on stdout)")
    m.add_argument("files", nargs="+")
    a = ap.parse_args(argv)
    if a.cmd == "matrix":
        from .report import render_matrix
        print(render_matrix(a.files))
        return 0
    import pytest
    suite = Path(__file__).parent / "suite"
    args = ["-p", "agent_security_kit.plugin", str(suite), "--agent", a.agent, "-q", "--no-header", f"--tb={a.tb}", "-rN",
            "-p", "no:cacheprovider", "--rootdir", str(suite), "-o", "addopts="]
    if a.json:
        args += ["--kit-json", a.json]
    if a.md:
        args += ["--kit-md", a.md]
    if a.keyword:
        args += ["-k", a.keyword]
    return int(pytest.main(args))


if __name__ == "__main__":
    sys.exit(main())
