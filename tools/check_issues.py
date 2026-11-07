#!/usr/bin/env python3
"""Check that SHGREP-issues.md is consistent: index rows match issue headings, every issue appears once,
solved issues sit under "# Done" and open ones above it, the counts line is right, and line endings are LF.

Usage: python tools/check_issues.py [path to SHGREP-issues.md]   (exit 0 = consistent, 1 = problems listed)
"""
from dataclasses import dataclass
import re
import sys
from pathlib import Path

HEADING = re.compile(r"^### #(\d+) \[([^\]]+)\] (.*?) — ((SOLVED|OPEN|PARTIAL|EXTERNAL).*?)\s*$")
ROW = re.compile(r"^\| (\d+) \| (.*?) \| (.*) \| (.*?) \|$")
COUNTS = re.compile(r"^(\d+) open, (\d+) partial, (\d+) external, (\d+) solved\.$")
FIELDS = ("sev", "title", "status")


@dataclass
class Heading:
    sev: str
    title: str
    status: str
    solved: bool
    line: int


@dataclass
class Row:
    sev: str
    title: str
    status: str


def unescape(cell: str) -> str:
    return cell.replace("\\|", "|")


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent / "SHGREP-issues.md"
    data = path.read_bytes()
    problems: list[str] = []
    if b"\r" in data:
        problems.append("line endings: file contains CR bytes; it must be LF only")
    lines = data.decode("utf-8").split("\n")

    headings: dict[int, Heading] = {}
    rows: dict[int, Row] = {}
    counts = None
    in_index = False
    done_line = None
    for number, line in enumerate(lines, 1):
        if line.startswith("## Index"):
            in_index = True
            continue
        if in_index and line.startswith("---"):
            in_index = False
        if line == "# Done":
            done_line = number
        match = HEADING.match(line)
        if match:
            issue = int(match.group(1))
            if issue in headings:
                problems.append(f"#{issue}: heading appears twice (lines {headings[issue].line} and {number})")
            headings[issue] = Heading(match.group(2), match.group(3), match.group(4), match.group(5) == "SOLVED", number)
            continue
        if line.startswith("### #"):
            problems.append(f"line {number}: issue heading does not parse: {line[:100]}")
        if in_index:
            match = ROW.match(line)
            if match:
                issue = int(match.group(1))
                if issue in rows:
                    problems.append(f"#{issue}: index row appears twice")
                rows[issue] = Row(unescape(match.group(2)), unescape(match.group(3)), unescape(match.group(4)))
            match = COUNTS.match(line)
            if match:
                counts = tuple(int(group) for group in match.groups())

    if done_line is None:
        problems.append('no "# Done" heading')
    for issue in sorted(set(headings) | set(rows)):
        heading, row = headings.get(issue), rows.get(issue)
        if heading is None:
            problems.append(f"#{issue}: index row without a heading")
            continue
        if row is None:
            problems.append(f"#{issue}: heading without an index row")
            continue
        for field in FIELDS:
            if getattr(heading, field) != getattr(row, field):
                problems.append(f"#{issue}: {field} differs: heading '{getattr(heading, field)}' vs index "
                                f"'{getattr(row, field)}'")
        if done_line is not None and heading.solved != (heading.line > done_line):
            where = "above" if heading.solved else "below"
            problems.append(f"#{issue}: {'SOLVED' if heading.solved else 'not solved'} but placed {where} '# Done'")

    expected = [0, 0, 0, 0]  # open, partial, external, solved
    for heading in headings.values():
        if heading.solved:
            expected[3] += 1
        elif heading.status.startswith("PARTIAL"):
            expected[1] += 1
        elif heading.status.startswith("EXTERNAL"):
            expected[2] += 1
        else:
            expected[0] += 1
    if counts is None:
        problems.append("index counts line missing")
    elif counts != tuple(expected):
        problems.append(f"index counts say {counts}, headings give {tuple(expected)} (open, partial, external, solved)")

    if problems:
        print(f"{path}: {len(problems)} problem(s)")
        for problem in problems:
            print("  " + problem)
        return 1
    print(f"{path}: consistent ({len(headings)} issues; {expected[0]} open, {expected[1]} partial, "
          f"{expected[2]} external, {expected[3]} solved)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
